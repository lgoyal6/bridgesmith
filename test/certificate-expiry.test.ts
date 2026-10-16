/**
 * Checks optional signed certificate expiry against the verifier's local clock.
 * Uses real certification and registry reads, with isolated fixture keys.
 * Legacy certificates keep their current lifetime; historical trust is separate.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { certify } from "../src/certify/certify.js";
import { deriveSpec } from "../src/spec/derive.js";
import { ensureRegistryKey, issueCertificate, verifyCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import { buildReplayBundle, runBundle, verifyBundle } from "../src/replay/bundle.js";
import { captureA, captureB } from "./fixtures.js";

const owned: string[] = [];
afterEach(() => {
  vi.useRealTimers();
  for (const dir of owned.splice(0)) rmSync(dir, { recursive: true, force: true });
});

async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bridgesmith-expiry-"));
  owned.push(root);
  const a = join(root, "a.har"), b = join(root, "b.har");
  writeFileSync(a, JSON.stringify(captureA()));
  writeFileSync(b, JSON.stringify(captureB()));
  const derive = loadHar(a);
  const spec = deriveSpec(derive, { app: "events", captureLabel: "A", host: "example-events.com" });
  const holdout = loadHar(b);
  const result = await certify(spec, holdout, { deriveExchanges: derive });
  const registryDir = join(root, "registry");
  const registry = new Registry(registryDir);
  return { ...result, holdout, registryDir, registry, anchor: ensureRegistryKey(registryDir).publicPem };
}

describe("signed certificate expiry", () => {
  it("accepts before expiry, refuses at the boundary, and keeps legacy validity", async () => {
    const f = await fixture();
    const now = Date.now();
    vi.useFakeTimers(); vi.setSystemTime(now);
    const expiresAt = new Date(now + 60_000).toISOString();
    const legacy = issueCertificate(f.effectiveSpec, f.report, 1, f.registryDir);
    const cert = issueCertificate(f.effectiveSpec, f.report, 2, f.registryDir, undefined, expiresAt);
    expect(cert.expiresAt).toBe(expiresAt);
    expect(verifyCertificate(cert, f.anchor, now + 59_999)).toBe(true);
    expect(verifyCertificate(cert, f.anchor, now + 60_000)).toBe(false);
    expect(verifyCertificate(cert, f.anchor, now - 1)).toBe(false);
    expect(verifyCertificate(cert, f.anchor, NaN)).toBe(false);
    expect(verifyCertificate(legacy, f.anchor, now + 120_000)).toBe(true);
    expect(verifyCertificate({ ...cert, expiresAt: new Date(now + 120_000).toISOString() }, f.anchor, now)).toBe(false);
  });

  it("lets normal promotion opt into expiry and leaves its default non-expiring", async () => {
    const f = await fixture();
    const now = Date.now();
    vi.useFakeTimers(); vi.setSystemTime(now);
    const expiresAt = new Date(now + 60_000).toISOString();
    const expiring = f.registry.promote(f.effectiveSpec, f.report, { expiresAt });
    expect(expiring.stored).toBe(true);
    if (!expiring.stored) throw new Error("expected initial promotion to store");
    expect(expiring.cert.expiresAt).toBe(expiresAt);
    expect(verifyCertificate(expiring.cert, f.anchor, now + 59_999)).toBe(true);
    expect(verifyCertificate(expiring.cert, f.anchor, now + 60_000)).toBe(false);

    const legacy = f.registry.promote(f.effectiveSpec, f.report);
    expect(legacy.stored).toBe(true);
    if (!legacy.stored) throw new Error("expected default promotion to store");
    expect(legacy.cert.expiresAt).toBeUndefined();
    vi.setSystemTime(now + 60_000);
    expect(f.registry.at("events", 1)).toBeNull();
    expect(f.registry.latest("events")?.cert.version).toBe(2);
  });

  it("forwards expiry when promoting a version with predecessor lineage", async () => {
    const f = await fixture();
    const now = Date.now();
    vi.useFakeTimers(); vi.setSystemTime(now);
    const first = f.registry.promote(f.effectiveSpec, f.report);
    expect(first.stored).toBe(true);
    if (!first.stored) throw new Error("expected initial promotion to store");

    const expiresAt = new Date(now + 60_000).toISOString();
    const second = f.registry.promote(f.effectiveSpec, f.report, { expiresAt });
    expect(second.stored).toBe(true);
    if (!second.stored) throw new Error("expected predecessor promotion to store");
    expect(second.cert.version).toBe(2);
    expect(second.cert.predecessor).toEqual({ version: 1, specHash: f.effectiveSpec.specHash });
    expect(second.cert.expiresAt).toBe(expiresAt);
    expect(verifyCertificate(second.cert, f.anchor, now + 59_999)).toBe(true);
    expect(verifyCertificate(second.cert, f.anchor, now + 60_000)).toBe(false);
  });

  it("rejects invalid expiry through normal promotion without storing a version", async () => {
    const f = await fixture();
    expect(() => f.registry.promote(f.effectiveSpec, f.report, { expiresAt: "not-a-date" })).toThrow(/expiry/);
    expect(f.registry.latest("events")).toBeNull();
  });

  it("refuses expired replay before using evidence and keeps legacy bundles valid", async () => {
    const f = await fixture();
    const now = Date.now();
    vi.useFakeTimers(); vi.setSystemTime(now);
    const expiresAt = new Date(now + 60_000).toISOString();
    const expiringCert = issueCertificate(f.effectiveSpec, f.report, 1, f.registryDir, undefined, expiresAt);
    const legacyCert = issueCertificate(f.effectiveSpec, f.report, 2, f.registryDir);
    const makeBundle = (cert: ReturnType<typeof issueCertificate>) => buildReplayBundle({
      kind: "certification", spec: f.effectiveSpec, cert, report: f.report,
      exchanges: f.holdout, registryDir: f.registryDir, now: () => new Date(now),
    });
    const expiringBundle = makeBundle(expiringCert);
    const legacyBundle = makeBundle(legacyCert);
    expect(verifyBundle(expiringBundle, f.anchor).ok).toBe(true);
    expect(verifyBundle(legacyBundle, f.anchor).ok).toBe(true);

    vi.setSystemTime(now + 60_000);
    expect(verifyBundle(expiringBundle, f.anchor).ok).toBe(false);
    const expiredReplay = await runBundle(expiringBundle, f.anchor);
    expect(expiredReplay.verified.ok).toBe(false);
    expect(expiredReplay.ops).toEqual([]);
    expect(expiredReplay.reproduced).toBe(false);
    expect(verifyBundle(legacyBundle, f.anchor).ok).toBe(true);
    expect((await runBundle(legacyBundle, f.anchor)).reproduced).toBe(true);
  });

  it("skips an expired newer version and serves the valid earlier version", async () => {
    const f = await fixture();
    const now = Date.now();
    vi.useFakeTimers(); vi.setSystemTime(now);
    const v1 = issueCertificate(f.effectiveSpec, f.report, 1, f.registryDir);
    f.registry.store(f.effectiveSpec, f.report, v1);
    const v2 = issueCertificate(f.effectiveSpec, f.report, 2, f.registryDir, undefined, new Date(now + 60_000).toISOString());
    f.registry.store(f.effectiveSpec, f.report, v2);
    expect(f.registry.latest("events")?.cert.version).toBe(2);
    vi.setSystemTime(now + 60_000);
    expect(f.registry.at("events", 2)).toBeNull();
    expect(f.registry.latest("events")?.cert.version).toBe(1);
    expect(f.registry.list().find(row => row.version === 2)?.valid).toBe(false);
  });

  it.each(["not-a-date", "2026-02-31T00:00:00.000Z", "2000-01-01T00:00:00.000Z"])("refuses invalid or nonfuture expiry %s before signing", async expiresAt => {
    const f = await fixture();
    expect(() => issueCertificate(f.effectiveSpec, f.report, 1, f.registryDir, undefined, expiresAt)).toThrow(/expiry/);
    expect(f.registry.latest("events")).toBeNull();
  });
});
