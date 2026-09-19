/**
 * Capture provenance: a certificate must say what evidence it was earned
 * against, and that statement must be as tamper-evident as the certificate.
 *
 * The properties under test are: the manifest identifies the EVIDENCE (not the
 * run), a holdout that is secretly the derive capture is refused rather than
 * certified, the secret scan is a signed claim rather than a comment, and
 * rewriting provenance in spec.json un-mounts the connector.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { buildCaptureManifest, manifestHash, isSameEvidence } from "../src/capture/manifest.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import { specHashOf } from "../src/spec/derive.js";
import type { Exchange } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "prov-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));

function ex(over: Partial<Exchange> = {}): Exchange {
  return {
    method: "GET",
    url: "https://api.example-events.com/api/events",
    path: "/api/events",
    query: {},
    requestHeaders: { accept: "application/json" },
    status: 200,
    responseHeaders: { "content-type": "application/json" },
    responseBody: { events: [] },
    responseType: "application/json",
    ...over,
  };
}

describe("capture manifest", () => {
  it("P1 records origin, driver, exchange count, body hashes and toolchain", () => {
    const m = buildCaptureManifest(A(), { app: "events", role: "derive" });
    expect(m.app).toBe("events");
    expect(m.role).toBe("derive");
    expect(m.targetOrigins).toEqual(["https://api.example-events.com"]);
    expect(m.driver).toMatch(/^har-ingest\//);
    expect(m.exchangeCount).toBe(m.bodies.length);
    expect(m.exchangeCount).toBeGreaterThan(0);
    expect(m.bodies.every((b) => /^[0-9a-f]{64}$|^none$/.test(b.response))).toBe(true);
    expect(m.toolchain.node).toBe(process.version);
    expect(m.toolchain.bridgesmith).toMatch(/^\d+\.\d+\.\d+$/);
    expect(Date.parse(m.capturedAt)).not.toBeNaN();
  });

  it("P2 setId identifies the evidence, not the run: same traffic collides, changed traffic does not", () => {
    const at = (iso: string) => () => new Date(iso);
    const one = buildCaptureManifest(A(), { app: "events", role: "derive", now: at("2026-01-01T00:00:00.000Z") });
    const two = buildCaptureManifest(A(), { app: "events", role: "derive", now: at("2026-06-01T00:00:00.000Z") });
    expect(two.setId).toBe(one.setId); // same evidence, five months apart
    expect(isSameEvidence(one, two)).toBe(true);
    // ...but the full manifest hash differs, because WHEN it was captured is provenance.
    expect(manifestHash(two)).not.toBe(manifestHash(one));

    const different = buildCaptureManifest(B(), { app: "events", role: "holdout" });
    expect(different.setId).not.toBe(one.setId);
  });

  it("P3 changing one response body changes the setId", () => {
    const base = [ex(), ex({ path: "/api/events/evt_1", responseBody: { id: "evt_1" } })];
    const tweaked = [base[0]!, { ...base[1]!, responseBody: { id: "evt_2" } }];
    const a = buildCaptureManifest(base, { app: "e", role: "derive" });
    const b = buildCaptureManifest(tweaked, { app: "e", role: "derive" });
    expect(b.setId).not.toBe(a.setId);
  });

  it("P4 the secret scan is a signed claim: an unredacted credential is reported, not silently dropped", () => {
    const clean = buildCaptureManifest([ex()], { app: "e", role: "derive" });
    expect(clean.secretScan).toEqual({ clean: true, findings: [] });

    const leaked = buildCaptureManifest(
      [ex({ requestHeaders: { accept: "application/json", authorization: "Bearer sk-live-1234" } })],
      { app: "e", role: "derive" },
    );
    expect(leaked.secretScan.clean).toBe(false);
    expect(leaked.secretScan.findings[0]).toContain('request header "authorization"');
    // the finding names the location only: the manifest itself is committable
    expect(JSON.stringify(leaked)).not.toContain("sk-live-1234");
  });

  it("P5 a query-string token is caught too", () => {
    const m = buildCaptureManifest([ex({ query: { api_key: "abcd1234" } })], { app: "e", role: "derive" });
    expect(m.secretScan.clean).toBe(false);
    expect(m.secretScan.findings[0]).toContain('query param "api_key"');
  });
});

describe("provenance is bound to the spec and the certificate", () => {
  it("P6 the derive manifest rides in the spec and specHash stays deterministic across runs", () => {
    const one = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const two = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    expect(one.capture.role).toBe("derive");
    expect(one.capture.exchangeCount).toBeGreaterThan(0);
    expect(one.specHash).toBe(two.specHash); // capturedAt excluded, evidence included
    expect(one.capture.setId).toBe(two.capture.setId);
  });

  it("P7 provenance is part of the evidence: a spec derived from different traffic hashes differently", () => {
    const fromA = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const fromB = deriveSpec(B(), { app: "events", captureLabel: "B", host: "example-events.com" });
    expect(fromB.capture.setId).not.toBe(fromA.capture.setId);
    expect(fromB.specHash).not.toBe(fromA.specHash);
  });

  it("P8 the certificate signs both manifest hashes, and they are different sets", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report, effectiveSpec } = await certify(spec, B(), { deriveExchanges: A() });
    expect(report.holdout.role).toBe("holdout");
    const cert = issueCertificate(effectiveSpec, report, 1, dir);
    expect(cert.captureManifestHash).toBe(manifestHash(effectiveSpec.capture));
    expect(cert.holdoutManifestHash).toBe(manifestHash(report.holdout));
    expect(cert.holdoutManifestHash).not.toBe(cert.captureManifestHash);
  });

  it("P9 a holdout that is secretly the derive capture is refused, not certified", async () => {
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    // the exact circular case: certify the spec against the traffic it was derived from
    await expect(certify(spec, A(), { deriveExchanges: A() })).rejects.toThrow(/circular/);
  });

  it("P10 rewriting provenance in spec.json un-mounts the connector", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report, effectiveSpec } = await certify(spec, B(), { deriveExchanges: A() });
    const cert = issueCertificate(effectiveSpec, report, reg.nextVersion("events"), dir);
    reg.store(effectiveSpec, report, cert);
    expect(reg.latest("events")?.cert.version).toBe(1);

    // claim the capture was clean when the signed manifest says it was not:
    // an edit that survives specHash still fails the manifest-hash binding.
    const path = join(dir, "events", "v1", "spec.json");
    const onDisk = JSON.parse(readFileSync(path, "utf8"));
    const forged = { ...onDisk, capture: { ...onDisk.capture, capturedAt: "1999-01-01T00:00:00.000Z" } };
    forged.specHash = specHashOf(forged);
    expect(forged.specHash).toBe(onDisk.specHash); // capturedAt is outside specHash...
    writeFileSync(path, JSON.stringify(forged, null, 2));
    expect(reg.latest("events")).toBeNull(); // ...but inside the signed manifest hash
  });

  // NOTE ON WHAT THIS PROVES: verified by mutation, this refusal comes from the
  // spec<->certificate specHash binding, not from the manifest-hash check: every
  // manifest field EXCEPT capturedAt is already inside specHash. P10 is the case
  // that isolates the manifest-hash check, because capturedAt is the one field
  // specHash deliberately excludes.
  it("P11 a different driver is different provenance and is also refused after the fact", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report, effectiveSpec } = await certify(spec, B(), { deriveExchanges: A() });
    reg.store(effectiveSpec, report, issueCertificate(effectiveSpec, report, 1, dir));

    const path = join(dir, "events", "v1", "spec.json");
    const onDisk = JSON.parse(readFileSync(path, "utf8"));
    const forged = { ...onDisk, capture: { ...onDisk.capture, driver: "official-vendor-sdk/9.9.9" } };
    forged.specHash = specHashOf(forged);
    writeFileSync(path, JSON.stringify(forged, null, 2));
    expect(reg.latest("events")).toBeNull();
  });
});
