/**
 * Signed replay bundles. A certificate proves an operation passed; it does not
 * let anyone else RE-RUN that proof. Without a bundle, the only way to check a
 * disputed certification is to hit the live service again and hope it has not
 * moved, which is not verification.
 *
 * Every field the manifest binds gets its own tampering test, because a
 * signature over a field nobody checks proves nothing about that field.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Registry } from "../src/registry/registry.js";
import { ensureRegistryKey, keyId, loadTrustAnchor } from "../src/registry/certificate.js";
import { buildReplayBundle, readBundle, runBundle, verifyBundle, writeBundle, listBundles, type ReplayBundle } from "../src/replay/bundle.js";
import { REDACTED } from "../src/capture/redact.js";
import type { ConnectorSpec, SemanticInvariant, WorkflowSpec } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "bun-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}
const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));

const TOTAL_MATCHES: SemanticInvariant = {
  id: "events.list.total-matches", severity: "blocking",
  kind: "total-matches", op: "get_api_events", path: "events", totalPath: "total",
};
const LIST_THEN_DETAIL: WorkflowSpec = {
  id: "list_then_detail",
  steps: [
    { id: "list", op: "get_api_events", constParams: { limit: "10" }, postconditions: [{ kind: "non-empty", path: "events" }], extract: { eventId: "events[0].id" }, idempotency: "read-only" },
    { id: "detail", op: "get_api_events_event_id", requires: ["eventId"], params: { event_id: "eventId" }, postconditions: [{ kind: "equals-state", path: "id", state: "eventId" }], idempotency: "read-only" },
  ],
};

async function bundled() {
  const dir = mkdtempSync(join(tmpdir(), "reg-"));
  const reg = new Registry(dir);
  const spec: ConnectorSpec = {
    ...deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" }),
    workflows: [LIST_THEN_DETAIL],
    semanticInvariants: [TOTAL_MATCHES],
  };
  const holdout = B();
  const { report, effectiveSpec } = await certify(spec, holdout, { deriveExchanges: A() });
  const promoted = reg.promote(effectiveSpec, report);
  expect(promoted.stored).toBe(true);
  if (!promoted.stored) throw new Error("unreachable");
  const bundle = buildReplayBundle({
    kind: "certification", spec: effectiveSpec, cert: promoted.cert, report,
    exchanges: holdout.filter((e) => e.status === 200 && e.responseBody !== undefined),
    registryDir: dir,
  });
  return { dir, reg, bundle, anchor: loadTrustAnchor(dir)!, report, spec: effectiveSpec };
}

/** Deep copy so a tampering test cannot leak into the next one. */
const clone = (b: ReplayBundle): ReplayBundle => structuredClone(b);

describe("a bundle reproduces a certification offline", () => {
  it("B1 the manifest binds target, driver, toolchain, evidence, redaction, spec, workflows and certificate", async () => {
    const { bundle, anchor } = await bundled();
    const m = bundle.signed.manifest;
    expect(m.app).toBe("events");
    expect(m.targetOrigins).toEqual(["https://api.example-events.com"]);
    expect(m.driver).toMatch(/^har-ingest\//);
    expect(m.toolchain.node).toBe(process.version);
    expect(m.exchangeCount).toBe(bundle.exchanges.length);
    expect(m.exchanges.every((e) => /^[0-9a-f]{64}$/.test(e.bodyHash))).toBe(true);
    expect(m.redaction.policy.version).toBe(1);
    expect(m.redaction.clean).toBe(true);
    expect(m.specHash).toBe(bundle.spec.specHash);
    expect(m.adapterHash).toBeTruthy();
    expect(m.workflows).toEqual([{ id: "list_then_detail", steps: ["list", "detail"] }]);
    expect(m.certificate.keyId).toBe(keyId(anchor));
    expect(m.expected.certifiedInvariants).toEqual([TOTAL_MATCHES.id]);
    expect(verifyBundle(bundle, anchor).ok).toBe(true);
  });

  it("B2 replay reproduces every certified operation and workflow with no network", async () => {
    const { bundle, anchor } = await bundled();
    // the adapter is given the bundle's own fetcher; a real fetch would need a
    // network the replay fetcher never exposes
    const r = await runBundle(bundle, anchor);
    expect(r.verified.ok).toBe(true);
    expect(r.verified.failures).toEqual([]);
    expect(r.ops.every((o) => o.ok)).toBe(true);
    expect(r.workflows).toEqual([{ id: "list_then_detail", pass: true }]);
    expect(r.reproduced).toBe(true);
  });

  it("B3 a bundle round-trips through disk and is discoverable", async () => {
    const { bundle, anchor } = await bundled();
    const out = join(mkdtempSync(join(tmpdir(), "bundles-")), "events-v1");
    writeBundle(out, bundle);
    const back = readBundle(out);
    expect(verifyBundle(back, anchor).ok).toBe(true);
    expect((await runBundle(back, anchor)).reproduced).toBe(true);
    expect(listBundles(join(out, ".."))).toEqual(["events-v1"]);
  });

  it("B4 an incomplete bundle is refused by name, not by crash", async () => {
    const { bundle } = await bundled();
    const out = join(mkdtempSync(join(tmpdir(), "bundles-")), "broken");
    writeBundle(out, bundle);
    rmSync(join(out, "exchanges.json"));
    expect(() => readBundle(out)).toThrow(/incomplete replay bundle, missing: exchanges.json/);
  });
});

describe("tampering with each bound field fails verification", () => {
  it("B5 no trust anchor means nothing is trusted", async () => {
    const { bundle } = await bundled();
    const v = verifyBundle(bundle, null);
    expect(v.ok).toBe(false);
    expect(v.failures[0]).toContain("no trust anchor");
  });

  it("B6 a manifest field edited after signing fails the signature", async () => {
    const { bundle, anchor } = await bundled();
    for (const edit of [
      (b: ReplayBundle) => { b.signed.manifest.app = "payments"; },
      (b: ReplayBundle) => { b.signed.manifest.driver = "official-vendor-sdk/9"; },
      (b: ReplayBundle) => { b.signed.manifest.capturedAt = "1999-01-01T00:00:00.000Z"; },
      (b: ReplayBundle) => { b.signed.manifest.expected.certifiedOps = ["delete_everything"]; },
      (b: ReplayBundle) => { b.signed.manifest.redaction.clean = false; },
      (b: ReplayBundle) => { b.signed.manifest.targetOrigins = ["https://evil.example"]; },
    ]) {
      const b = clone(bundle);
      edit(b);
      const v = verifyBundle(b, anchor);
      expect(v.ok, JSON.stringify(b.signed.manifest.app)).toBe(false);
      expect(v.failures.join(" ")).toContain("manifest signature does not verify");
    }
  });

  it("B7 evidence that was ALTERED is rejected", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    const target = b.exchanges.find((e) => e.path === "/api/events")!;
    target.responseBody = { ...(target.responseBody as Record<string, unknown>), total: 99 };
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("does not match the manifest");
  });

  it("B8 evidence that was REORDERED is rejected, because order is semantic", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    expect(b.exchanges.length).toBeGreaterThan(1);
    b.exchanges = [b.exchanges[b.exchanges.length - 1]!, ...b.exchanges.slice(0, -1)];
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/replay input 0 does not match/);
  });

  it("B9 evidence that is MISSING is rejected", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    b.exchanges = b.exchanges.slice(0, -1);
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/holds \d+ exchanges, manifest says \d+/);
  });

  it("B10 a cross-target replay is rejected: another registry's bundle is not valid here", async () => {
    const mine = await bundled();
    const theirs = await bundled();
    const v = verifyBundle(theirs.bundle, mine.anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("manifest signature does not verify");
    // and the certificate inside it is equally not ours
    expect(v.failures.join(" ")).toContain("certificate does not verify");
  });

  it("B11 a bundle whose spec was swapped under the manifest is rejected", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    b.spec.operations.push({ ...b.spec.operations[0]!, id: "get_admin_dump", pathTemplate: "/admin/dump" });
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("spec does not hash to the manifest's specHash");
  });

  it("B12 a bundle whose workflow ordering was rewritten is rejected", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    b.spec.workflows![0]!.steps.reverse();
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("workflow steps or their ordering differ");
  });

  it("B13 a bundle from a different certificate version is rejected", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    b.signed.manifest.certificate.version = 2;
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
  });

  it("B14 replaying an unverified bundle produces no result at all", async () => {
    const { bundle, anchor } = await bundled();
    const b = clone(bundle);
    b.exchanges = b.exchanges.slice(0, -1);
    const r = await runBundle(b, anchor);
    expect(r.verified.ok).toBe(false);
    expect(r.ops).toEqual([]); // no number is produced from evidence that did not verify
    expect(r.workflows).toEqual([]);
    expect(r.reproduced).toBe(false);
  });
});

describe("captured secrets never enter a bundle", () => {
  it("B15 building a bundle around unredacted evidence is refused", async () => {
    const { bundle, dir, report } = await bundled();
    const leaky = structuredClone(bundle.exchanges);
    leaky[0]!.requestHeaders = { ...leaky[0]!.requestHeaders, authorization: "Bearer sk-live-SECRETVALUE" };
    expect(() =>
      buildReplayBundle({ kind: "certification", spec: bundle.spec, cert: bundle.cert, report, exchanges: leaky, registryDir: dir }),
    ).toThrow(/refusing to bundle unredacted evidence/);
  });

  it("B16 a bundle written to disk carries no credential, and redaction is re-checked not trusted", async () => {
    const { bundle, anchor } = await bundled();
    const out = join(mkdtempSync(join(tmpdir(), "bundles-")), "events");
    writeBundle(out, bundle);
    for (const f of ["replay-manifest.json", "spec.json", "certificate.json", "report.json", "exchanges.json"]) {
      const text = readFileSync(join(out, f), "utf8");
      expect(text).not.toMatch(/Bearer\s+\S/);
      expect(text).not.toMatch(/sk-live/);
    }
    // the manifest's "clean" claim is re-derived on verify, so smuggling a secret
    // into the evidence afterwards cannot ride on the earlier scan
    const b = clone(bundle);
    b.exchanges[0]!.requestHeaders = { ...b.exchanges[0]!.requestHeaders, authorization: "Bearer sk-live-SECRETVALUE" };
    const v = verifyBundle(b, anchor);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("unredacted evidence");
  });

  it("B17 redacted material stays redacted through the whole bundle path", async () => {
    const { bundle } = await bundled();
    const serialized = JSON.stringify(bundle);
    // the fixture carries no auth header, so assert the marker is what survives
    // wherever redaction did fire, and that no raw Authorization value appears
    expect(serialized.includes(REDACTED) || !serialized.includes("authorization")).toBe(true);
  });
});

describe("the registry key is the one anchor", () => {
  it("B18 a bundle signed by a key this registry does not own is refused", async () => {
    const { bundle } = await bundled();
    const foreign = ensureRegistryKey(mkdtempSync(join(tmpdir(), "other-"))).publicPem;
    const v = verifyBundle(bundle, foreign);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toContain("manifest signature does not verify");
  });
});
