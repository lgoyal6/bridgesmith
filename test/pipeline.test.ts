import { describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { ensureRegistryKey, issueCertificate, verifyCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import { captureA, captureB, capturePoisoned } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "ts-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

describe("spec derivation", () => {
  it("templates id paths and infers a stable schema from capture A", () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    expect(spec.operations.map((o) => o.pathTemplate).sort()).toEqual([
      "/api/events",
      "/api/events/{event_id}",
    ]);
    const byId = spec.operations.find((o) => o.pathTemplate === "/api/events/{event_id}")!;
    expect(byId.pathParams).toEqual(["event_id"]);
    expect(byId.responseSchema.required).toContain("status");
    const statusSchema = byId.responseSchema.properties?.status;
    expect(statusSchema?.enum).toContain("published");
  });

  it("is deterministic: same input => same specHash", () => {
    const a = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    const b = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    expect(a.specHash).toEqual(b.specHash);
  });
});

describe("certification against holdout", () => {
  it("certifies ops that validate against an INDEPENDENT capture B", async () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    const holdout = loadHar(harFile(captureB()));
    const { report } = await certify(spec, holdout, { deriveExchanges: loadHar(harFile(captureA())) });
    expect(report.verdict).not.toBe("refused");
    expect(report.certifiedOps).toContain("get_api_events_event_id");
    // mutation suite actually caught corrupted responses
    expect(report.mutation.generated).toBeGreaterThan(0);
    expect(report.mutation.caught).toBeGreaterThan(0);
  });

  it("REFUSES an op whose holdout is poisoned (wrong type / missing required)", async () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    // holdout has the by-id op returning a broken object; list op has no holdout coverage
    const { report } = await certify(spec, loadHar(harFile(capturePoisoned())), { maxRepairs: 0 });
    const byId = report.refusedOps.find((r) => r.op === "get_api_events_event_id");
    expect(byId).toBeDefined();
    expect(byId!.reason).toMatch(/holdout-replay failed/);
  });

  it("REFUSES ops with no holdout coverage (never mount the unexercised)", async () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report } = await certify(spec, loadHar(harFile(capturePoisoned())), { maxRepairs: 0 });
    expect(report.uncoveredOps).toContain("get_api_events"); // list op never appeared in poisoned capture
  });
});

describe("birth certificate", () => {
  it("signs a certificate that verifies, and tampering breaks verification", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report } = await certify(spec, loadHar(harFile(captureB())), { deriveExchanges: loadHar(harFile(captureA())) });
    const cert = issueCertificate(spec, report, 1, dir);
    const anchor = ensureRegistryKey(dir).publicPem;
    expect(verifyCertificate(cert, anchor)).toBe(true);
    const tampered = { ...cert, certifiedOps: [...cert.certifiedOps, "smuggled_op"] };
    expect(verifyCertificate(tampered, anchor)).toBe(false);
  });

  it("registry stores and retrieves the latest valid version", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report } = await certify(spec, loadHar(harFile(captureB())), { deriveExchanges: loadHar(harFile(captureA())) });
    const cert = issueCertificate(spec, report, reg.nextVersion("events"), dir);
    reg.store(spec, report, cert);
    const latest = reg.latest("events");
    expect(latest?.cert.version).toBe(1);
    expect(latest?.spec.specHash).toBe(spec.specHash);
  });
});

describe("adapter runtime", () => {
  it("returns data on schema-valid responses and blocks schema-invalid ones", async () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
    let tick = 0;
    const adapter = new Adapter(spec, {
      now: () => (tick += 5),
      fetcher: async (url) => {
        // valid response for a known id, invalid (missing required) for another
        const valid = url.endsWith("/api/events/evt_1001");
        return {
          status: 200,
          headers: { get: () => "application/json" },
          json: async () =>
            valid
              ? { id: "evt_1001", title: "T", status: "published", startDate: "2026-09-13T18:00:00Z", capacity: 51, venue: "Venue X" }
              : { id: "evt_9999" }, // missing required fields
          text: async () => "",
        };
      },
    });
    const good = await adapter.call("get_api_events_event_id", { event_id: "evt_1001" });
    expect(good.ok).toBe(true);
    const bad = await adapter.call("get_api_events_event_id", { event_id: "evt_9999" });
    expect(bad.ok).toBe(false);
    expect(bad.outcome).toBe("schema-violation");
  });
});
