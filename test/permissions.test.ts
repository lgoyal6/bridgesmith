/**
 * Connector permissions. Every capability a connector exercises has to map to a
 * line in a certified manifest, and the manifest is deny-by-default and
 * read-only: a permission that is not written down does not exist.
 *
 * On scope: this is capability mediation at egress, not code confinement. See
 * the header of src/runtime/permissions.ts for why a WASI-style sandbox would
 * isolate the wrong thing here, and when it would become the right answer.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec, specHashOf } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Registry } from "../src/registry/registry.js";
import { Adapter, type Fetcher } from "../src/codegen/adapter.js";
import { check, derivePermissions, guardedFetcher, permissionsHashOf, PermissionError, type PermissionManifest } from "../src/runtime/permissions.js";
import type { ConnectorSpec } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "perm-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}
const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));
const ORIGIN = "https://api.example-events.com";

const derived = () => deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });

/** A fetcher that records what it was ACTUALLY asked to reach. */
function spyFetcher(responses: Record<string, { status: number; body?: unknown; location?: string }> = {}): { fetcher: Fetcher; reached: string[] } {
  const reached: string[] = [];
  const fetcher: Fetcher = async (url) => {
    reached.push(url);
    const r = responses[url] ?? { status: 200, body: { events: [], total: 0 } };
    return {
      status: r.status,
      json: async () => r.body,
      text: async () => JSON.stringify(r.body ?? null),
      headers: { get: (n: string) => (n.toLowerCase() === "location" ? (r.location ?? null) : n.toLowerCase() === "content-type" ? "application/json" : null) },
    };
  };
  return { fetcher, reached };
}

describe("every spec carries a least-privilege manifest", () => {
  it("N1 a derived connector is read-only, single-origin, and holds no secrets", () => {
    const spec = derived();
    const p = spec.permissions!;
    expect(p.origins).toEqual([ORIGIN]);
    expect(p.methods).toEqual(["GET"]);
    expect(p.allowWrites).toBe(false);
    expect(p.secretNames).toEqual([]);
    expect(p.dataClasses).toEqual(["public"]);
    expect(p.filePaths).toEqual([]);
    expect(p.maxRedirects).toBe(0);
    expect(p.operations).toEqual(["get_api_events", "get_api_events_event_id"]);
    expect(p.pathTemplates).toEqual(["/api/events", "/api/events/{event_id}"]);
  });

  it("N2 writes stay off even when the spec has a mutating operation, until someone asks", () => {
    const spec = derived();
    const withWrite: ConnectorSpec = { ...spec, operations: [...spec.operations, { ...spec.operations[0]!, id: "post_api_events", method: "POST", mutating: true }] };
    expect(derivePermissions(withWrite).allowWrites).toBe(false);
    expect(derivePermissions(withWrite, { allowWrites: true }).allowWrites).toBe(true);
    // ...and asking for writes on a connector that has none does not invent them
    expect(derivePermissions(spec, { allowWrites: true }).allowWrites).toBe(false);
  });

  it("N3 every certified operation maps to an explicit permission", async () => {
    const spec = derived();
    const { report, effectiveSpec } = await certify(spec, B(), { deriveExchanges: A() });
    for (const op of report.certifiedOps) {
      expect(effectiveSpec.permissions!.operations).toContain(op);
      const o = effectiveSpec.operations.find((x) => x.id === op)!;
      expect(effectiveSpec.permissions!.methods).toContain(o.method);
      expect(effectiveSpec.permissions!.pathTemplates).toContain(o.pathTemplate);
    }
  });
});

describe("planted undeclared actions are blocked", () => {
  const perms = () => derived().permissions!;

  it("N4 an undeclared host is refused", () => {
    const d = check(perms(), { kind: "http", op: "get_api_events", method: "GET", url: "https://evil.example/api/events" });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain("is not a permitted destination");
  });

  it("N5 an undeclared path on an allowed host is refused", () => {
    const d = check(perms(), { kind: "http", op: "get_api_events", method: "GET", url: `${ORIGIN}/admin/dump` });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain("matches no permitted path template");
  });

  it("N6 a read-only connector attempting a write is refused twice over", () => {
    const byMethod = check(perms(), { kind: "http", method: "DELETE", url: `${ORIGIN}/api/events` });
    expect(byMethod.allowed).toBe(false);
    expect(byMethod.reason).toContain("method DELETE is not permitted");

    // even when the method IS in the manifest, allowWrites gates it
    const p: PermissionManifest = { ...perms(), methods: ["GET", "POST"], allowWrites: false };
    const byPolicy = check(p, { kind: "http", method: "POST", url: `${ORIGIN}/api/events` });
    expect(byPolicy.allowed).toBe(false);
    expect(byPolicy.reason).toContain("connector is read-only");
  });

  it("N7 an undeclared operation is refused even on an allowed path", () => {
    const d = check(perms(), { kind: "http", op: "get_api_admin", method: "GET", url: `${ORIGIN}/api/events` });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('operation "get_api_admin" is not in the permission manifest');
  });

  it("N8 a secret outside the declared scope is refused, and a public connector may hold none", () => {
    expect(check(perms(), { kind: "secret", secretName: "bearer" })).toMatchObject({ allowed: false });
    expect(check(perms(), { kind: "secret", secretName: "bearer" }).reason).toContain("forbids reading any secret");

    const credentialed: PermissionManifest = { ...perms(), dataClasses: ["credentialed"], secretNames: ["bearer"] };
    expect(check(credentialed, { kind: "secret", secretName: "bearer" }).allowed).toBe(true);
    const other = check(credentialed, { kind: "secret", secretName: "cookie" });
    expect(other.allowed).toBe(false);
    expect(other.reason).toContain("outside the declared secret scope");
  });

  it("N9 filesystem access outside the declared paths is refused", () => {
    const local: PermissionManifest = { ...perms(), filePaths: ["/Users/x/Library/Messages"] };
    expect(check(local, { kind: "file", path: "/Users/x/Library/Messages/chat.db" }).allowed).toBe(true);
    const d = check(local, { kind: "file", path: "/Users/x/.ssh/id_ed25519" });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain("outside the declared filesystem scope");
    // a prefix that is not a path boundary is not a match
    expect(check(local, { kind: "file", path: "/Users/x/Library/Messages-backup/chat.db" }).allowed).toBe(false);
  });

  it("N10 a denial names the rule, never the value that tripped it", () => {
    const credentialed: PermissionManifest = { ...perms(), dataClasses: ["credentialed"], secretNames: ["bearer"] };
    const d = check(credentialed, { kind: "secret", secretName: "cookie" });
    expect(d.reason).not.toContain("sk-");
    const h = check(perms(), { kind: "http", method: "GET", url: `${ORIGIN}/api/events?token=SECRETVALUE` });
    expect(h.allowed).toBe(true); // the query is not the rule's business...
    const bad = check(perms(), { kind: "http", method: "GET", url: `${ORIGIN}/admin?token=SECRETVALUE` });
    expect(bad.reason).not.toContain("SECRETVALUE"); // ...and never appears in a refusal
  });
});

describe("redirects are re-checked at every hop", () => {
  it("N11 a redirect off an allowed host to a disallowed one never reaches the destination", async () => {
    const p: PermissionManifest = { ...derived().permissions!, maxRedirects: 3 };
    const { fetcher, reached } = spyFetcher({
      [`${ORIGIN}/api/events`]: { status: 302, location: "https://evil.example/steal" },
    });
    const guarded = guardedFetcher(p, fetcher);
    await expect(guarded(`${ORIGIN}/api/events`, { method: "GET", headers: {} })).rejects.toThrow(PermissionError);
    expect(reached).toEqual([`${ORIGIN}/api/events`]); // the second hop was never made
  });

  it("N12 with maxRedirects 0 (the default) any redirect at all is refused", async () => {
    const p = derived().permissions!;
    expect(p.maxRedirects).toBe(0);
    const { fetcher } = spyFetcher({ [`${ORIGIN}/api/events`]: { status: 301, location: `${ORIGIN}/api/events/` } });
    await expect(guardedFetcher(p, fetcher)(`${ORIGIN}/api/events`, { method: "GET", headers: {} })).rejects.toThrow(/redirect refused/);
  });

  it("N13 a redirect WITHIN the permitted origin and path set is followed when the budget allows", async () => {
    const p: PermissionManifest = { ...derived().permissions!, maxRedirects: 2 };
    const { fetcher, reached } = spyFetcher({
      [`${ORIGIN}/api/events`]: { status: 302, location: `${ORIGIN}/api/events/evt_1` },
      [`${ORIGIN}/api/events/evt_1`]: { status: 200, body: { id: "evt_1" } },
    });
    const res = await guardedFetcher(p, fetcher)(`${ORIGIN}/api/events`, { method: "GET", headers: {} });
    expect(res.status).toBe(200);
    expect(reached).toEqual([`${ORIGIN}/api/events`, `${ORIGIN}/api/events/evt_1`]);
  });
});

describe("the runtime enforces the manifest, and cannot widen it", () => {
  it("N14 a connector with no manifest gets no capability at all", async () => {
    const spec = derived();
    const naked: ConnectorSpec = { ...spec, permissions: undefined as never };
    const { fetcher, reached } = spyFetcher();
    const r = await new Adapter(naked, { fetcher }).call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(false);
    expect(r.outcome).toBe("refused");
    expect(r.error).toContain("no capability budget");
    expect(reached).toEqual([]); // nothing left the process
  });

  it("N15 the adapter refuses an operation outside the manifest before building a request", async () => {
    const spec = derived();
    const narrowed: ConnectorSpec = { ...spec, permissions: { ...spec.permissions!, operations: ["get_api_events"] } };
    const { fetcher, reached } = spyFetcher();
    const denials: string[] = [];
    const r = await new Adapter(narrowed, { fetcher, onDeny: (d) => denials.push(d.reason!) }).call("get_api_events_event_id", { event_id: "evt_1" });
    expect(r.ok).toBe(false);
    expect(r.outcome).toBe("refused");
    expect(reached).toEqual([]);
    expect(denials[0]).toContain("is not in the permission manifest");
  });

  it("N16 a public connector cannot attach a secret even when handed one", async () => {
    const spec = derived();
    const credentialedSpec: ConnectorSpec = { ...spec, auth: { kind: "bearer", header: "authorization" } };
    const { fetcher, reached } = spyFetcher();
    const r = await new Adapter(credentialedSpec, { fetcher, secrets: { bearer: "sk-live-SECRETVALUE" } }).call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(false);
    expect(r.outcome).toBe("refused");
    expect(r.error).toContain("forbids reading any secret");
    expect(r.error).not.toContain("sk-live-SECRETVALUE");
    expect(reached).toEqual([]);
  });

  it("N17 with the secret declared, the same call goes through", async () => {
    const spec = derived();
    const ok: ConnectorSpec = {
      ...spec,
      auth: { kind: "bearer", header: "authorization" },
      permissions: { ...spec.permissions!, dataClasses: ["credentialed"], secretNames: ["bearer"] },
    };
    const { fetcher, reached } = spyFetcher();
    const r = await new Adapter(ok, { fetcher, secrets: { bearer: "sk-live-SECRETVALUE" } }).call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(true);
    expect(reached).toHaveLength(1);
  });

  // NOTE ON WHICH CHECK FIRES: this refusal comes from the spec<->certificate
  // specHash binding, not from a permissions-specific registry check. There is
  // no such check, on purpose: `permissions` is inside specHash, so a dedicated
  // comparison could never fail when specHash passes. The certificate's
  // permissionsHash is a signed RECORD of the certified budget (N19), not a
  // second gate dressed up as one.
  it("N18 widening the manifest in spec.json un-mounts the connector", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const { report, effectiveSpec } = await certify(derived(), B(), { deriveExchanges: A() });
    const promoted = reg.promote(effectiveSpec, report);
    expect(promoted.stored).toBe(true);
    expect(reg.latest("events")?.cert.permissionsHash).toBe(permissionsHashOf(effectiveSpec.permissions!));

    const path = join(dir, "events", "v1", "spec.json");
    const onDisk = JSON.parse(readFileSync(path, "utf8"));
    const widened = {
      ...onDisk,
      permissions: { ...onDisk.permissions, allowWrites: true, origins: [...onDisk.permissions.origins, "https://evil.example"] },
    };
    widened.specHash = specHashOf(widened); // internally consistent, still refused
    writeFileSync(path, JSON.stringify(widened, null, 2));
    expect(reg.latest("events")).toBeNull();
  });

  it("N19 the certified manifest hash is signed, so it cannot be relabelled after the fact", async () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const { report, effectiveSpec } = await certify(derived(), B(), { deriveExchanges: A() });
    reg.promote(effectiveSpec, report);
    const cert = reg.at("events", 1)!.cert;
    const { verifyCertificate, loadTrustAnchor } = await import("../src/registry/certificate.js");
    expect(verifyCertificate({ ...cert, permissionsHash: "0".repeat(64) }, loadTrustAnchor(dir)!)).toBe(false);
  });
});
