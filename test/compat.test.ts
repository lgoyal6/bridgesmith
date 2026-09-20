/**
 * Version compatibility. A re-certification that passes proves the new spec
 * matches the new evidence. It says nothing about what the new spec BREAKS for
 * something already calling the current version, and treating the first answer
 * as the second is how a green run silently removes an operation.
 *
 * Every class below is planted deliberately, and the policy fails closed: a
 * change these rules cannot explain is `unknown` and is never auto-promoted.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { diffSpecs, renderDiff } from "../src/registry/compat.js";
import { Registry } from "../src/registry/registry.js";
import { Adapter } from "../src/codegen/adapter.js";
import { replayFetcher } from "../src/certify/replay.js";
import { adapterHashOf, issueCertificate } from "../src/registry/certificate.js";
import type { ConnectorSpec, SemanticInvariant, WorkflowSpec } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "cmp-")), "cap.har");
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
    {
      id: "list", op: "get_api_events", constParams: { limit: "10" },
      postconditions: [{ kind: "non-empty", path: "events" }],
      extract: { eventId: "events[0].id" }, idempotency: "read-only",
    },
    {
      id: "detail", op: "get_api_events_event_id", requires: ["eventId"], params: { event_id: "eventId" },
      postconditions: [{ kind: "equals-state", path: "id", state: "eventId" }], idempotency: "read-only",
    },
  ],
};

function base(): ConnectorSpec {
  return {
    ...deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" }),
    workflows: [LIST_THEN_DETAIL],
    semanticInvariants: [TOTAL_MATCHES],
  };
}

/** Apply a mutation to a copy of the base spec. */
function variant(edit: (s: ConnectorSpec) => ConnectorSpec): ConnectorSpec {
  return edit(structuredClone(base()));
}
const diff = (to: ConnectorSpec, from: ConnectorSpec = base()) => diffSpecs(from, to, { from: 1, to: 2 });
const listOp = (s: ConnectorSpec) => s.operations.find((o) => o.id === "get_api_events")!;
// Only the by-id operation has enough samples for a vocabulary to be inferred at
// all (the list op is seen twice, below the enum evidence floor), so vocabulary
// changes are planted there.
const detailOp = (s: ConnectorSpec) => s.operations.find((o) => o.id === "get_api_events_event_id")!;

describe("planted changes receive distinct classifications", () => {
  it("C1 an identical spec is identical and auto-promotable", () => {
    const d = diff(base());
    expect(d.overall).toBe("identical");
    expect(d.changes).toEqual([]);
    expect(d.autoPromotable).toBe(true);
    expect(renderDiff(d)).toContain("no observable changes");
  });

  it("C2 additive: a new operation, a new optional field and a widened vocabulary", () => {
    const d = diff(
      variant((s) => {
        s.operations.push({ ...listOp(s), id: "get_api_venues", pathTemplate: "/api/venues" });
        listOp(s).responseSchema.properties!["events"]!.items!.properties!["nickname"] = { type: "string" };
        detailOp(s).responseSchema.properties!["status"]!.enum = ["archived", "cancelled", "published"];
        return s;
      }),
    );
    expect(d.overall).toBe("additive");
    expect(d.autoPromotable).toBe(true);
    const kinds = d.changes.map((c) => `${c.class}:${c.detail}`);
    expect(kinds.some((k) => k.startsWith("additive:new operation"))).toBe(true);
    expect(kinds.some((k) => k.includes("new field"))).toBe(true);
    expect(kinds.some((k) => k.includes("vocabulary widened by [archived]"))).toBe(true);
    expect(d.changes.every((c) => c.class === "additive")).toBe(true);
  });

  it("C3 documentation-only: descriptions move, behaviour does not", () => {
    const d = diff(variant((s) => { listOp(s).responseSchema.description = "the event list"; return s; }));
    expect(d.overall).toBe("documentation");
    expect(d.autoPromotable).toBe(true);
    expect(d.changes.map((c) => c.class)).toEqual(["documentation"]);
  });

  it("C3b a re-capture with no observable change is documentation, not identical", async () => {
    const from = base();
    const to = structuredClone(from);
    to.capture = { ...to.capture, setId: "different-evidence", capturedAt: new Date().toISOString() };
    const d = diff(to, from);
    expect(d.overall).toBe("documentation");
    expect(d.changes[0]!.detail).toContain("re-captured");
  });

  it("C4 conditional: a narrowed vocabulary and a newly required field need a guard", () => {
    const d = diff(
      variant((s) => {
        detailOp(s).responseSchema.properties!["status"]!.enum = ["published"];
        const events = listOp(s).responseSchema.properties!["events"]!;
        events.items!.required = [...(events.items!.required ?? []), "venue"];
        return s;
      }),
    );
    expect(d.overall).toBe("conditional");
    expect(d.autoPromotable).toBe(false);
    expect(d.blockedBy.join(" ")).toContain("vocabulary narrowed");
    expect(d.blockedBy.join(" ")).toContain("newly required: venue");
  });

  it("C5 breaking: a removed operation, a removed field and a type change", () => {
    const removed = diff(variant((s) => { s.operations = s.operations.filter((o) => o.id !== "get_api_events_event_id"); return s; }));
    expect(removed.overall).toBe("breaking");
    expect(removed.autoPromotable).toBe(false);

    const dropped = diff(variant((s) => { delete listOp(s).responseSchema.properties!["total"]; return s; }));
    expect(dropped.overall).toBe("breaking");
    expect(dropped.changes.some((c) => c.where.endsWith(".total") && c.detail.includes("removed"))).toBe(true);

    const retyped = diff(variant((s) => { listOp(s).responseSchema.properties!["total"] = { type: "string" }; return s; }));
    expect(retyped.overall).toBe("breaking");
    expect(retyped.changes.some((c) => c.detail.includes("type integer -> string"))).toBe(true);
  });

  it("C6 semantic: dropping a certified invariant is breaking, with no schema change at all", () => {
    const d = diff(variant((s) => { s.semanticInvariants = []; return s; }));
    expect(d.overall).toBe("breaking");
    expect(d.changes).toHaveLength(1);
    expect(d.changes[0]!.where).toBe(`invariant.${TOTAL_MATCHES.id}`);
    // the point: every operation and every field is byte-identical
    expect(d.changes.some((c) => c.where.startsWith("get_api_"))).toBe(false);
  });

  it("C7 unknown fails closed: a change the rules cannot explain is never auto-promoted", () => {
    const d = diff(variant((s) => { s.app = "something-else"; return s; }));
    expect(d.overall).toBe("unknown");
    expect(d.autoPromotable).toBe(false);
  });

  it("C8 a diff names the workflow steps a changed operation reaches", () => {
    const d = diff(variant((s) => { delete listOp(s).responseSchema.properties!["total"]; return s; }));
    const change = d.changes.find((c) => c.where.endsWith(".total"))!;
    expect(change.affectedWorkflowSteps).toEqual(["list_then_detail.list"]);
  });

  it("C9 both renderings exist: the diff is machine-readable and the text is derived from it", () => {
    const d = diff(variant((s) => { s.operations = s.operations.filter((o) => o.id !== "get_api_events_event_id"); return s; }));
    expect(JSON.parse(JSON.stringify(d)).changes[0]).toHaveProperty("class");
    const text = renderDiff(d);
    expect(text).toContain("v1 -> v2");
    expect(text).toContain("[breaking] get_api_events_event_id");
    expect(text).toContain("BLOCKED");
    expect(text).not.toMatch(/evt_\d+/); // a diff carries no payload content
  });
});

describe("promotion policy", () => {
  async function seeded() {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const { report, effectiveSpec } = await certify(base(), B(), { deriveExchanges: A() });
    const first = reg.promote(effectiveSpec, report);
    expect(first.stored).toBe(true);
    return { dir, reg, spec: effectiveSpec, report };
  }

  it("C10 the first version is 'initial' with no predecessor", async () => {
    const { reg } = await seeded();
    const v1 = reg.latest("events")!;
    expect(v1.cert.version).toBe(1);
    expect(v1.cert.compat).toBe("initial");
    expect(v1.cert.predecessor).toBeNull();
  });

  it("C11 an additive change promotes itself and records its lineage", async () => {
    const { reg, spec, report } = await seeded();
    const next = structuredClone(spec);
    next.operations.push({ ...spec.operations[0]!, id: "get_api_venues", pathTemplate: "/api/venues" });
    next.specHash = (await import("../src/spec/derive.js")).specHashOf(next);

    const r = reg.promote(next, report);
    expect(r.stored).toBe(true);
    if (!r.stored) return;
    expect(r.cert.version).toBe(2);
    expect(r.cert.compat).toBe("additive");
    expect(r.cert.predecessor).toEqual({ version: 1, specHash: spec.specHash });
    expect(reg.latest("events")?.cert.version).toBe(2);
  });

  it("C12 a breaking change cannot inherit the old certificate and is refused without approval", async () => {
    const { reg, spec, report } = await seeded();
    const next = structuredClone(spec);
    next.operations = next.operations.filter((o) => o.id !== "get_api_events_event_id");
    next.workflows = [];
    next.specHash = (await import("../src/spec/derive.js")).specHashOf(next);

    const refused = reg.promote(next, report);
    expect(refused.stored).toBe(false);
    if (refused.stored) return;
    expect(refused.diff.overall).toBe("breaking");
    expect(refused.reason).toContain("needs explicit approval");
    // v1 is untouched and still served
    expect(reg.latest("events")?.cert.version).toBe(1);
    expect(reg.versions("events")).toEqual([1]);

    const approved = reg.promote(next, report, { approve: true, approvedBy: "test" });
    expect(approved.stored).toBe(true);
    if (!approved.stored) return;
    expect(approved.cert.compat).toBe("breaking");
    // a NEW certificate, not the old one carried forward
    expect(approved.cert.specHash).not.toBe(spec.specHash);
    expect(approved.cert.signature).not.toBe(reg.at("events", 1)!.cert.signature);
  });

  it("C13 a superseded version stays fully verifiable and replayable for comparison and rollback", async () => {
    const { reg, spec, report } = await seeded();
    const next = structuredClone(spec);
    next.operations.push({ ...spec.operations[0]!, id: "get_api_venues", pathTemplate: "/api/venues" });
    next.specHash = (await import("../src/spec/derive.js")).specHashOf(next);
    reg.promote(next, report);
    expect(reg.latest("events")?.cert.version).toBe(2);

    // v1 reads through the SAME gate, not a relaxed one, and still answers calls
    const old = reg.at("events", 1);
    expect(old).not.toBeNull();
    expect(old!.cert.version).toBe(1);
    const { fetcher } = replayFetcher(B());
    const r = await new Adapter(old!.spec, { fetcher }).call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(true);
    expect(reg.versions("events")).toEqual([2, 1]);
  });

  it("C14 lineage and compatibility are signed, so a breaking promotion cannot be relabelled", async () => {
    const { dir, reg, spec, report } = await seeded();
    const cert = reg.at("events", 1)!.cert;
    const relabelled = { ...cert, compat: "additive" };
    const { verifyCertificate, loadTrustAnchor } = await import("../src/registry/certificate.js");
    expect(verifyCertificate(relabelled, loadTrustAnchor(dir)!)).toBe(false);
    const rewired = { ...cert, predecessor: { version: 99, specHash: "0".repeat(64) } };
    expect(verifyCertificate(rewired, loadTrustAnchor(dir)!)).toBe(false);
    void spec; void report;
  });

  it("C15 the adapter hash binds the certificate to the runtime that issued it", async () => {
    // HONEST NOTE ON WHAT THIS BUYS: adapterHashOf() hashes specHash, the mounted
    // operations, the declared invariants, the workflows AND the runtime version.
    // Everything except the runtime version is already inside specHash, so within a
    // single runtime the registry's adapter-hash check is unreachable - verified by
    // mutation, deleting it fails no test. The runtime component is the part that is
    // load-bearing: a certificate issued by one executor version does not silently
    // carry over to another that may interpret the same spec differently.
    const { dir, reg, spec, report } = await seeded();
    const v1 = reg.at("events", 1)!;
    expect(v1.cert.adapterHash).toBe(adapterHashOf(spec));
    expect(adapterHashOf(spec, "9.9.9")).not.toBe(adapterHashOf(spec));

    // ...and a spec whose executor configuration differs is refused - here by the
    // specHash binding, which is the check that actually fires within one runtime.
    const other = structuredClone(spec);
    other.operations[0]!.responseSchema = { type: "object" };
    reg.store({ ...other, specHash: spec.specHash }, report, issueCertificate(spec, report, 2, dir));
    expect(reg.at("events", 2)).toBeNull();
    expect(reg.latest("events")?.cert.version).toBe(1);
  });
});
