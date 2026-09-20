/**
 * Semantic false greens: responses a schema gate calls perfect and that are
 * still wrong. Every case below validates against the certified schema.
 *
 * The scope claim is deliberately narrow - these are named, DECLARED invariants,
 * not a general semantic-correctness result - and certification keeps three
 * distinct verdicts so a schema pass can never carry a semantic failure over the
 * line, and so "declared nothing" can never read as "passed everything".
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec, specHashOf } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { certifySemantics, checkResponseInvariants, safeDetail, RUNTIME_KINDS } from "../src/certify/semantic.js";
import { replayFetcher } from "../src/certify/replay.js";
import { Adapter } from "../src/codegen/adapter.js";
import { ConnectorMonitor } from "../src/runtime/breaker.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import type { ConnectorSpec, Exchange, SemanticInvariant } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "sem-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}
const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));

const TOTAL_MATCHES: SemanticInvariant = {
  id: "events.list.total-matches", severity: "blocking",
  kind: "total-matches", op: "get_api_events", path: "events", totalPath: "total",
};
const ID_AGREEMENT: SemanticInvariant = {
  id: "events.detail-agrees-with-list", severity: "blocking",
  kind: "id-agreement", idField: "id", fields: ["title", "status", "capacity"],
  sources: [{ op: "get_api_events", path: "events" }, { op: "get_api_events_event_id", path: "$" }],
};
const STATUS_ENUM: SemanticInvariant = {
  id: "events.status-vocabulary", severity: "blocking",
  kind: "enum-consistency", field: "status", allowed: ["draft", "published", "cancelled"],
  sources: [{ op: "get_api_events", path: "events" }, { op: "get_api_events_event_id", path: "$" }],
};

async function certified(invariants: SemanticInvariant[], holdout: Exchange[] = B()) {
  const derived = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
  const spec: ConnectorSpec = { ...derived, semanticInvariants: invariants };
  return certify(spec, holdout, { deriveExchanges: A() });
}

/** Rewrite the holdout's list response so it stays schema-valid but lies. */
function listBody(holdout: Exchange[], patch: (body: Record<string, unknown>) => Record<string, unknown>): Exchange[] {
  return holdout.map((e) => (e.path === "/api/events" && e.responseBody ? { ...e, responseBody: patch(e.responseBody as Record<string, unknown>) } : e));
}

describe("the invariant record is an identity, not a description", () => {
  it("S0 every check carries a stable id, scope, severity, evidence source and evidence hash", async () => {
    const { report } = await certified([TOTAL_MATCHES, ID_AGREEMENT]);
    const c = report.semantic[0]!;
    expect(c.id).toBe("events.list.total-matches"); // author-assigned, not derived
    expect(c.severity).toBe("blocking");
    expect(c.scope).toEqual(["get_api_events"]);
    expect(report.semantic[1]!.scope).toEqual(["get_api_events", "get_api_events_event_id"]);
    expect(c.evidenceSource).toBe("holdout");
    expect(c.evidenceHash).toMatch(/^[0-9a-f]{64}$/);
    expect(c.samples).toBeGreaterThan(0);
  });

  it("S0b the evidence hash is deterministic over the same evidence and changes with it", async () => {
    const one = await certified([TOTAL_MATCHES]);
    const two = await certified([TOTAL_MATCHES]);
    expect(two.report.semantic[0]!.evidenceHash).toBe(one.report.semantic[0]!.evidenceHash);

    const altered = await certified([TOTAL_MATCHES], listBody(B(), (b) => ({ ...b, total: 99 })));
    expect(altered.report.semantic[0]!.evidenceHash).not.toBe(one.report.semantic[0]!.evidenceHash);
  });

  it("S0c the label may change without the id changing, and duplicate ids are refused", async () => {
    const tightened: SemanticInvariant = { ...TOTAL_MATCHES, path: "events", totalPath: "total", description: "tightened" };
    const { report } = await certified([tightened]);
    expect(report.semantic[0]!.id).toBe(TOTAL_MATCHES.id);

    await expect(certified([TOTAL_MATCHES, { ...ID_AGREEMENT, id: TOTAL_MATCHES.id }])).rejects.toThrow(/duplicate semantic invariant id/);
  });
});

describe("schema, semantic and mount verdicts stay distinct", () => {
  it("S1 declared invariants that hold produce three separate certified verdicts", async () => {
    const { report, effectiveSpec } = await certified([TOTAL_MATCHES, ID_AGREEMENT, STATUS_ENUM]);
    expect(report.semantic.map((c) => c.pass)).toEqual([true, true, true]);
    expect(report.schemaVerdict).toBe("certified");
    expect(report.semanticVerdict).toBe("certified");
    expect(report.verdict).toBe("certified");

    const cert = issueCertificate(effectiveSpec, report, 1, mkdtempSync(join(tmpdir(), "reg-")));
    expect(cert.certifiedInvariants.map((i) => i.id)).toEqual(report.semantic.map((c) => c.id));
    expect(cert.certifiedInvariants.map((i) => i.evidenceHash)).toEqual(report.semantic.map((c) => c.evidenceHash));
  });

  it("S1b declaring NO invariants is 'not-declared', never a semantic pass", async () => {
    const derived = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { report } = await certify(derived, B(), { deriveExchanges: A() });
    expect(report.semanticVerdict).toBe("not-declared");
    expect(report.schemaVerdict).toBe("certified");
    expect(report.verdict).toBe("certified"); // mountable, and honest about what was proven
    expect(report.semantic).toEqual([]);
  });

  it("S1c a blocking semantic failure degrades the mount verdict even with a perfect schema verdict", async () => {
    const { report } = await certified([TOTAL_MATCHES, ID_AGREEMENT], listBody(B(), (b) => ({ ...b, total: 99 })));
    expect(report.schemaVerdict).toBe("certified"); // every response is still well-typed
    expect(report.semanticVerdict).toBe("partial");
    expect(report.verdict).toBe("partial");
  });

  it("S1d when every declared blocking invariant fails, semantics are refused outright", async () => {
    const { report } = await certified([TOTAL_MATCHES], listBody(B(), (b) => ({ ...b, total: 99 })));
    expect(report.semanticVerdict).toBe("refused");
    expect(report.verdict).toBe("refused");
    expect(report.schemaVerdict).toBe("certified");
  });

  it("S1e an advisory failure is reported and unmounted, but does not refuse the connector", async () => {
    const advisory: SemanticInvariant = { ...TOTAL_MATCHES, severity: "advisory" };
    const { report, effectiveSpec } = await certified([advisory], listBody(B(), (b) => ({ ...b, total: 99 })));
    expect(report.semantic[0]!.pass).toBe(false);
    expect(report.semanticVerdict).toBe("partial"); // not "refused"
    expect(report.verdict).toBe("partial");
    // severity never buys coverage: a failing invariant is not mounted at either severity
    expect(effectiveSpec.semanticInvariants).toEqual([]);
    const cert = issueCertificate(effectiveSpec, report, 1, mkdtempSync(join(tmpdir(), "reg-")));
    expect(cert.certifiedInvariants).toEqual([]);
  });

  it("S2 an invariant that never executes is refused, never assumed satisfied", async () => {
    const orphan: SemanticInvariant = {
      id: "events.orphan", severity: "blocking",
      kind: "monotonic", op: "get_api_events", path: "nowhere", field: "x", direction: "increasing",
    };
    const { report } = await certified([orphan]);
    expect(report.semantic[0]).toMatchObject({ pass: false, samples: 0 });
    expect(report.semantic[0]!.detail).toContain("no holdout evidence");
    expect(report.semanticVerdict).toBe("refused");
    expect(report.verdict).toBe("refused");
  });

  it("S3 a refused invariant is not carried into the mounted spec or the certificate", async () => {
    const liar = listBody(B(), (b) => ({ ...b, total: 99 }));
    const { report, effectiveSpec } = await certified([TOTAL_MATCHES, ID_AGREEMENT], liar);
    expect(report.semantic.find((c) => c.id === TOTAL_MATCHES.id)?.pass).toBe(false);
    expect(effectiveSpec.semanticInvariants?.map((i) => i.id)).toEqual([ID_AGREEMENT.id]);
    const cert = issueCertificate(effectiveSpec, report, 1, mkdtempSync(join(tmpdir(), "reg-")));
    expect(cert.certifiedInvariants.map((i) => i.id)).toEqual([ID_AGREEMENT.id]);
  });
});

describe("each invariant catches its own shape-valid lie", () => {
  it("S4 totals that do not match the returned collection", async () => {
    const { report } = await certified([TOTAL_MATCHES], listBody(B(), (b) => ({ ...b, total: 99 })));
    expect(report.semantic[0]!.pass).toBe(false);
    expect(report.semantic[0]!.detail).toContain("says 99");
  });

  it("S5 two endpoints disagreeing about the same entity", async () => {
    const holdout = B().map((e) =>
      e.path === "/api/events/evt_1007" && e.responseBody
        ? { ...e, responseBody: { ...(e.responseBody as Record<string, unknown>), title: "Renamed Event" } }
        : e,
    );
    const { report } = await certified([ID_AGREEMENT], holdout);
    expect(report.semantic[0]!.pass).toBe(false);
    expect(report.semantic[0]!.detail).toContain("evt_1007");
    expect(report.semantic[0]!.detail).toContain("Renamed Event");
  });

  it("S6 a field using a vocabulary the connector never declared", async () => {
    const holdout = listBody(B(), (b) => ({
      ...b,
      events: (b.events as Record<string, unknown>[]).map((e, i) => (i === 0 ? { ...e, status: "ARCHIVED" } : e)),
    }));
    const { report } = await certified([STATUS_ENUM], holdout);
    expect(report.semantic[0]!.pass).toBe(false);
    expect(report.semantic[0]!.detail).toContain("ARCHIVED");
  });

  it("S7 timestamps that stop being ordered", async () => {
    const inv: SemanticInvariant = {
      id: "events.list-ordered-by-date", severity: "blocking",
      kind: "monotonic", op: "get_api_events", path: "events", field: "startDate", direction: "increasing",
    };
    const ok = await certified([inv]); // fixture list is already ascending by date
    expect(ok.report.semantic[0]!.pass).toBe(true);

    const shuffled = listBody(B(), (b) => ({ ...b, events: [...(b.events as unknown[])].reverse() }));
    const { report } = await certified([inv], shuffled);
    expect(report.semantic[0]!.pass).toBe(false);
    expect(report.semantic[0]!.detail).toContain("not increasing");
  });

  it("S8 pages that overlap, and pages that leave a gap against the reported total", async () => {
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const inv: SemanticInvariant = {
      id: "events.pages-union", severity: "blocking",
      kind: "pagination-union", op: "get_api_events", path: "events", idField: "id",
    };

    const page = (query: string, ids: number[], total: number): Exchange => ({
      method: "GET", url: `https://api.example-events.com/api/events?${query}`, path: "/api/events",
      query: Object.fromEntries(new URLSearchParams(query)), requestHeaders: {}, status: 200,
      responseHeaders: { "content-type": "application/json" }, responseType: "application/json",
      responseBody: { events: ids.map((n) => ({ id: `evt_${n}` })), total },
    });

    const clean = [page("limit=2", [1, 2], 4), page("limit=2&offset=2", [3, 4], 4)];
    expect(certifySemantics({ ...spec, semanticInvariants: [inv] }, clean)[0]!.pass).toBe(true);

    const overlapping = [page("limit=2", [1, 2], 4), page("limit=2&offset=2", [2, 3], 4)];
    const dup = certifySemantics({ ...spec, semanticInvariants: [inv] }, overlapping)[0]!;
    expect(dup.pass).toBe(false);
    expect(dup.detail).toContain("evt_2");

    const withTotal: SemanticInvariant = { ...inv, totalPath: "total" };
    const gapped = [page("limit=2", [1, 2], 4), page("limit=2&offset=2", [3], 4)];
    const gap = certifySemantics({ ...spec, semanticInvariants: [withTotal] }, gapped)[0]!;
    expect(gap.pass).toBe(false);
    expect(gap.detail).toContain("union to 3");
  });

  it("S9 a numeric field that changed unit between endpoints", async () => {
    const spec = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const inv: SemanticInvariant = {
      id: "events.capacity-unit", severity: "blocking",
      kind: "unit-consistency", field: "capacity", maxRatio: 10,
      sources: [{ op: "get_api_events", path: "events" }, { op: "get_api_events_event_id", path: "$" }],
    };
    const evidence = B();
    expect(certifySemantics({ ...spec, semanticInvariants: [inv] }, evidence)[0]!.pass).toBe(true);

    const slipped = evidence.map((e) =>
      e.path.startsWith("/api/events/") && e.responseBody
        ? { ...e, responseBody: { ...(e.responseBody as Record<string, unknown>), capacity: (e.responseBody as { capacity: number }).capacity * 1000 } }
        : e,
    );
    const bad = certifySemantics({ ...spec, semanticInvariants: [inv] }, slipped)[0]!;
    expect(bad.pass).toBe(false);
    expect(bad.detail).toContain("unit mismatch");
  });
});

describe("the registry will not let a connector self-assert what it passed", () => {
  async function mounted(invariants: SemanticInvariant[]) {
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const { report, effectiveSpec } = await certified(invariants);
    const cert = issueCertificate(effectiveSpec, report, reg.nextVersion("events"), dir);
    reg.store(effectiveSpec, report, cert);
    return { dir, reg, cert, spec: effectiveSpec, report };
  }

  it("S13 removing a certified invariant from the mounted spec un-mounts the connector", async () => {
    const { dir, reg, cert } = await mounted([TOTAL_MATCHES, ID_AGREEMENT]);
    expect(reg.latest("events")?.cert.version).toBe(1);
    expect(cert.certifiedInvariants).toHaveLength(2);

    const path = join(dir, "events", "v1", "spec.json");
    const onDisk = JSON.parse(readFileSync(path, "utf8"));
    const stripped = { ...onDisk, semanticInvariants: onDisk.semanticInvariants.filter((i: { id: string }) => i.id !== TOTAL_MATCHES.id) };
    // even re-deriving specHash so the spec is internally consistent
    stripped.specHash = specHashOf(stripped);
    writeFileSync(path, JSON.stringify(stripped, null, 2));
    expect(reg.latest("events")).toBeNull();
  });

  it("S14 removing an invariant changes the certificate itself, so the drop is visible in the signed artifact", async () => {
    const both = await certified([TOTAL_MATCHES, ID_AGREEMENT]);
    const one = await certified([ID_AGREEMENT]);
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const certBoth = issueCertificate(both.effectiveSpec, both.report, 1, dir);
    const certOne = issueCertificate(one.effectiveSpec, one.report, 1, dir);
    expect(certBoth.certifiedInvariants.map((i) => i.id)).toEqual([TOTAL_MATCHES.id, ID_AGREEMENT.id]);
    expect(certOne.certifiedInvariants.map((i) => i.id)).toEqual([ID_AGREEMENT.id]);
    expect(certOne.specHash).not.toBe(certBoth.specHash);
    expect(certOne.signature).not.toBe(certBoth.signature);
  });

  it("S15 a spec declaring an invariant the certificate never certified is not served", async () => {
    // Isolating check 5 takes care: editing spec.json changes specHash, so check 3
    // fires first and proves nothing about this one. The reachable case is a
    // GENUINE, correctly signed certificate whose specHash matches the stored spec
    // exactly, but whose certified-invariant list is shorter than what the spec
    // declares - which is what "the adapter decided what it passed" looks like on
    // disk. The spec below enforces two invariants; the certificate certifies one.
    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const reg = new Registry(dir);
    const two = await certified([TOTAL_MATCHES, ID_AGREEMENT]);
    const one = await certified([ID_AGREEMENT]);

    const understated = issueCertificate(
      two.effectiveSpec, // so cert.specHash matches the spec that gets stored
      { ...two.report, semantic: one.report.semantic }, // ...but only one invariant is certified
      1,
      dir,
    );
    expect(understated.specHash).toBe(two.effectiveSpec.specHash); // check 3 is satisfied
    expect(understated.certifiedInvariants.map((i) => i.id)).toEqual([ID_AGREEMENT.id]);
    expect(two.effectiveSpec.semanticInvariants).toHaveLength(2);

    reg.store(two.effectiveSpec, two.report, understated);
    expect(reg.latest("events")).toBeNull();

    // control: the same spec with a certificate that certifies both IS served
    const honest = issueCertificate(two.effectiveSpec, two.report, 1, dir);
    reg.store(two.effectiveSpec, two.report, honest);
    expect(reg.latest("events")?.cert.version).toBe(1);
  });
});

describe("schema and semantic false greens are counted separately", () => {
  it("S10 only single-response invariants are enforced live", () => {
    expect([...RUNTIME_KINDS].sort()).toEqual(["enum-consistency", "monotonic", "total-matches"]);
    const corpusOnly: SemanticInvariant = {
      id: "x", severity: "blocking", kind: "pagination-union", op: "get_api_events", path: "events", idField: "id",
    };
    expect(checkResponseInvariants([corpusOnly], "get_api_events", { events: [], total: 7 })).toEqual([]);
  });

  it("S11 a certified op that starts lying is a SEMANTIC false green, with a schema rate of zero", async () => {
    const { report, effectiveSpec } = await certified([TOTAL_MATCHES]);
    expect(report.semantic[0]!.pass).toBe(true);

    const lying = listBody(B(), (b) => ({ ...b, total: 99 }));
    const { fetcher } = replayFetcher(lying);
    const monitor = new ConnectorMonitor(new Set(report.certifiedOps), 3);
    const adapter = new Adapter(effectiveSpec, { fetcher });

    const r = await adapter.call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(false);
    expect(r.outcome).toBe("semantic-violation"); // NOT schema-violation
    expect(r.error).toContain(TOTAL_MATCHES.id); // attribution by stable id
    monitor.record("get_api_events", r);

    const rates = monitor.falseGreenRate();
    expect(rates.falseGreen).toBe(0);
    expect(rates.rate).toBe(0);
    expect(rates.semanticFalseGreen).toBe(1);
    expect(rates.semanticRate).toBeGreaterThan(0);
    expect(monitor.snapshot().ops["get_api_events"]).toMatchObject({ schemaViolations: 0, semanticViolations: 1 });
  });

  it("S11b a schema drift on the same connector is attributed to schema, not semantics", async () => {
    const { report, effectiveSpec } = await certified([TOTAL_MATCHES]);
    // capacity becomes a string: wrong SHAPE, so the schema gate fires first
    const drifted = listBody(B(), (b) => ({
      ...b,
      events: (b.events as Record<string, unknown>[]).map((e) => ({ ...e, capacity: "fifty" })),
    }));
    const { fetcher } = replayFetcher(drifted);
    const monitor = new ConnectorMonitor(new Set(report.certifiedOps), 3);
    const r = await new Adapter(effectiveSpec, { fetcher }).call("get_api_events", { limit: "10" });
    expect(r.outcome).toBe("schema-violation");
    monitor.record("get_api_events", r);

    const rates = monitor.falseGreenRate();
    expect(rates.falseGreen).toBe(1);
    expect(rates.semanticFalseGreen).toBe(0); // the two axes never borrow from each other
  });

  it("S12 with no declared invariants the runtime gate is shape-only and says so by passing the lie", async () => {
    const derived = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
    const { effectiveSpec } = await certify(derived, B(), { deriveExchanges: A() });
    expect(effectiveSpec.semanticInvariants).toBeUndefined();

    const { fetcher } = replayFetcher(listBody(B(), (b) => ({ ...b, total: 99 })));
    const r = await new Adapter(effectiveSpec, { fetcher }).call("get_api_events", { limit: "10" });
    expect(r.ok).toBe(true); // the boundary, stated as a test: shape-only means shape-only
  });

  it("S16 a violation reason is attributable without disclosing captured credentials", () => {
    const leaked = 'events[0].token="sk-live-abcdef0123456789abcdef" is outside the declared vocabulary';
    const safe = safeDetail(leaked);
    expect(safe).not.toContain("sk-live-abcdef0123456789abcdef");
    expect(safe).toContain("[redacted]");
    expect(safeDetail("Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghij.signaturehere")).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    // long details are clipped so a whole body can never ride out in a log line
    expect(safeDetail("x".repeat(5000)).length).toBeLessThan(250);
  });
});
