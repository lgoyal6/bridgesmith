/**
 * Tracing and drift incidents.
 *
 * Two properties carry the weight. First, a trace links an incident to the spec
 * and certificate it came from WITHOUT carrying any payload, so it can be
 * shipped to a collector that has no business seeing the app's data. Second, a
 * drift incident can be replayed offline, which is the difference between
 * diagnosing a failure and re-attempting it.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Registry } from "../src/registry/registry.js";
import { loadTrustAnchor } from "../src/registry/certificate.js";
import { Adapter } from "../src/codegen/adapter.js";
import { replayFetcher } from "../src/certify/replay.js";
import { readBundle, runBundle, writeBundle } from "../src/replay/bundle.js";
import { buildIncident, classifyDrift, invariantIdFrom } from "../src/observe/incident.js";
import { ATTR, assertNoPayload, Tracer, type Span } from "../src/observe/trace.js";
import type { ConnectorSpec, Exchange, SemanticInvariant } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "obs-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}
const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));

const TOTAL_MATCHES: SemanticInvariant = {
  id: "events.list.total-matches", severity: "blocking",
  kind: "total-matches", op: "get_api_events", path: "events", totalPath: "total",
};

/** Deterministic ids and clock, so span structure can be asserted exactly. */
function fixedTracer() {
  let n = 0;
  let t = 1_000;
  return new Tracer({ idFactory: (bytes) => String(++n).padStart(bytes * 2, "0"), now: () => (t += 5) });
}

async function certified() {
  const dir = mkdtempSync(join(tmpdir(), "reg-"));
  const reg = new Registry(dir);
  const spec: ConnectorSpec = {
    ...deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" }),
    semanticInvariants: [TOTAL_MATCHES],
  };
  const { report, effectiveSpec } = await certify(spec, B(), { deriveExchanges: A() });
  const promoted = reg.promote(effectiveSpec, report);
  if (!promoted.stored) throw new Error(promoted.reason);
  return { dir, reg, report, spec: effectiveSpec, cert: promoted.cert, anchor: loadTrustAnchor(dir)! };
}

/** Same list endpoint, shape broken / meaning broken. */
function drifted(kind: "schema" | "semantic"): Exchange[] {
  return B()
    .filter((e) => e.path === "/api/events")
    .map((e) => {
      const body = e.responseBody as { events: Record<string, unknown>[]; total: number };
      return {
        ...e,
        responseBody:
          kind === "schema"
            ? { ...body, events: body.events.map((x) => ({ ...x, capacity: "fifty" })) }
            : { ...body, total: 47 },
      };
    });
}

describe("spans cover the lifecycle and carry no payload", () => {
  it("T1 spans nest, record status, and serialize as OTLP", async () => {
    const tr = fixedTracer();
    const outer = await tr.span("certify", { [ATTR.app]: "events" }, async (ctx) => {
      await tr.span("certify.operation", { [ATTR.op]: "get_api_events" }, () => "x", ctx.spanId);
      ctx.setAttribute(ATTR.schemaVerdict, "certified");
      return ctx.spanId;
    });

    const spans = tr.all();
    expect(spans.map((s) => s.name)).toEqual(["certify.operation", "certify"]);
    expect(spans[0]!.parentSpanId).toBe(outer);
    expect(spans.every((s) => s.traceId === tr.traceId)).toBe(true);
    expect(spans[1]!.attributes[ATTR.schemaVerdict]).toBe("certified");
    expect(spans.every((s) => s.status.code === "ok")).toBe(true);

    const otlp = tr.toOtlp() as { resourceSpans: [{ scopeSpans: [{ spans: { name: string; status: { code: number }; attributes: unknown[] }[] }] }] };
    const emitted = otlp.resourceSpans[0].scopeSpans[0].spans;
    expect(emitted).toHaveLength(2);
    expect(emitted[0]!.status.code).toBe(1);
    expect(emitted[1]!.attributes).toContainEqual({ key: ATTR.app, value: { stringValue: "events" } });
  });

  it("T2 a span records the failure it was opened to describe, and rethrows", async () => {
    const tr = fixedTracer();
    await expect(
      tr.span("certify", { [ATTR.app]: "events" }, () => {
        throw new Error("holdout replay failed");
      }),
    ).rejects.toThrow("holdout replay failed");
    const s = tr.all()[0]!;
    expect(s.status).toEqual({ code: "error", message: "holdout replay failed" });
  });

  it("T3 correlation is by hash and id, never by content", async () => {
    const { spec, cert } = await certified();
    const tr = fixedTracer();
    tr.record("runtime.invoke", {
      [ATTR.app]: spec.app,
      [ATTR.specHash]: spec.specHash,
      [ATTR.captureSetId]: spec.capture.setId,
      [ATTR.certVersion]: cert.version,
      [ATTR.adapterHash]: cert.adapterHash,
      [ATTR.op]: "get_api_events",
    });
    const span = tr.all()[0]!;
    expect(() => assertNoPayload(span)).not.toThrow();
    const text = JSON.stringify(span);
    expect(text).not.toContain("Event 7"); // no title from the fixture
    expect(text).not.toMatch(/evt_\d+/); // no entity ids
    expect(text).toContain(spec.specHash); // the join key IS there
  });

  it("T4 an attribute large enough to be a response body is rejected", () => {
    const tr = fixedTracer();
    const span: Span = tr.record("runtime.invoke", { "bridgesmith.oops": "x".repeat(300) });
    expect(() => assertNoPayload(span)).toThrow(/too long to be an identifier/);
  });
});

describe("drift is classified, attributed and replayable", () => {
  it("T5 schema drift and a semantic false green are different incidents", async () => {
    const { spec, cert, report, dir } = await certified();

    for (const kind of ["schema", "semantic"] as const) {
      const evidence = drifted(kind);
      const { fetcher } = replayFetcher(evidence);
      const r = await new Adapter(spec, { fetcher, unguarded: true }).call("get_api_events", { limit: "10" });
      expect(r.ok).toBe(false);
      expect(classifyDrift(r)).toBe(kind);

      const tr = fixedTracer();
      const { incident } = buildIncident({
        kind, app: "events", op: "get_api_events", spec, cert, report,
        failing: evidence, result: r, detectionMs: 1.5, registryDir: dir, tracer: tr,
        now: () => new Date("2026-09-19T12:00:00.000Z"),
      });

      expect(incident.kind).toBe(kind);
      expect(incident.certVersion).toBe(cert.version);
      expect(incident.specHash).toBe(spec.specHash);
      expect(incident.traceId).toBe(tr.traceId);
      if (kind === "semantic") expect(incident.invariantId).toBe(TOTAL_MATCHES.id);
      else expect(incident.invariantId).toBeUndefined();

      const breaker = tr.all().find((s) => s.name === "runtime.breaker")!;
      expect(breaker.status.code).toBe("error");
      expect(breaker.attributes[ATTR.driftKind]).toBe(kind);
      expect(() => assertNoPayload(breaker)).not.toThrow();
    }
  });

  it("T6 an incident bundle replays the FAILURE offline, and a passing replay is not a reproduction", async () => {
    const { spec, cert, report, dir, anchor } = await certified();
    const evidence = drifted("semantic");
    const { fetcher } = replayFetcher(evidence);
    const r = await new Adapter(spec, { fetcher, unguarded: true }).call("get_api_events", { limit: "10" });

    const { bundle } = buildIncident({
      kind: "semantic", app: "events", op: "get_api_events", spec, cert, report,
      failing: evidence, result: r, detectionMs: 1, registryDir: dir, tracer: fixedTracer(),
    });
    expect(bundle.signed.manifest.kind).toBe("drift-incident");

    const out = join(mkdtempSync(join(tmpdir(), "inc-")), "events");
    writeBundle(out, bundle);

    const realFetch = globalThis.fetch;
    let attempted = 0;
    globalThis.fetch = (() => { attempted++; throw new Error("network"); }) as typeof fetch;
    let replayed;
    try {
      replayed = await runBundle(readBundle(out), anchor);
    } finally {
      globalThis.fetch = realFetch;
    }

    expect(attempted).toBe(0);
    expect(replayed.verified.ok).toBe(true);
    expect(replayed.reproduced).toBe(true); // the failure is still there
    const op = replayed.ops.find((o) => o.op === "get_api_events")!;
    expect(op.ok).toBe(false);
    expect(op.outcome).toBe("semantic-violation");
    // an operation the incident carries no evidence for is skipped, not failed
    expect(replayed.ops.find((o) => o.op === "get_api_events_event_id")).toMatchObject({ skipped: true });
  });

  it("T7 'reproduced' means opposite things for the two bundle kinds", async () => {
    const { spec, cert, report, dir, anchor } = await certified();
    const healthy = B().filter((e) => e.status === 200 && e.responseBody !== undefined);

    // a CERTIFICATION bundle over healthy evidence reproduces by passing
    const { buildReplayBundle } = await import("../src/replay/bundle.js");
    const certBundle = buildReplayBundle({ kind: "certification", spec, cert, report, exchanges: healthy, registryDir: dir });
    expect((await runBundle(certBundle, anchor)).reproduced).toBe(true);

    // a DRIFT bundle over the same healthy evidence reproduces nothing: the
    // failure it claims to carry is not there
    const notDrifting = buildReplayBundle({ kind: "drift-incident", spec, cert, report, exchanges: healthy, registryDir: dir });
    const r = await runBundle(notDrifting, anchor);
    expect(r.verified.ok).toBe(true);
    expect(r.reproduced).toBe(false);
  });

  it("T8 an incident reason is redacted and clipped before it reaches a bundle or a span", async () => {
    const { spec, cert, report, dir } = await certified();
    const evidence = drifted("schema");
    const tr = fixedTracer();
    const { incident } = buildIncident({
      kind: "schema", app: "events", op: "get_api_events", spec, cert, report, failing: evidence,
      result: { ok: false, outcome: "schema-violation", error: 'token "sk-live-abcdef0123456789abcdef" rejected', ms: 1 },
      detectionMs: 1, registryDir: dir, tracer: tr,
    });
    expect(incident.detail).not.toContain("sk-live-abcdef0123456789abcdef");
    expect(incident.detail).toContain("[redacted]");
    expect(JSON.stringify(tr.all())).not.toContain("sk-live-abcdef0123456789abcdef");
  });

  it("T9 an incident bundle cannot be built around unredacted evidence", async () => {
    const { spec, cert, report, dir } = await certified();
    const leaky = drifted("schema").map((e) => ({ ...e, requestHeaders: { ...e.requestHeaders, authorization: "Bearer sk-live-X" } }));
    expect(() =>
      buildIncident({
        kind: "schema", app: "events", op: "get_api_events", spec, cert, report, failing: leaky,
        result: { ok: false, outcome: "schema-violation", error: "x", ms: 1 }, detectionMs: 1,
        registryDir: dir, tracer: fixedTracer(),
      }),
    ).toThrow(/refusing to bundle unredacted evidence/);
  });

  it("T11 a missing path parameter is refused, not thrown: replay drives ops it has no evidence for", async () => {
    const { spec } = await certified();
    const { fetcher } = replayFetcher(B());
    // `call` is the complete answer for every caller - surfaces, workflows,
    // replay - so an exception escaping it bypasses all of their handling. The
    // incident-replay path hits this directly: an incident carries only the
    // evidence that reproduces it, so by-id operations get no path parameter.
    const r = await new Adapter(spec, { fetcher, unguarded: true }).call("get_api_events_event_id", {});
    expect(r.ok).toBe(false);
    expect(r.outcome).toBe("refused");
    expect(r.error).toContain('missing path param "event_id"');
  });

  it("T10 the invariant id is parsed back out of a runtime attribution", () => {
    expect(invariantIdFrom("semantic invariant events.list.total-matches (total-matches:x): events has 2 items but total says 47")).toBe("events.list.total-matches");
    expect(invariantIdFrom("/events/0/capacity must be integer")).toBeUndefined();
    expect(invariantIdFrom(undefined)).toBeUndefined();
  });
});
