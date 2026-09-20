/**
 * Workflow certification. Per-operation certification proves each response has
 * the right shape; none of it says a SEQUENCE is correct. Each test below is one
 * multi-step failure that a schema gate cannot see.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { buildCaptureManifest } from "../src/capture/manifest.js";
import { replayFetcher, invocationCount } from "../src/certify/replay.js";
import { runWorkflow, resolvePath, isReadOnlyWorkflow } from "../src/certify/workflow.js";
import { issueCertificate } from "../src/registry/certificate.js";
import type { ConnectorSpec, Exchange, JsonSchema, WorkflowSpec } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "wf-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}
const A = () => loadHar(harFile(captureA()));
const B = () => loadHar(harFile(captureB()));

/** The workflow under certification: list events, then read back the first one. */
const LIST_THEN_DETAIL: WorkflowSpec = {
  id: "list_then_detail",
  description: "read the event list, then fetch the first event by the id the list reported",
  steps: [
    {
      id: "list",
      op: "get_api_events",
      constParams: { limit: "10" },
      postconditions: [
        { kind: "non-empty", path: "events" },
        { kind: "count-matches", path: "events", totalPath: "total" },
      ],
      extract: { eventId: "events[0].id" },
      idempotency: "read-only",
    },
    {
      id: "detail",
      op: "get_api_events_event_id",
      requires: ["eventId"],
      params: { event_id: "eventId" },
      postconditions: [{ kind: "equals-state", path: "id", state: "eventId" }],
      idempotency: "read-only",
    },
  ],
};

async function certified(workflows: WorkflowSpec[] = [LIST_THEN_DETAIL]) {
  const derived = deriveSpec(A(), { app: "events", captureLabel: "A", host: "example-events.com" });
  const spec: ConnectorSpec = { ...derived, workflows };
  const holdout = B();
  const out = await certify(spec, holdout, { deriveExchanges: A() });
  return { ...out, holdout };
}

/** Synthetic spec with one non-idempotent write op, served entirely from replay. */
function writeSpec(): { spec: ConnectorSpec; exchanges: Exchange[] } {
  const ok: JsonSchema = { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] };
  const exchanges: Exchange[] = [
    {
      method: "POST", url: "https://api.x.test/api/charge", path: "/api/charge", query: {},
      requestHeaders: {}, status: 200, responseHeaders: { "content-type": "application/json" },
      responseBody: { ok: true }, responseType: "application/json",
    },
    {
      method: "DELETE", url: "https://api.x.test/api/charge", path: "/api/charge", query: {},
      requestHeaders: {}, status: 200, responseHeaders: { "content-type": "application/json" },
      responseBody: { ok: true }, responseType: "application/json",
    },
  ];
  const spec: ConnectorSpec = {
    app: "x", baseUrl: "https://api.x.test", tier: "derived-api", auth: { kind: "none" },
    operations: [
      { id: "post_charge", method: "POST", pathTemplate: "/api/charge", pathParams: [], queryParams: [], responseSchema: ok, samples: 1, mutating: true },
      { id: "delete_charge", method: "DELETE", pathTemplate: "/api/charge", pathParams: [], queryParams: [], responseSchema: ok, samples: 1, mutating: true },
    ],
    specHash: "test", derivedAt: new Date(0).toISOString(), derivedFrom: "synthetic",
    capture: buildCaptureManifest(exchanges, { app: "x", role: "derive" }),
  };
  return { spec, exchanges };
}
const ALL_OPS = (s: ConnectorSpec) => new Set(s.operations.map((o) => o.id));

describe("path resolution", () => {
  it("W0 resolves dotted paths with array indexing, and misses return undefined", () => {
    const body = { events: [{ id: "a" }, { id: "b" }], total: 2, nested: { list: [[1, 2]] } };
    expect(resolvePath(body, "total")).toBe(2);
    expect(resolvePath(body, "events[1].id")).toBe("b");
    expect(resolvePath(body, "nested.list[0][1]")).toBe(2);
    expect(resolvePath(body, "events[9].id")).toBeUndefined();
    expect(resolvePath(body, "nope.deeper")).toBeUndefined();
  });
});

describe("a multi-step read workflow certifies against holdout evidence", () => {
  it("W1 list_then_detail passes, is marked read-only, and is named on the certificate", async () => {
    const { report, effectiveSpec } = await certified();
    expect(report.workflows).toEqual([{ id: "list_then_detail", pass: true }]);
    expect(report.verdict).toBe("certified");
    expect(isReadOnlyWorkflow(effectiveSpec, LIST_THEN_DETAIL)).toBe(true);

    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    const cert = issueCertificate(effectiveSpec, report, 1, dir);
    expect(cert.certifiedWorkflows).toEqual(["list_then_detail"]);
  });

  it("W2 a refused workflow is not mounted and is not on the certificate", async () => {
    const broken: WorkflowSpec = {
      id: "broken",
      steps: [{ id: "detail", op: "get_api_events_event_id", requires: ["eventId"], params: { event_id: "eventId" }, idempotency: "read-only" }],
    };
    const { report, effectiveSpec } = await certified([LIST_THEN_DETAIL, broken]);
    expect(report.workflows.find((w) => w.id === "broken")?.pass).toBe(false);
    expect(report.verdict).toBe("partial");
    expect(effectiveSpec.workflows?.map((w) => w.id)).toEqual(["list_then_detail"]);

    const dir = mkdtempSync(join(tmpdir(), "reg-"));
    expect(issueCertificate(effectiveSpec, report, 1, dir).certifiedWorkflows).toEqual(["list_then_detail"]);
  });

  it("W3 a workflow may not call an uncertified operation", async () => {
    const sneaky: WorkflowSpec = {
      id: "sneaky",
      steps: [{ id: "s", op: "get_api_admin_dump", idempotency: "read-only" }],
    };
    const { report } = await certified([sneaky]);
    expect(report.workflows[0]).toMatchObject({ id: "sneaky", pass: false, failure: "uncertified-op" });
  });
});

describe("sequence failures a schema gate cannot see", () => {
  it("W4 a step run out of order is refused, naming the state it needed", async () => {
    const outOfOrder: WorkflowSpec = { ...LIST_THEN_DETAIL, id: "out_of_order", steps: [...LIST_THEN_DETAIL.steps].reverse() };
    const { report } = await certified([outOfOrder]);
    const r = report.workflows[0]!;
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("precondition-failed");
    expect(r.detail).toContain("eventId");
  });

  it("W5 state invalidated by a later step cannot be reused", async () => {
    const stale: WorkflowSpec = {
      id: "stale",
      steps: [
        { ...LIST_THEN_DETAIL.steps[0]!, id: "list" },
        // a refresh step that supersedes the id without producing a new one
        { id: "refresh", op: "get_api_events", constParams: { limit: "10" }, invalidates: ["eventId"], idempotency: "read-only" },
        { ...LIST_THEN_DETAIL.steps[1]!, id: "detail" },
      ],
    };
    const { report } = await certified([stale]);
    expect(report.workflows[0]).toMatchObject({ id: "stale", pass: false, failure: "stale-state" });
    expect(report.workflows[0]!.detail).toContain("eventId");

    // control: without the invalidation the identical sequence certifies
    const fresh: WorkflowSpec = { ...stale, id: "fresh", steps: stale.steps.map((s) => (s.id === "refresh" ? { ...s, invalidates: [] } : s)) };
    const ok = await certified([fresh]);
    expect(ok.report.workflows[0]).toEqual({ id: "fresh", pass: true });
  });

  it("W6 a retry never duplicates a non-idempotent action, and an idempotent one is retried", async () => {
    const { spec, exchanges } = writeSpec();

    const nonIdem: WorkflowSpec = {
      id: "charge",
      steps: [{ id: "charge", op: "post_charge", idempotency: "non-idempotent" }],
    };
    const failFirst = { key: "POST /api/charge", status: 503 };
    const a = replayFetcher(exchanges, { failOnce: failFirst });
    const r1 = await runWorkflow(spec, nonIdem, ALL_OPS(spec), { fetcher: a.fetcher, retries: 5 });
    expect(r1.pass).toBe(false);
    expect(r1.failure).toBe("call-failed"); // refused to retry rather than charging twice
    expect(invocationCount(a.log, "POST", "/api/charge")).toBe(1);

    // control: the SAME transient failure on an idempotent step is retried and recovers
    const idem: WorkflowSpec = { id: "idem", steps: [{ id: "charge", op: "post_charge", idempotency: "idempotent" }] };
    const b = replayFetcher(exchanges, { failOnce: failFirst });
    const r2 = await runWorkflow(spec, idem, ALL_OPS(spec), { fetcher: b.fetcher, retries: 5 });
    expect(r2.pass).toBe(true);
    expect(invocationCount(b.log, "POST", "/api/charge")).toBe(2);
  });

  it("W7 a non-idempotent op invoked twice by the workflow itself is caught as a duplicate effect", async () => {
    const { spec, exchanges } = writeSpec();
    const twice: WorkflowSpec = {
      id: "double_charge",
      steps: [
        { id: "charge", op: "post_charge", idempotency: "non-idempotent" },
        { id: "charge_again", op: "post_charge", idempotency: "non-idempotent" },
      ],
    };
    const { fetcher, log } = replayFetcher(exchanges);
    const r = await runWorkflow(spec, twice, ALL_OPS(spec), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("duplicate-effect");
    expect(invocationCount(log, "POST", "/api/charge")).toBe(2);
  });

  it("W8 cleanup failure fails the workflow even though every step passed", async () => {
    const { spec, exchanges } = writeSpec();
    const wf: WorkflowSpec = {
      id: "charge_then_refund",
      steps: [{ id: "charge", op: "post_charge", idempotency: "non-idempotent", cleanup: { op: "delete_charge" } }],
    };

    const good = replayFetcher(exchanges);
    const okRun = await runWorkflow(spec, wf, ALL_OPS(spec), { fetcher: good.fetcher });
    expect(okRun.pass).toBe(true);
    expect(okRun.cleanup).toEqual([{ op: "delete_charge", pass: true }]);

    // same workflow, cleanup call fails
    const bad = replayFetcher(exchanges, { failOnce: { key: "DELETE /api/charge", status: 500 } });
    const badRun = await runWorkflow(spec, wf, ALL_OPS(spec), { fetcher: bad.fetcher });
    expect(badRun.steps.every((s) => s.pass)).toBe(true);
    expect(badRun.pass).toBe(false);
    expect(badRun.failure).toBe("cleanup-failed");
  });

  it("W9 a schema-VALID response that violates the workflow postcondition is refused", async () => {
    const { effectiveSpec } = await certified();
    // total says 99, the array has 3: every field has the right type, the
    // response is a lie about itself.
    const lying: Exchange[] = B().map((e) =>
      e.path === "/api/events" && e.responseBody
        ? { ...e, responseBody: { ...(e.responseBody as Record<string, unknown>), total: 99 } }
        : e,
    );

    // the schema gate is happy with it: the adapter returns ok
    const probe = replayFetcher(lying);
    const direct = await new Adapter(effectiveSpec, { fetcher: probe.fetcher }).call("get_api_events", { limit: "10" });
    expect(direct.ok).toBe(true);

    // the workflow gate is not
    const { fetcher } = replayFetcher(lying);
    const r = await runWorkflow(effectiveSpec, LIST_THEN_DETAIL, ALL_OPS(effectiveSpec), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("postcondition-failed");
    expect(r.detail).toContain("99");
  });

  it("W10 a shape-valid detail response for the WRONG event is refused by equals-state", async () => {
    const { effectiveSpec } = await certified();
    const wrongEvent: Exchange[] = B().map((e) =>
      e.path.startsWith("/api/events/") && e.responseBody
        ? { ...e, responseBody: { ...(e.responseBody as Record<string, unknown>), id: "evt_9999" } }
        : e,
    );
    const { fetcher } = replayFetcher(wrongEvent);
    const r = await runWorkflow(effectiveSpec, LIST_THEN_DETAIL, ALL_OPS(effectiveSpec), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("postcondition-failed");
    expect(r.detail).toContain("evt_9999");
  });
});
