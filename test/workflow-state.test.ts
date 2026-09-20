/**
 * Stateful workflow certification beyond independent calls.
 *
 * The cases here are the ones a per-call gate structurally cannot see: a cursor
 * that stops advancing, authorization that was true at step 1 and false at step
 * 5, a partial failure that leaves nothing to diagnose, and a sequence where
 * every single response is valid and the ORDER is the bug.
 */
import { describe, it, expect } from "vitest";
import { buildCaptureManifest } from "../src/capture/manifest.js";
import { replayFetcher } from "../src/certify/replay.js";
import { runWorkflow, isConsequential } from "../src/certify/workflow.js";
import type { ConnectorSpec, Exchange, JsonSchema, WorkflowSpec, WorkflowStep } from "../src/core/types.js";

const ORIGIN = "https://api.paged.test";

const pageSchema: JsonSchema = {
  type: "object",
  properties: {
    items: { type: "array", items: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } },
    nextCursor: { type: ["string", "null"] },
  },
  required: ["items"],
};
const okSchema: JsonSchema = { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] };

function ex(method: string, path: string, search: string, body: unknown): Exchange {
  return {
    method, url: `${ORIGIN}${path}${search}`, path,
    query: Object.fromEntries(new URLSearchParams(search.replace(/^\?/, ""))),
    requestHeaders: { accept: "application/json" }, status: 200,
    responseHeaders: { "content-type": "application/json" },
    responseBody: body, responseType: "application/json", capturedBy: "test-fixture/1",
  };
}

function spec(ops: ConnectorSpec["operations"], exchanges: Exchange[]): ConnectorSpec {
  return {
    app: "paged", baseUrl: ORIGIN, tier: "derived-api", auth: { kind: "none" },
    operations: ops, specHash: "test", derivedAt: new Date(0).toISOString(), derivedFrom: "synthetic",
    capture: buildCaptureManifest(exchanges, { app: "paged", role: "derive" }),
  };
}

const listOp = { id: "list", method: "GET", pathTemplate: "/items", pathParams: [], queryParams: [{ name: "cursor", required: false }], responseSchema: pageSchema, samples: 1, mutating: false };
const writeOp = { id: "archive", method: "POST", pathTemplate: "/archive", pathParams: [], queryParams: [], responseSchema: okSchema, samples: 1, mutating: true };
const ALL = (s: ConnectorSpec) => new Set(s.operations.map((o) => o.id));

/** Pages that advance properly: c0 -> c1 -> c2 -> null. */
function goodPages(): Exchange[] {
  return [
    ex("GET", "/items", "", { items: [{ id: "a" }], nextCursor: "c1" }),
    ex("GET", "/items", "?cursor=c1", { items: [{ id: "b" }], nextCursor: "c2" }),
    ex("GET", "/items", "?cursor=c2", { items: [{ id: "c" }], nextCursor: null }),
  ];
}

const paginate: WorkflowSpec = {
  id: "paginate",
  steps: [
    {
      id: "page", op: "list",
      params: { cursor: "cursor" },
      extract: { cursor: "nextCursor" },
      mustAdvance: ["cursor"],
      repeat: { whileState: "cursor", maxIterations: 10 },
      postconditions: [{ kind: "non-empty", path: "items" }],
      idempotency: "read-only",
    },
  ],
};

describe("cursor state must actually advance", () => {
  it("X1 a well-behaved cursor walks every page and terminates", async () => {
    const pages = goodPages();
    const s = spec([listOp], pages);
    const { fetcher, log } = replayFetcher(pages);
    const r = await runWorkflow(s, paginate, ALL(s), { fetcher });
    expect(r.pass).toBe(true);
    expect(r.failure).toBeUndefined();
    expect(log.calls.length).toBe(3); // one call per page, then nextCursor null stops it
  });

  it("X2 a cursor that repeats itself is caught on the iteration that repeats it", async () => {
    // page 2 hands back the SAME cursor it was called with: a classic infinite loop
    const pages = [
      ex("GET", "/items", "", { items: [{ id: "a" }], nextCursor: "c1" }),
      ex("GET", "/items", "?cursor=c1", { items: [{ id: "b" }], nextCursor: "c1" }),
    ];
    const s = spec([listOp], pages);
    const { fetcher, log } = replayFetcher(pages);
    const r = await runWorkflow(s, paginate, ALL(s), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("no-advance");
    expect(r.detail).toContain("no-advance");
    expect(log.calls.length).toBe(2); // stopped immediately, not after ten loops
  });

  it("X3 a loop that never terminates exhausts its budget loudly instead of hanging", async () => {
    // every page advances, so `mustAdvance` is satisfied, and it never ends
    const pages = Array.from({ length: 30 }, (_, i) =>
      ex("GET", "/items", i === 0 ? "" : `?cursor=c${i}`, { items: [{ id: `i${i}` }], nextCursor: `c${i + 1}` }),
    );
    const s = spec([listOp], pages);
    const { fetcher } = replayFetcher(pages);
    const r = await runWorkflow(s, { ...paginate, steps: [{ ...paginate.steps[0]!, repeat: { whileState: "cursor", maxIterations: 4 } }] }, ALL(s), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("repeat-exhausted");
    expect(r.detail).toContain("did not terminate within 4");
  });

  it("X4 every page still has to satisfy the postcondition, not just the first", async () => {
    const pages = [
      ex("GET", "/items", "", { items: [{ id: "a" }], nextCursor: "c1" }),
      ex("GET", "/items", "?cursor=c1", { items: [], nextCursor: "c2" }), // schema-valid, empty
    ];
    const s = spec([listOp], pages);
    const { fetcher } = replayFetcher(pages);
    const r = await runWorkflow(s, paginate, ALL(s), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("postcondition-failed");
    expect(r.detail).toContain("iteration 2");
  });
});

describe("authorization is re-evaluated, never inherited", () => {
  const pages = goodPages();
  const withWrite = () => {
    const exchanges = [...pages, ex("POST", "/archive", "", { ok: true })];
    return { s: spec([listOp, writeOp], exchanges), exchanges };
  };
  const wf: WorkflowSpec = {
    id: "read_then_archive",
    steps: [
      { id: "page", op: "list", extract: { cursor: "nextCursor" }, idempotency: "read-only" },
      { id: "archive", op: "archive", requiresAuth: ["items:write"], idempotency: "non-idempotent" },
    ],
  };

  it("X5 a write step is consequential by default; a read is not unless it says so", () => {
    const { s } = withWrite();
    expect(isConsequential(s, wf.steps[1]!)).toBe(true);
    expect(isConsequential(s, wf.steps[0]!)).toBe(false);
    expect(isConsequential(s, { ...wf.steps[0]!, consequential: true } as WorkflowStep)).toBe(true);
  });

  it("X6 authorization granted at step 1 does not carry to step 2", async () => {
    const { s, exchanges } = withWrite();
    let calls = 0;
    const { fetcher } = replayFetcher(exchanges);
    // authorize the first consequential check, refuse the next
    const r = await runWorkflow(s, wf, ALL(s), { fetcher, authorize: () => ++calls <= 0 });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("unauthorized");
    expect(r.detail).toContain("items:write");
  });

  it("X7 a workflow declaring scopes run with no authorizer is refused, not permitted", async () => {
    const { s, exchanges } = withWrite();
    const { fetcher, log } = replayFetcher(exchanges);
    const r = await runWorkflow(s, wf, ALL(s), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("unauthorized");
    expect(r.detail).toContain("no authorization model in play");
    expect(log.counts.get("POST /archive")).toBeUndefined(); // the write never happened
  });

  it("X8 with authorization granted the same workflow completes", async () => {
    const { s, exchanges } = withWrite();
    const { fetcher, log } = replayFetcher(exchanges);
    const r = await runWorkflow(s, wf, ALL(s), { fetcher, authorize: (_s, scopes) => scopes.includes("items:write") });
    expect(r.pass).toBe(true);
    expect(log.counts.get("POST /archive")).toHaveLength(1);
  });

  it("X9 authorization is re-checked on every loop iteration, not once per step", async () => {
    const s = spec([listOp], pages);
    const loop: WorkflowSpec = {
      id: "authed_pagination",
      steps: [{ ...paginate.steps[0]!, requiresAuth: ["items:read"], consequential: true }],
    };
    let granted = 2; // allow the first two checks, then revoke
    const { fetcher, log } = replayFetcher(pages);
    const r = await runWorkflow(s, loop, ALL(s), { fetcher, authorize: () => granted-- > 0 });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("unauthorized");
    expect(r.detail).toContain("lost authorization during iteration");
    expect(log.calls.length).toBeLessThan(3); // it stopped where the grant stopped
  });
});

describe("a partial failure leaves enough behind to replay it", () => {
  const exchanges = [...goodPages(), ex("POST", "/archive", "", { ok: true })];
  const s = () => spec([listOp, writeOp], exchanges);
  const wf: WorkflowSpec = {
    id: "page_then_fail",
    steps: [
      { id: "page", op: "list", extract: { cursor: "nextCursor" }, idempotency: "read-only" },
      { id: "second", op: "list", params: { cursor: "cursor" }, requires: ["cursor"], extract: { cursor2: "nextCursor" }, idempotency: "read-only" },
      { id: "archive", op: "archive", idempotency: "non-idempotent" },
    ],
  };

  it("X10 the checkpoint names where it stopped, what it had, and every call it made", async () => {
    const sp = s();
    const { fetcher } = replayFetcher(exchanges, { failOnce: { key: "POST /archive", status: 503 } });
    const r = await runWorkflow(sp, wf, ALL(sp), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("call-failed");

    const cp = r.checkpoint!;
    expect(cp.atStepId).toBe("archive");
    expect(cp.atStepIndex).toBe(2);
    expect(cp.completedSteps).toEqual(["page", "second"]);
    expect(cp.state).toEqual({ cursor: "c1", cursor2: "c2" });
    expect(cp.calls).toHaveLength(3);
    expect(cp.calls[2]).toContain("archive");
  });

  it("X11 replaying from the checkpoint reproduces the same failure deterministically", async () => {
    const sp = s();
    const run = async () => {
      const { fetcher } = replayFetcher(exchanges, { failOnce: { key: "POST /archive", status: 503 } });
      return runWorkflow(sp, wf, ALL(sp), { fetcher });
    };
    const first = await run();
    const second = await run();
    expect(second.failure).toBe(first.failure);
    expect(second.checkpoint).toEqual(first.checkpoint);
    expect(second.steps).toEqual(first.steps);
  });

  it("X15 a failed workflow compensates the steps that DID complete, and not the ones that did not", async () => {
    const compensating: WorkflowSpec = {
      id: "compensated",
      steps: [
        { id: "page", op: "list", extract: { cursor: "nextCursor" }, idempotency: "read-only", cleanup: { op: "archive" } },
        { id: "archive", op: "archive", idempotency: "non-idempotent", cleanup: { op: "archive" } },
      ],
    };
    const sp = s();
    const { fetcher, log } = replayFetcher(exchanges, { failOnce: { key: "POST /archive", status: 503 } });
    const r = await runWorkflow(sp, compensating, ALL(sp), { fetcher });

    expect(r.pass).toBe(false);
    expect(r.failure).toBe("call-failed"); // the original reason, not the cleanup
    // step 1 completed, so its cleanup ran; step 2 never completed, so its did not
    expect(r.cleanup).toEqual([{ op: "archive", pass: true }]);
    expect(r.checkpoint!.completedSteps).toEqual(["page"]);
    // one failed attempt at the step itself, one compensating call
    expect(log.counts.get("POST /archive")).toHaveLength(2);
  });

  it("X16 a cleanup that also fails is recorded and never masks the original failure", async () => {
    const compensating: WorkflowSpec = {
      id: "compensation_fails",
      steps: [
        { id: "page", op: "list", extract: { cursor: "nextCursor" }, idempotency: "read-only", cleanup: { op: "archive" } },
        { id: "second", op: "list", requires: ["nope"], idempotency: "read-only" },
      ],
    };
    const sp = s();
    const { fetcher } = replayFetcher(exchanges, { failOnce: { key: "POST /archive", status: 500 } });
    const r = await runWorkflow(sp, compensating, ALL(sp), { fetcher });
    expect(r.failure).toBe("precondition-failed"); // NOT cleanup-failed
    expect(r.cleanup).toEqual([{ op: "archive", pass: false, detail: "HTTP 500" }]);
  });

  it("X12 a passing run carries no checkpoint: there is nothing to diagnose", async () => {
    const sp = s();
    const { fetcher } = replayFetcher(exchanges);
    const r = await runWorkflow(sp, wf, ALL(sp), { fetcher });
    expect(r.pass).toBe(true);
    expect(r.checkpoint).toBeUndefined();
  });
});

describe("state machine: only the valid ordering certifies", () => {
  const exchanges = goodPages();
  const s = () => spec([listOp], exchanges);
  // three steps with a strict dependency chain: a -> b -> c
  const stepsInOrder: WorkflowStep[] = [
    { id: "a", op: "list", extract: { k1: "nextCursor" }, idempotency: "read-only" },
    { id: "b", op: "list", requires: ["k1"], params: { cursor: "k1" }, extract: { k2: "nextCursor" }, idempotency: "read-only" },
    { id: "c", op: "list", requires: ["k2"], params: { cursor: "k2" }, idempotency: "read-only" },
  ];

  function permutations<T>(xs: T[]): T[][] {
    if (xs.length <= 1) return [xs];
    return xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p]));
  }

  it("X13 of all six orderings of a three-step chain, exactly one passes", async () => {
    const sp = s();
    const orders = permutations(stepsInOrder);
    expect(orders).toHaveLength(6);

    const results: { order: string; pass: boolean; failure?: string }[] = [];
    for (const order of orders) {
      const { fetcher } = replayFetcher(exchanges);
      const r = await runWorkflow(sp, { id: "chain", steps: order }, ALL(sp), { fetcher });
      results.push({ order: order.map((x) => x.id).join(">"), pass: r.pass, ...(r.failure ? { failure: r.failure } : {}) });
    }
    const passing = results.filter((r) => r.pass);
    expect(passing.map((p) => p.order)).toEqual(["a>b>c"]);
    // and every rejection is an explained precondition failure, not a crash or a 404
    expect(results.filter((r) => !r.pass).every((r) => r.failure === "precondition-failed")).toBe(true);
  });

  it("X14 a planted sequence where every response is schema-valid and the ORDER is the bug", async () => {
    const sp = s();
    // b before a: b's response validates perfectly, it is just answering a
    // question nobody asked yet, using a cursor that does not exist
    const { fetcher } = replayFetcher(exchanges);
    const r = await runWorkflow(sp, { id: "inverted", steps: [stepsInOrder[1]!, stepsInOrder[0]!] }, ALL(sp), { fetcher });
    expect(r.pass).toBe(false);
    expect(r.failure).toBe("precondition-failed");
    expect(r.detail).toContain("k1");
    expect(r.checkpoint!.completedSteps).toEqual([]); // it never got off the ground
  });
});
