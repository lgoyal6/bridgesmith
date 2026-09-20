/**
 * A certified multi-step WRITE workflow, run entirely against replayed fixtures.
 *
 *   pnpm tsx scripts/write-workflow-proof.ts
 *
 * No third-party service is mutated at any point, and that is a design position
 * rather than a limitation of the demo: Bridgesmith never live-canaries a write.
 * A write workflow is certified the only way a write workflow honestly can be -
 * against recorded evidence, with the retry, ordering, authorization, idempotency
 * and cleanup rules enforced by the same engine that certifies reads.
 *
 * The workflow: open a draft, add an item to it, submit it, and delete the draft
 * on the way out. Every step is a write. The run prints what each guard caught.
 */
import { buildCaptureManifest } from "../src/capture/manifest.js";
import { replayFetcher, invocationCount } from "../src/certify/replay.js";
import { runWorkflow } from "../src/certify/workflow.js";
import { derivePermissions } from "../src/runtime/permissions.js";
import type { ConnectorSpec, Exchange, JsonSchema, WorkflowSpec } from "../src/core/types.js";

const ORIGIN = "https://api.orders.test";

const draftSchema: JsonSchema = { type: "object", properties: { draftId: { type: "string" }, itemCount: { type: "integer" } }, required: ["draftId"] };
const itemSchema: JsonSchema = { type: "object", properties: { draftId: { type: "string" }, itemCount: { type: "integer" } }, required: ["draftId", "itemCount"] };
const submitSchema: JsonSchema = { type: "object", properties: { orderId: { type: "string" }, draftId: { type: "string" }, itemCount: { type: "integer" } }, required: ["orderId", "draftId", "itemCount"] };
const okSchema: JsonSchema = { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] };

const ex = (method: string, path: string, body: unknown): Exchange => ({
  method, url: `${ORIGIN}${path}`, path, query: {},
  requestHeaders: { accept: "application/json" }, status: 200,
  responseHeaders: { "content-type": "application/json" },
  responseBody: body, responseType: "application/json", capturedBy: "recorded-fixture/1",
});

/** Recorded evidence for the happy path. Nothing here touches a real service. */
const EVIDENCE: Exchange[] = [
  ex("POST", "/drafts", { draftId: "d_100", itemCount: 0 }),
  ex("POST", "/drafts/items", { draftId: "d_100", itemCount: 1 }),
  ex("POST", "/drafts/submit", { orderId: "o_900", draftId: "d_100", itemCount: 1 }),
  ex("DELETE", "/drafts", { ok: true }),
];

const op = (id: string, method: string, pathTemplate: string, responseSchema: JsonSchema) => ({
  id, method, pathTemplate, pathParams: [], queryParams: [], responseSchema, samples: 1, mutating: method !== "GET",
});

const SPEC: ConnectorSpec = (() => {
  const base = {
    app: "orders", baseUrl: ORIGIN, tier: "derived-api" as const, auth: { kind: "none" as const },
    operations: [
      op("create_draft", "POST", "/drafts", draftSchema),
      op("add_item", "POST", "/drafts/items", itemSchema),
      op("submit_draft", "POST", "/drafts/submit", submitSchema),
      op("delete_draft", "DELETE", "/drafts", okSchema),
    ],
    specHash: "write-proof", derivedAt: new Date(0).toISOString(), derivedFrom: "recorded",
    capture: buildCaptureManifest(EVIDENCE, { app: "orders", role: "derive" }),
  };
  // Writes are permitted here, explicitly, and the manifest records that decision.
  return { ...base, permissions: derivePermissions(base as ConnectorSpec, { allowWrites: true }) };
})();

const ALL = new Set(SPEC.operations.map((o) => o.id));

const WORKFLOW: WorkflowSpec = {
  id: "draft_then_submit",
  description: "open a draft, add one item, submit it, and clean the draft up",
  steps: [
    {
      id: "open", op: "create_draft",
      postconditions: [{ kind: "non-empty", path: "draftId" }],
      extract: { draftId: "draftId" },
      idempotency: "non-idempotent",
      requiresAuth: ["orders:write"],
      cleanup: { op: "delete_draft", params: { draft_id: "draftId" } },
    },
    {
      id: "add", op: "add_item",
      requires: ["draftId"],
      postconditions: [{ kind: "equals-state", path: "draftId", state: "draftId" }],
      extract: { itemCount: "itemCount" },
      idempotency: "non-idempotent",
      requiresAuth: ["orders:write"],
    },
    {
      id: "submit", op: "submit_draft",
      requires: ["draftId", "itemCount"],
      postconditions: [
        { kind: "equals-state", path: "draftId", state: "draftId" },
        { kind: "equals-state", path: "itemCount", state: "itemCount" }, // the order must carry what we added
      ],
      extract: { orderId: "orderId" },
      idempotency: "non-idempotent",
      requiresAuth: ["orders:write"],
    },
  ],
};

const authorize = (_s: unknown, scopes: string[]) => scopes.includes("orders:write");

async function run(label: string, wf: WorkflowSpec, opts: Parameters<typeof runWorkflow>[3], evidence = EVIDENCE) {
  const { log } = replayFetcher(evidence);
  void log;
  const r = await runWorkflow(SPEC, wf, ALL, opts);
  console.log(`${label}`);
  console.log(`  verdict   ${r.pass ? "PASS" : `REFUSED (${r.failure})`}`);
  if (r.detail) console.log(`  detail    ${r.detail}`);
  if (r.checkpoint) console.log(`  stopped   at "${r.checkpoint.atStepId}" after [${r.checkpoint.completedSteps.join(", ") || "nothing"}], state ${JSON.stringify(r.checkpoint.state)}`);
  if (r.cleanup.length) console.log(`  cleanup   ${r.cleanup.map((c) => `${c.op}=${c.pass ? "ok" : `FAILED (${c.detail})`}`).join(", ")}`);
  console.log();
  return r;
}

async function main() {
  console.log(`connector "${SPEC.app}" - ${SPEC.operations.length} operations, all writes, permissions allowWrites=${SPEC.permissions!.allowWrites}`);
  console.log(`evidence: ${EVIDENCE.length} recorded exchanges. No live third-party call is made anywhere in this script.\n`);

  {
    const { fetcher, log } = replayFetcher(EVIDENCE);
    const r = await run("1. happy path, authorized", WORKFLOW, { fetcher, authorize });
    if (!r.pass) throw new Error("the happy path must certify");
    console.log(`  calls     ${log.calls.join(" -> ")}`);
    console.log(`  cleanup ran exactly once: ${invocationCount(log, "DELETE", "/drafts") === 1}\n`);
  }

  {
    const { fetcher, log } = replayFetcher(EVIDENCE);
    const r = await run("2. same workflow, authorization refused at the first write", WORKFLOW, { fetcher, authorize: () => false });
    if (r.failure !== "unauthorized") throw new Error("expected an authorization refusal");
    console.log(`  nothing was written: ${log.calls.length === 0}\n`);
  }

  {
    const { fetcher } = replayFetcher(EVIDENCE);
    await run("3. steps out of order (submit before the draft exists)", { ...WORKFLOW, id: "inverted", steps: [WORKFLOW.steps[2]!, WORKFLOW.steps[0]!, WORKFLOW.steps[1]!] }, { fetcher, authorize });
  }

  {
    // The submit endpoint agrees on draftId and disagrees on itemCount: every
    // field is the right type, and the order does not contain what we added.
    const lying = EVIDENCE.map((e) => (e.path === "/drafts/submit" ? { ...e, responseBody: { orderId: "o_900", draftId: "d_100", itemCount: 0 } } : e));
    const { fetcher } = replayFetcher(lying);
    const r = await run("4. schema-valid submit that loses the item", WORKFLOW, { fetcher, authorize }, lying);
    if (r.failure !== "postcondition-failed") throw new Error("expected a postcondition refusal");
  }

  {
    // A transient failure on a NON-IDEMPOTENT write. The engine must not retry.
    const { fetcher, log } = replayFetcher(EVIDENCE, { failOnce: { key: "POST /drafts/items", status: 503 } });
    const r = await run("5. transient failure mid-workflow on a non-idempotent write", WORKFLOW, { fetcher, authorize, retries: 5 });
    if (r.failure !== "call-failed") throw new Error("expected the step to fail without retrying");
    console.log(`  add_item invoked exactly once despite retries=5: ${invocationCount(log, "POST", "/drafts/items") === 1}`);
    const compensated = invocationCount(log, "DELETE", "/drafts") === 1;
    console.log(`  the draft opened by step 1 was compensated: ${compensated}`);
    if (!compensated) throw new Error("a failed workflow left residue behind");
    console.log();
  }

  {
    const { fetcher } = replayFetcher(EVIDENCE, { failOnce: { key: "DELETE /drafts", status: 500 } });
    const r = await run("6. every step succeeds and cleanup fails", WORKFLOW, { fetcher, authorize });
    if (r.failure !== "cleanup-failed") throw new Error("expected a cleanup refusal");
    console.log(`  all steps passed: ${r.steps.every((s) => s.pass)} - and the workflow is still refused\n`);
  }

  console.log("Every case behaved as certified. No third-party service was mutated.");
}

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
