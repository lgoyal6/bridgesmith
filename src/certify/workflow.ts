/**
 * Workflow certification: the gate for multi-step behaviour.
 *
 * Per-operation certification proves each response has the right SHAPE. It says
 * nothing about a sequence: that step 2 may only run once step 1 produced an id,
 * that the id step 2 uses is the one step 1 just produced rather than a leftover
 * from an earlier run, that retrying a failed step does not repeat an effect
 * that cannot be repeated, or that the whole thing cleans up after itself.
 *
 * A workflow is data, not code: ordered steps with declared preconditions,
 * extracted state, declarative postconditions, an idempotency class, and
 * optional cleanup. That matters because the workflow lives in the spec, so
 * specHash covers it and the certificate binds to it like everything else.
 *
 * Certification runs the workflow against HOLDOUT evidence through the replay
 * fetcher: no network, no third-party writes, and a call log that makes a
 * duplicated effect observable.
 */
import type { ConnectorSpec, WorkflowSpec, WorkflowStep, Postcondition } from "../core/types.js";
import { Adapter, type Fetcher } from "../codegen/adapter.js";

export type WorkflowFailure =
  | "precondition-failed"
  | "stale-state"
  | "call-failed"
  | "postcondition-failed"
  | "extract-failed"
  | "duplicate-effect"
  | "cleanup-failed"
  | "uncertified-op";

export interface StepResult {
  step: string;
  op: string;
  pass: boolean;
  failure?: WorkflowFailure;
  detail?: string;
  /** Times this step's operation was invoked, including retries. */
  invocations: number;
}

export interface WorkflowResult {
  workflow: string;
  pass: boolean;
  steps: StepResult[];
  cleanup: { op: string; pass: boolean; detail?: string }[];
  failure?: WorkflowFailure;
  detail?: string;
}

interface Binding {
  value: unknown;
  /** Index of the step that produced it; used to detect stale reuse. */
  producedBy: number;
  stale: boolean;
}

export interface RunWorkflowOptions {
  fetcher: Fetcher;
  /** Retry budget per step. Applied ONLY to read-only and idempotent steps. */
  retries?: number;
}

/**
 * Resolve a dotted path with array indexing (`events[0].id`, `total`) against a
 * response body. Returns undefined rather than throwing on any miss.
 */
export function resolvePath(value: unknown, path: string): unknown {
  if (path === "" || path === "$") return value;
  let cur: unknown = value;
  for (const raw of path.split(".")) {
    const m = /^([^[\]]*)((?:\[\d+\])*)$/.exec(raw);
    if (!m) return undefined;
    const [, name, idx] = m;
    if (name) {
      if (cur === null || typeof cur !== "object") return undefined;
      cur = (cur as Record<string, unknown>)[name];
    }
    for (const g of (idx ?? "").matchAll(/\[(\d+)\]/g)) {
      if (!Array.isArray(cur)) return undefined;
      cur = cur[Number(g[1])];
    }
  }
  return cur;
}

function checkPostcondition(pc: Postcondition, body: unknown, state: Map<string, Binding>): string | null {
  switch (pc.kind) {
    case "non-empty": {
      const v = resolvePath(body, pc.path);
      const empty = v === undefined || v === null || (Array.isArray(v) && v.length === 0) || v === "";
      return empty ? `${pc.path} is empty` : null;
    }
    case "equals-state": {
      const v = resolvePath(body, pc.path);
      const b = state.get(pc.state);
      if (!b) return `state "${pc.state}" is not bound`;
      return v === b.value ? null : `${pc.path}=${JSON.stringify(v)} != state "${pc.state}"=${JSON.stringify(b.value)}`;
    }
    case "count-matches": {
      const arr = resolvePath(body, pc.path);
      const total = resolvePath(body, pc.totalPath);
      if (!Array.isArray(arr)) return `${pc.path} is not an array`;
      if (typeof total !== "number") return `${pc.totalPath} is not a number`;
      return arr.length === total ? null : `${pc.path} has ${arr.length} items but ${pc.totalPath} says ${total}`;
    }
  }
}

export async function runWorkflow(
  spec: ConnectorSpec,
  wf: WorkflowSpec,
  certifiedOps: Set<string>,
  opts: RunWorkflowOptions,
): Promise<WorkflowResult> {
  const adapter = new Adapter(spec, { fetcher: opts.fetcher });
  const state = new Map<string, Binding>();
  const steps: StepResult[] = [];
  const cleanup: WorkflowResult["cleanup"] = [];
  const invoked = new Map<string, number>();

  const finish = (failure?: WorkflowFailure, detail?: string): WorkflowResult => ({
    workflow: wf.id,
    pass: !failure,
    steps,
    cleanup,
    ...(failure ? { failure } : {}),
    ...(detail ? { detail } : {}),
  });

  for (let i = 0; i < wf.steps.length; i++) {
    const step = wf.steps[i]!;
    const record = (pass: boolean, failure?: WorkflowFailure, detail?: string): StepResult => {
      const r: StepResult = {
        step: step.id,
        op: step.op,
        pass,
        invocations: invoked.get(step.op) ?? 0,
        ...(failure ? { failure } : {}),
        ...(detail ? { detail } : {}),
      };
      steps.push(r);
      return r;
    };

    // An uncertified operation can never appear in a certified workflow: the
    // workflow gate must not become a side door around the per-op gate.
    if (!certifiedOps.has(step.op)) {
      record(false, "uncertified-op", `${step.op} is not a certified operation`);
      return finish("uncertified-op", `step "${step.id}" calls uncertified ${step.op}`);
    }

    // PRECONDITION: everything this step reads must already be bound. This is
    // what makes an out-of-order step a failure rather than a confusing 404.
    for (const need of step.requires ?? []) {
      const b = state.get(need);
      if (!b) {
        record(false, "precondition-failed", `state "${need}" is not bound yet`);
        return finish("precondition-failed", `step "${step.id}" ran before "${need}" was produced`);
      }
      // STALE STATE: bound, but an intervening step declared it invalid. Reusing
      // it would silently operate on a value the workflow already superseded.
      if (b.stale) {
        record(false, "stale-state", `state "${need}" was invalidated by a later step`);
        return finish("stale-state", `step "${step.id}" reused stale state "${need}"`);
      }
    }

    const params: Record<string, unknown> = { ...(step.constParams ?? {}) };
    for (const [param, key] of Object.entries(step.params ?? {})) {
      params[param] = state.get(key)?.value;
    }

    // RETRY POLICY: a non-idempotent step is never retried, because a retry is
    // indistinguishable from a second invocation to the target. Refusing here is
    // the point - "we retried and hoped" is exactly the failure mode.
    const budget = step.idempotency === "non-idempotent" ? 0 : (opts.retries ?? 0);
    let result = await adapter.call(step.op, params);
    invoked.set(step.op, (invoked.get(step.op) ?? 0) + 1);
    for (let attempt = 0; !result.ok && attempt < budget; attempt++) {
      result = await adapter.call(step.op, params);
      invoked.set(step.op, (invoked.get(step.op) ?? 0) + 1);
    }

    // DUPLICATE EFFECT: whatever the reason, a non-idempotent op that ran twice
    // is a certification failure, not a warning.
    if (step.idempotency === "non-idempotent" && (invoked.get(step.op) ?? 0) > 1) {
      record(false, "duplicate-effect", `non-idempotent ${step.op} was invoked ${invoked.get(step.op)} times`);
      return finish("duplicate-effect", `step "${step.id}" duplicated a non-idempotent effect`);
    }

    if (!result.ok) {
      record(false, "call-failed", result.error ?? result.outcome);
      return finish("call-failed", `step "${step.id}": ${result.error ?? result.outcome}`);
    }

    // POSTCONDITIONS run on a response that already passed schema validation in
    // the adapter, so a failure here is a shape-valid, meaning-wrong response.
    for (const pc of step.postconditions ?? []) {
      const err = checkPostcondition(pc, result.data, state);
      if (err) {
        record(false, "postcondition-failed", err);
        return finish("postcondition-failed", `step "${step.id}": ${err}`);
      }
    }

    for (const key of step.invalidates ?? []) {
      const b = state.get(key);
      if (b) b.stale = true;
    }

    for (const [key, path] of Object.entries(step.extract ?? {})) {
      const v = resolvePath(result.data, path);
      if (v === undefined) {
        record(false, "extract-failed", `cannot extract "${key}" from ${path}`);
        return finish("extract-failed", `step "${step.id}" produced no "${key}"`);
      }
      state.set(key, { value: v, producedBy: i, stale: false });
    }

    record(true);
  }

  // CLEANUP runs in reverse declaration order and its failure fails the whole
  // workflow: a workflow that leaves residue behind is not certified.
  for (const step of [...wf.steps].reverse()) {
    if (!step.cleanup) continue;
    const params: Record<string, unknown> = { ...(step.cleanup.constParams ?? {}) };
    for (const [param, key] of Object.entries(step.cleanup.params ?? {})) params[param] = state.get(key)?.value;
    const r = await adapter.call(step.cleanup.op, params);
    cleanup.push({ op: step.cleanup.op, pass: r.ok, ...(r.ok ? {} : { detail: r.error ?? r.outcome }) });
    if (!r.ok) return finish("cleanup-failed", `cleanup ${step.cleanup.op}: ${r.error ?? r.outcome}`);
  }

  return finish();
}

/** Any step that writes makes the whole workflow a write workflow. */
export function isReadOnlyWorkflow(spec: ConnectorSpec, wf: WorkflowSpec): boolean {
  const byId = new Map(spec.operations.map((o) => [o.id, o]));
  return wf.steps.every((s: WorkflowStep) => byId.get(s.op)?.mutating === false);
}
