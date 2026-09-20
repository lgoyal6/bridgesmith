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
  | "uncertified-op"
  | "unauthorized"
  | "no-advance"
  | "repeat-exhausted";

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
  /**
   * Where a failing run stopped and what it had established by then. A partial
   * failure that discards its state cannot be replayed, only re-attempted, and
   * "re-attempt and see" is not a diagnosis. Present on failure only.
   */
  checkpoint?: {
    atStepIndex: number;
    atStepId: string;
    completedSteps: string[];
    state: Record<string, unknown>;
    /** Every call the run made, in order, as `METHOD /path`. */
    calls: string[];
  };
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
  /**
   * Consulted before every consequential step, every time it runs. Returning
   * false refuses the step. Absent means no authorization model is in play,
   * which a workflow declaring `requiresAuth` must not silently rely on.
   */
  authorize?: (step: WorkflowStep, scopes: string[]) => boolean;
  /** Observes every call, so a caller can assert on the exact sequence. */
  onCall?: (opId: string, params: Record<string, unknown>) => void;
}

/** A read step is consequential only if it says so; a write always is. */
export function isConsequential(spec: ConnectorSpec, step: WorkflowStep): boolean {
  if (step.consequential !== undefined) return step.consequential;
  return spec.operations.find((o) => o.id === step.op)?.mutating ?? false;
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
  // Certification and replay drive the adapter over RECORDED evidence, so there
  // is no egress for the capability guard to mediate. The guard exists for the
  // serving path, where a call really does leave the process.
  const adapter = new Adapter(spec, { fetcher: opts.fetcher, unguarded: true });
  const state = new Map<string, Binding>();
  const steps: StepResult[] = [];
  const cleanup: WorkflowResult["cleanup"] = [];
  const invoked = new Map<string, number>();
  const calls: string[] = [];
  let atIndex = 0;

  const snapshot = (): Record<string, unknown> =>
    Object.fromEntries([...state.entries()].map(([k, b]) => [k, b.value]));

  const finish = (failure?: WorkflowFailure, detail?: string): WorkflowResult => ({
    workflow: wf.id,
    pass: !failure,
    steps,
    cleanup,
    ...(failure ? { failure } : {}),
    ...(detail ? { detail } : {}),
    ...(failure
      ? {
          checkpoint: {
            atStepIndex: atIndex,
            atStepId: wf.steps[atIndex]?.id ?? "(cleanup)",
            completedSteps: steps.filter((r) => r.pass).map((r) => r.step),
            state: snapshot(),
            calls: [...calls],
          },
        }
      : {}),
  });

  /**
   * Run the cleanup declared by steps that actually COMPLETED, newest first.
   * `completed` is what determines this, not the step list: a step that never
   * ran created nothing to undo, and calling its cleanup would be an effect the
   * workflow never earned.
   */
  const compensate = async (completed: string[]): Promise<void> => {
    for (const step of [...wf.steps].reverse()) {
      if (!step.cleanup || !completed.includes(step.id)) continue;
      const p: Record<string, unknown> = { ...(step.cleanup.constParams ?? {}) };
      for (const [param, key] of Object.entries(step.cleanup.params ?? {})) p[param] = state.get(key)?.value;
      const r = await adapter.call(step.cleanup.op, p);
      cleanup.push({ op: step.cleanup.op, pass: r.ok, ...(r.ok ? {} : { detail: r.error ?? r.outcome }) });
    }
  };

  /**
   * Fail the workflow, compensating first. The ORIGINAL failure is what the
   * workflow reports: a cleanup that also fails is recorded in `cleanup` and
   * never allowed to mask the reason the run stopped.
   */
  const fail = async (failure: WorkflowFailure, detail: string): Promise<WorkflowResult> => {
    await compensate(steps.filter((r) => r.pass).map((r) => r.step));
    return finish(failure, detail);
  };

  for (let i = 0; i < wf.steps.length; i++) {
    const step = wf.steps[i]!;
    atIndex = i;
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
      return fail("uncertified-op", `step "${step.id}" calls uncertified ${step.op}`);
    }

    // PRECONDITION: everything this step reads must already be bound. This is
    // what makes an out-of-order step a failure rather than a confusing 404.
    for (const need of step.requires ?? []) {
      const b = state.get(need);
      if (!b) {
        record(false, "precondition-failed", `state "${need}" is not bound yet`);
        return fail("precondition-failed", `step "${step.id}" ran before "${need}" was produced`);
      }
      // STALE STATE: bound, but an intervening step declared it invalid. Reusing
      // it would silently operate on a value the workflow already superseded.
      if (b.stale) {
        record(false, "stale-state", `state "${need}" was invalidated by a later step`);
        return fail("stale-state", `step "${step.id}" reused stale state "${need}"`);
      }
    }

    // AUTHORIZATION is re-evaluated here, not inherited from an earlier step.
    // A workflow that declares scopes and is run without an authorizer is
    // refused rather than treated as permitted.
    const scopes = step.requiresAuth ?? [];
    if (scopes.length > 0 && isConsequential(spec, step)) {
      if (!opts.authorize) {
        record(false, "unauthorized", `step requires ${scopes.join(", ")} but no authorizer was supplied`);
        return fail("unauthorized", `step "${step.id}" declares scopes with no authorization model in play`);
      }
      if (!opts.authorize(step, scopes)) {
        record(false, "unauthorized", `authorization refused for ${scopes.join(", ")}`);
        return fail("unauthorized", `step "${step.id}" is not authorized for ${scopes.join(", ")}`);
      }
    }

    const buildParams = (): Record<string, unknown> => {
      const p: Record<string, unknown> = { ...(step.constParams ?? {}) };
      for (const [param, key] of Object.entries(step.params ?? {})) p[param] = state.get(key)?.value;
      return p;
    };
    let params = buildParams();

    // RETRY POLICY: a non-idempotent step is never retried, because a retry is
    // indistinguishable from a second invocation to the target. Refusing here is
    // the point - "we retried and hoped" is exactly the failure mode.
    const budget = step.idempotency === "non-idempotent" ? 0 : (opts.retries ?? 0);
    const invoke = async () => {
      opts.onCall?.(step.op, params);
      calls.push(`${step.op}(${JSON.stringify(params)})`);
      const r = await adapter.call(step.op, params);
      invoked.set(step.op, (invoked.get(step.op) ?? 0) + 1);
      return r;
    };
    let result = await invoke();
    for (let attempt = 0; !result.ok && attempt < budget; attempt++) result = await invoke();

    // DUPLICATE EFFECT: whatever the reason, a non-idempotent op that ran twice
    // is a certification failure, not a warning.
    if (step.idempotency === "non-idempotent" && (invoked.get(step.op) ?? 0) > 1) {
      record(false, "duplicate-effect", `non-idempotent ${step.op} was invoked ${invoked.get(step.op)} times`);
      return fail("duplicate-effect", `step "${step.id}" duplicated a non-idempotent effect`);
    }

    if (!result.ok) {
      record(false, "call-failed", result.error ?? result.outcome);
      return fail("call-failed", `step "${step.id}": ${result.error ?? result.outcome}`);
    }

    // POSTCONDITIONS run on a response that already passed schema validation in
    // the adapter, so a failure here is a shape-valid, meaning-wrong response.
    for (const pc of step.postconditions ?? []) {
      const err = checkPostcondition(pc, result.data, state);
      if (err) {
        record(false, "postcondition-failed", err);
        return fail("postcondition-failed", `step "${step.id}": ${err}`);
      }
    }

    for (const key of step.invalidates ?? []) {
      const b = state.get(key);
      if (b) b.stale = true;
    }

    const extractInto = (data: unknown): WorkflowFailure | null => {
      const previous = new Map([...state.entries()].map(([k, b]) => [k, b.value]));
      for (const [key, path] of Object.entries(step.extract ?? {})) {
        const v = resolvePath(data, path);
        if (v === undefined) {
          record(false, "extract-failed", `cannot extract "${key}" from ${path}`);
          return "extract-failed";
        }
        state.set(key, { value: v, producedBy: i, stale: false });
      }
      // ADVANCE: a cursor that does not move is not progress. Checked against the
      // value the key held BEFORE this iteration, so a repeated page is caught on
      // the iteration that repeats it rather than at the end of the run.
      for (const key of step.mustAdvance ?? []) {
        if (!previous.has(key)) continue; // nothing to advance from on the first pass
        if (JSON.stringify(previous.get(key)) === JSON.stringify(state.get(key)?.value)) {
          record(false, "no-advance", `"${key}" did not change: ${JSON.stringify(state.get(key)?.value)}`);
          return "no-advance";
        }
      }
      return null;
    };

    let failure = extractInto(result.data);
    if (failure) return finish(failure, `step "${step.id}" failed on ${failure}`);

    // REPEAT: pagination. Every iteration re-authorizes, re-checks
    // postconditions and re-checks advancement, and exhausting the budget is a
    // failure rather than a quiet stop.
    if (step.repeat) {
      let iterations = 1;
      while (state.get(step.repeat.whileState)?.value) {
        if (iterations >= step.repeat.maxIterations) {
          record(false, "repeat-exhausted", `still looping after ${iterations} iterations`);
          return fail("repeat-exhausted", `step "${step.id}" did not terminate within ${step.repeat.maxIterations} iterations`);
        }
        if (scopes.length > 0 && isConsequential(spec, step) && opts.authorize && !opts.authorize(step, scopes)) {
          record(false, "unauthorized", `authorization refused mid-loop for ${scopes.join(", ")}`);
          return fail("unauthorized", `step "${step.id}" lost authorization during iteration ${iterations + 1}`);
        }
        params = buildParams();
        const next = await invoke();
        iterations++;
        if (!next.ok) {
          record(false, "call-failed", next.error ?? next.outcome);
          return fail("call-failed", `step "${step.id}" iteration ${iterations}: ${next.error ?? next.outcome}`);
        }
        for (const pc of step.postconditions ?? []) {
          const err = checkPostcondition(pc, next.data, state);
          if (err) {
            record(false, "postcondition-failed", `iteration ${iterations}: ${err}`);
            return fail("postcondition-failed", `step "${step.id}" iteration ${iterations}: ${err}`);
          }
        }
        failure = extractInto(next.data);
        if (failure) return finish(failure, `step "${step.id}" failed on ${failure} at iteration ${iterations}`);
      }
    }

    record(true);
  }
  atIndex = wf.steps.length - 1;

  // CLEANUP on the success path runs the same compensation, in reverse step
  // order. Its failure fails the whole workflow: a workflow that leaves residue
  // behind is not certified, however well its steps went.
  await compensate(steps.filter((r) => r.pass).map((r) => r.step));
  const dirty = cleanup.find((c) => !c.pass);
  if (dirty) return finish("cleanup-failed", `cleanup ${dirty.op}: ${dirty.detail}`);

  return finish();
}

/** Any step that writes makes the whole workflow a write workflow. */
export function isReadOnlyWorkflow(spec: ConnectorSpec, wf: WorkflowSpec): boolean {
  const byId = new Map(spec.operations.map((o) => [o.id, o]));
  return wf.steps.every((s: WorkflowStep) => byId.get(s.op)?.mutating === false);
}
