/**
 * Compatibility between two certified connector versions.
 *
 * A new capture of the same app produces a new spec. The question that decides
 * whether it can be promoted is not "did it certify" - it did, or it would not
 * be here - but "what does it BREAK for anything already calling v(N-1)". Those
 * are different questions, and conflating them is how a green re-certification
 * silently removes an operation someone depends on.
 *
 * The classification is deliberately coarse and fails closed: a change this code
 * cannot explain is `unknown`, which is never auto-promotable. There is no
 * heuristic here that guesses intent.
 */
import type { ConnectorSpec, JsonSchema, OperationSpec, SemanticInvariant, WorkflowSpec } from "../core/types.js";

/** Ordered by severity: later classes dominate earlier ones. */
export const COMPAT_CLASSES = [
  /** First version of a connector: there is nothing to be compatible with. */
  "initial",
  /** Nothing an existing caller can observe. */
  "identical",
  /** New operations, new optional fields, a widened vocabulary. Old callers keep working. */
  "additive",
  /** Same observable behaviour; only descriptions or provenance moved. */
  "documentation",
  /** Old callers keep working only behind a guard: a narrowed vocabulary or a newly required field. */
  "conditional",
  /** An operation, field or workflow an existing caller could be using is gone, or changed type. */
  "breaking",
  /** Not explainable by the rules above. Fails closed. */
  "unknown",
] as const;
export type CompatClass = (typeof COMPAT_CLASSES)[number];

export interface SpecChange {
  class: CompatClass;
  /** Dotted location, e.g. `get_api_events.responseSchema.events[].status`. */
  where: string;
  /** What changed, in one line, with no payload content. */
  detail: string;
  /** Workflow steps that read this location, so a diff names its blast radius. */
  affectedWorkflowSteps: string[];
}

export interface SpecDiff {
  app: string;
  from: { version: number; specHash: string };
  to: { version: number; specHash: string };
  changes: SpecChange[];
  /** The most severe class present. `identical` when there are no changes. */
  overall: CompatClass;
  /** Whether promotion may happen without a human decision. */
  autoPromotable: boolean;
  /** Why not, when it is not. */
  blockedBy: string[];
}

function severity(c: CompatClass): number {
  return COMPAT_CLASSES.indexOf(c);
}

function worst(classes: CompatClass[]): CompatClass {
  return classes.reduce<CompatClass>((acc, c) => (severity(c) > severity(acc) ? c : acc), "identical");
}

/* ---------------------------------------------------------------- *
 * Schema walk
 * ---------------------------------------------------------------- */

function typeSet(s: JsonSchema | undefined): string[] {
  if (!s?.type) return [];
  return (Array.isArray(s.type) ? s.type : [s.type]).slice().sort();
}

function diffSchema(from: JsonSchema | undefined, to: JsonSchema | undefined, where: string, out: Omit<SpecChange, "affectedWorkflowSteps">[]): void {
  if (!from && !to) return;
  if (from && !to) {
    out.push({ class: "breaking", where, detail: "removed from the response schema" });
    return;
  }
  if (!from && to) {
    out.push({ class: "additive", where, detail: "new field in the response schema" });
    return;
  }
  const a = from!;
  const b = to!;

  const ta = typeSet(a);
  const tb = typeSet(b);
  if (ta.join(",") !== tb.join(",")) {
    // Widening a type union keeps old callers working; narrowing or swapping does not.
    const widened = ta.every((t) => tb.includes(t));
    out.push({
      class: widened ? "additive" : "breaking",
      where,
      detail: `type ${ta.join("|") || "(none)"} -> ${tb.join("|") || "(none)"}`,
    });
  }

  const ea = a.enum ? [...a.enum].map(String).sort() : null;
  const eb = b.enum ? [...b.enum].map(String).sort() : null;
  if (ea && !eb) out.push({ class: "additive", where, detail: "vocabulary opened (enum removed)" });
  else if (!ea && eb) out.push({ class: "conditional", where, detail: `vocabulary closed to [${eb.join(", ")}]` });
  else if (ea && eb && ea.join(",") !== eb.join(",")) {
    const removed = ea.filter((v) => !eb.includes(v));
    const added = eb.filter((v) => !ea.includes(v));
    if (removed.length === 0) out.push({ class: "additive", where, detail: `vocabulary widened by [${added.join(", ")}]` });
    else out.push({ class: "conditional", where, detail: `vocabulary narrowed, dropped [${removed.join(", ")}]` });
  }

  const ra = new Set(a.required ?? []);
  const rb = new Set(b.required ?? []);
  const newlyRequired = [...rb].filter((k) => !ra.has(k));
  const noLongerRequired = [...ra].filter((k) => !rb.has(k));
  if (newlyRequired.length) out.push({ class: "conditional", where, detail: `newly required: ${newlyRequired.sort().join(", ")}` });
  if (noLongerRequired.length) out.push({ class: "additive", where, detail: `no longer required: ${noLongerRequired.sort().join(", ")}` });

  if (a.description !== b.description) out.push({ class: "documentation", where, detail: "description changed" });

  const keys = new Set([...Object.keys(a.properties ?? {}), ...Object.keys(b.properties ?? {})]);
  for (const k of [...keys].sort()) diffSchema(a.properties?.[k], b.properties?.[k], `${where}.${k}`, out);
  if (a.items || b.items) diffSchema(a.items, b.items, `${where}[]`, out);
}

function diffOperation(a: OperationSpec, b: OperationSpec, out: Omit<SpecChange, "affectedWorkflowSteps">[]): void {
  if (a.method !== b.method) out.push({ class: "breaking", where: a.id, detail: `method ${a.method} -> ${b.method}` });
  if (a.pathTemplate !== b.pathTemplate) out.push({ class: "breaking", where: a.id, detail: `path ${a.pathTemplate} -> ${b.pathTemplate}` });
  if (a.mutating !== b.mutating) out.push({ class: "breaking", where: a.id, detail: `mutating ${a.mutating} -> ${b.mutating}` });

  const qa = new Map(a.queryParams.map((q) => [q.name, q]));
  const qb = new Map(b.queryParams.map((q) => [q.name, q]));
  for (const [name, q] of qa) {
    const other = qb.get(name);
    if (!other) out.push({ class: "breaking", where: `${a.id}.query.${name}`, detail: "query parameter removed" });
    else if (!q.required && other.required) out.push({ class: "conditional", where: `${a.id}.query.${name}`, detail: "query parameter became required" });
  }
  for (const name of qb.keys()) if (!qa.has(name)) out.push({ class: "additive", where: `${a.id}.query.${name}`, detail: "new query parameter" });

  diffSchema(a.responseSchema, b.responseSchema, `${a.id}.response`, out);
}

/* ---------------------------------------------------------------- *
 * Blast radius: which workflow steps read a changed location
 * ---------------------------------------------------------------- */

function stepsTouching(where: string, workflows: WorkflowSpec[] | undefined): string[] {
  const opId = where.split(".")[0];
  const out: string[] = [];
  for (const wf of workflows ?? []) {
    for (const step of wf.steps) {
      if (step.op === opId || step.cleanup?.op === opId) out.push(`${wf.id}.${step.id}`);
    }
  }
  return [...new Set(out)].sort();
}

/* ---------------------------------------------------------------- *
 * Public API
 * ---------------------------------------------------------------- */

export function diffSpecs(
  from: ConnectorSpec,
  to: ConnectorSpec,
  versions: { from: number; to: number },
): SpecDiff {
  const raw: Omit<SpecChange, "affectedWorkflowSteps">[] = [];

  if (from.app !== to.app) raw.push({ class: "unknown", where: "app", detail: `app identity changed ${from.app} -> ${to.app}` });
  if (from.baseUrl !== to.baseUrl) raw.push({ class: "breaking", where: "baseUrl", detail: `base URL ${from.baseUrl} -> ${to.baseUrl}` });
  if (from.tier !== to.tier) raw.push({ class: "breaking", where: "tier", detail: `access tier ${from.tier} -> ${to.tier}` });
  if (from.auth.kind !== to.auth.kind) raw.push({ class: "breaking", where: "auth", detail: `auth scheme ${from.auth.kind} -> ${to.auth.kind}` });

  const opsA = new Map(from.operations.map((o) => [o.id, o]));
  const opsB = new Map(to.operations.map((o) => [o.id, o]));
  for (const [id, a] of opsA) {
    const b = opsB.get(id);
    if (!b) raw.push({ class: "breaking", where: id, detail: "operation removed" });
    else diffOperation(a, b, raw);
  }
  for (const id of opsB.keys()) if (!opsA.has(id)) raw.push({ class: "additive", where: id, detail: "new operation" });

  // Workflows
  const wfA = new Map((from.workflows ?? []).map((w) => [w.id, w]));
  const wfB = new Map((to.workflows ?? []).map((w) => [w.id, w]));
  for (const [id, a] of wfA) {
    const b = wfB.get(id);
    if (!b) raw.push({ class: "breaking", where: `workflow.${id}`, detail: "certified workflow removed" });
    else if (a.steps.map((s) => `${s.id}:${s.op}`).join(">") !== b.steps.map((s) => `${s.id}:${s.op}`).join(">"))
      raw.push({ class: "breaking", where: `workflow.${id}`, detail: "step order or operations changed" });
  }
  for (const id of wfB.keys()) if (!wfA.has(id)) raw.push({ class: "additive", where: `workflow.${id}`, detail: "new workflow" });

  // Semantic invariants. Dropping one is not cosmetic: a caller that relied on a
  // certified meaning loses that guarantee with no schema change to warn them.
  const invA = new Map((from.semanticInvariants ?? []).map((i: SemanticInvariant) => [i.id, i]));
  const invB = new Map((to.semanticInvariants ?? []).map((i: SemanticInvariant) => [i.id, i]));
  for (const [id] of invA) {
    if (!invB.has(id)) raw.push({ class: "breaking", where: `invariant.${id}`, detail: "certified semantic invariant no longer holds or was dropped" });
  }
  for (const id of invB.keys()) if (!invA.has(id)) raw.push({ class: "additive", where: `invariant.${id}`, detail: "new semantic invariant" });

  // Provenance-only movement is documentation: same shape, new capture.
  if (from.capture.setId !== to.capture.setId && raw.length === 0) {
    raw.push({ class: "documentation", where: "capture", detail: "re-captured from new evidence with no observable change" });
  }

  const changes: SpecChange[] = raw.map((c) => ({ ...c, affectedWorkflowSteps: stepsTouching(c.where, to.workflows ?? from.workflows) }));
  const overall = worst(changes.map((c) => c.class));

  // Promotion policy. Only changes nothing observable, pure additions and pure
  // documentation promote themselves. Everything else - including `unknown` -
  // waits for a decision, which is what failing closed means here.
  const blocking = changes.filter((c) => severity(c.class) >= severity("conditional"));
  return {
    app: to.app,
    from: { version: versions.from, specHash: from.specHash },
    to: { version: versions.to, specHash: to.specHash },
    changes,
    overall,
    autoPromotable: blocking.length === 0,
    blockedBy: blocking.map((c) => `${c.class}: ${c.where} (${c.detail})`),
  };
}

/** Human-readable rendering. The machine-readable form is the SpecDiff itself. */
export function renderDiff(d: SpecDiff): string {
  const lines = [
    `${d.app}: v${d.from.version} -> v${d.to.version}`,
    `  overall: ${d.overall}`,
    `  auto-promotable: ${d.autoPromotable ? "yes" : "no"}`,
  ];
  if (d.changes.length === 0) lines.push("  (no observable changes)");
  for (const c of d.changes) {
    lines.push(`  [${c.class}] ${c.where}: ${c.detail}`);
    if (c.affectedWorkflowSteps.length) lines.push(`      affects workflow steps: ${c.affectedWorkflowSteps.join(", ")}`);
  }
  for (const b of d.blockedBy) lines.push(`  BLOCKED ${b}`);
  return lines.join("\n");
}
