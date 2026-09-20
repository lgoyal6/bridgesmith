/**
 * Semantic invariants: the second kind of false green.
 *
 * Schema validation asks "is this the right shape". It passes an API that
 * returns `total: 99` above three items, a detail endpoint that disagrees with
 * the list endpoint about the same entity, a page-2 that repeats page-1, a
 * timestamp field that switched from seconds to milliseconds, or a status enum
 * one endpoint spells differently from another. Every one of those is
 * well-typed JSON and a wrong answer.
 *
 * The scope claim is narrow on purpose. These are named, opt-in properties a
 * connector DECLARES. Passing them is not a claim that a connector is
 * semantically correct in general - that is not decidable here, and the report
 * counts schema and semantic outcomes separately so the two are never conflated.
 *
 * Kinds split into two groups:
 *   - runtime-checkable: decidable from one response alone, so the adapter can
 *     evaluate them on every live call (total-matches, monotonic,
 *     enum-consistency within one response);
 *   - corpus-only: need several responses, so they are evaluated at
 *     certification time against the holdout (id-agreement, pagination-union,
 *     unit-consistency).
 */
import type { ConnectorSpec, Exchange, SemanticCheck, SemanticInvariant } from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import { pathMatches } from "./certify.js";
import { resolvePath } from "./workflow.js";

/** Invariants decidable from a single response, and therefore enforceable live. */
export const RUNTIME_KINDS = new Set<SemanticInvariant["kind"]>(["total-matches", "monotonic", "enum-consistency"]);

export function invariantLabel(inv: SemanticInvariant): string {
  switch (inv.kind) {
    case "id-agreement":
      return `id-agreement:${inv.idField}:${inv.sources.map((s) => s.op).join("+")}`;
    case "monotonic":
      return `monotonic:${inv.op}:${inv.path}.${inv.field}:${inv.direction}`;
    case "pagination-union":
      return `pagination-union:${inv.op}:${inv.idField}`;
    case "total-matches":
      return `total-matches:${inv.op}:${inv.path}~${inv.totalPath}`;
    case "enum-consistency":
      return `enum-consistency:${inv.field}`;
    case "unit-consistency":
      return `unit-consistency:${inv.field}`;
  }
}

/** Ops an invariant reads, so the adapter can tell which apply to a given call. */
export function invariantOps(inv: SemanticInvariant): string[] {
  return "op" in inv ? [inv.op] : inv.sources.map((s) => s.op);
}

/** Normalize a resolved path to a list of objects: single objects count as one. */
function objectsAt(body: unknown, path: string): Record<string, unknown>[] {
  const v = resolvePath(body, path);
  const arr = Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
  return arr.filter((x): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x));
}

function numeric(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const t = Date.parse(v);
    if (!Number.isNaN(t)) return t;
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Single-response checks. Shared by certification and the live runtime.
 * ------------------------------------------------------------------ */

/**
 * How many values one response actually let an invariant inspect. Counting
 * matching RESPONSES is not enough: a `monotonic` invariant over a path that
 * resolves to nothing inspects an empty list and would pass vacuously, which is
 * the same mistake as mounting an operation with no holdout coverage.
 */
function evidenceIn(inv: SemanticInvariant, body: unknown): number {
  switch (inv.kind) {
    case "total-matches":
      return Array.isArray(resolvePath(body, inv.path)) && typeof resolvePath(body, inv.totalPath) === "number" ? 1 : 0;
    case "monotonic":
      return objectsAt(body, inv.path).filter((o) => o[inv.field] !== undefined).length;
    case "enum-consistency":
      return inv.sources.reduce(
        (n, src) => n + objectsAt(body, src.path).filter((o) => o[inv.field] !== undefined && o[inv.field] !== null).length,
        0,
      );
    default:
      return 0;
  }
}

function checkOneResponse(inv: SemanticInvariant, body: unknown): string | null {
  switch (inv.kind) {
    case "total-matches": {
      const items = resolvePath(body, inv.path);
      const total = resolvePath(body, inv.totalPath);
      if (!Array.isArray(items)) return `${inv.path} is not an array`;
      if (typeof total !== "number") return `${inv.totalPath} is not a number`;
      return items.length === total ? null : `${inv.path} has ${items.length} items but ${inv.totalPath} says ${total}`;
    }
    case "monotonic": {
      const items = objectsAt(body, inv.path);
      let prev: number | null = null;
      for (const [i, item] of items.entries()) {
        const n = numeric(item[inv.field]);
        if (n === null) return `${inv.path}[${i}].${inv.field} is not comparable`;
        if (prev !== null) {
          const ok = inv.direction === "increasing" ? n >= prev : n <= prev;
          if (!ok) return `${inv.field} is not ${inv.direction} at ${inv.path}[${i}] (${prev} then ${n})`;
        }
        prev = n;
      }
      return null;
    }
    case "enum-consistency": {
      const allowed = new Set(inv.allowed);
      for (const src of inv.sources) {
        for (const [i, item] of objectsAt(body, src.path).entries()) {
          const v = item[inv.field];
          if (v === undefined || v === null) continue;
          if (!allowed.has(String(v))) return `${src.path}[${i}].${inv.field}="${String(v)}" is outside the declared vocabulary`;
        }
      }
      return null;
    }
    default:
      return null; // corpus-only kinds are not decidable from one response
  }
}

/**
 * The breaker and the trace have to say WHY a call was refused, and that reason
 * is built from response content. Values are therefore clipped and any captured
 * credential shape is masked, so an attribution can be logged without becoming a
 * disclosure. The invariant id and kind carry the diagnostic weight; the value
 * is only there to make the reason readable.
 */
const SECRETISH = /\b(?:bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9_-]{32,})\b/g;
const MAX_DETAIL = 200;

export function safeDetail(detail: string): string {
  const masked = detail.replace(SECRETISH, "[redacted]");
  return masked.length > MAX_DETAIL ? `${masked.slice(0, MAX_DETAIL)}...` : masked;
}

/**
 * Evaluate every runtime-checkable invariant that applies to `opId` against one
 * response body. Returns the violations; an empty array means nothing was
 * violated, which is NOT the same as "this response is semantically correct".
 */
export function checkResponseInvariants(
  invariants: SemanticInvariant[] | undefined,
  opId: string,
  body: unknown,
): { id: string; label: string; detail: string }[] {
  const out: { id: string; label: string; detail: string }[] = [];
  for (const inv of invariants ?? []) {
    if (!RUNTIME_KINDS.has(inv.kind)) continue;
    if (!invariantOps(inv).includes(opId)) continue;
    const err = checkOneResponse(inv, body);
    if (err) out.push({ id: inv.id, label: invariantLabel(inv), detail: safeDetail(err) });
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Corpus checks, evaluated at certification time over holdout evidence.
 * ------------------------------------------------------------------ */

function samplesFor(spec: ConnectorSpec, opId: string, exchanges: Exchange[]): Exchange[] {
  const op = spec.operations.find((o) => o.id === opId);
  if (!op) return [];
  return exchanges.filter((e) => e.method === op.method && pathMatches(op.pathTemplate, e.path));
}

function checkCorpus(inv: SemanticInvariant, spec: ConnectorSpec, exchanges: Exchange[]): { detail: string | null; samples: number } {
  switch (inv.kind) {
    case "id-agreement": {
      // entity id -> field -> the first value seen, plus where it came from
      const seen = new Map<string, Map<string, { value: unknown; from: string }>>();
      let samples = 0;
      for (const src of inv.sources) {
        for (const ex of samplesFor(spec, src.op, exchanges)) {
          for (const item of objectsAt(ex.responseBody, src.path)) {
            const id = item[inv.idField];
            if (id === undefined || id === null) continue;
            samples++;
            const byField = seen.get(String(id)) ?? new Map();
            for (const f of inv.fields) {
              if (!(f in item)) continue;
              const prior = byField.get(f);
              if (prior && JSON.stringify(prior.value) !== JSON.stringify(item[f])) {
                return {
                  detail: `${inv.idField}=${String(id)}: ${src.op} says ${f}=${JSON.stringify(item[f])}, ${prior.from} says ${JSON.stringify(prior.value)}`,
                  samples,
                };
              }
              if (!prior) byField.set(f, { value: item[f], from: src.op });
            }
            seen.set(String(id), byField);
          }
        }
      }
      return { detail: null, samples };
    }
    case "pagination-union": {
      const pages = samplesFor(spec, inv.op, exchanges);
      const owner = new Map<string, string>();
      let reportedTotal: number | null = null;
      for (const ex of pages) {
        const page = new URL(ex.url).search || "(no query)";
        for (const item of objectsAt(ex.responseBody, inv.path)) {
          const id = item[inv.idField];
          if (id === undefined || id === null) continue;
          const prior = owner.get(String(id));
          if (prior && prior !== page)
            return { detail: `id ${String(id)} appears on both "${prior}" and "${page}"`, samples: pages.length };
          owner.set(String(id), page);
        }
        if (inv.totalPath) {
          const t = resolvePath(ex.responseBody, inv.totalPath);
          if (typeof t === "number") reportedTotal = Math.max(reportedTotal ?? 0, t);
        }
      }
      if (inv.totalPath && reportedTotal !== null && owner.size !== reportedTotal)
        return { detail: `pages union to ${owner.size} distinct ids but ${inv.totalPath} reports ${reportedTotal}`, samples: pages.length };
      return { detail: null, samples: pages.length };
    }
    case "unit-consistency": {
      // Compare the median magnitude of the field per source. A seconds->millis
      // slip is a ~1000x jump; anything under maxRatio is treated as the same unit.
      const medians: { op: string; median: number }[] = [];
      let samples = 0;
      for (const src of inv.sources) {
        const values: number[] = [];
        for (const ex of samplesFor(spec, src.op, exchanges)) {
          for (const item of objectsAt(ex.responseBody, src.path)) {
            const n = numeric(item[inv.field]);
            if (n !== null && n !== 0) values.push(Math.abs(n));
          }
        }
        if (values.length === 0) continue;
        samples += values.length;
        values.sort((a, b) => a - b);
        medians.push({ op: src.op, median: values[Math.floor(values.length / 2)]! });
      }
      if (medians.length < 2) return { detail: null, samples };
      const lo = medians.reduce((m, x) => (x.median < m.median ? x : m));
      const hi = medians.reduce((m, x) => (x.median > m.median ? x : m));
      const ratio = hi.median / lo.median;
      return ratio > inv.maxRatio
        ? { detail: `${inv.field} differs by ${ratio.toFixed(0)}x between ${lo.op} and ${hi.op} (max ${inv.maxRatio}x): likely a unit mismatch`, samples }
        : { detail: null, samples };
    }
    default: {
      // runtime-checkable kinds: evaluate them over every recorded response
      const ops = [...new Set(invariantOps(inv))];
      let samples = 0;
      for (const opId of ops) {
        for (const ex of samplesFor(spec, opId, exchanges)) {
          samples += evidenceIn(inv, ex.responseBody);
          const err = checkOneResponse(inv, ex.responseBody);
          if (err) return { detail: err, samples };
        }
      }
      return { detail: null, samples };
    }
  }
}

/** Every exchange an invariant is allowed to read, in a stable order. */
function evidenceFor(inv: SemanticInvariant, spec: ConnectorSpec, exchanges: Exchange[]): Exchange[] {
  const ops = [...new Set(invariantOps(inv))].sort();
  const out: Exchange[] = [];
  for (const opId of ops) out.push(...samplesFor(spec, opId, exchanges));
  return out;
}

/**
 * Hash of exactly the responses an invariant was evaluated against. Two runs
 * over the same evidence produce the same hash, which is what makes a check a
 * reproducible record rather than a claim. The certificate binds to it, so
 * re-running certification against DIFFERENT evidence cannot silently inherit a
 * prior pass.
 */
function evidenceHashOf(inv: SemanticInvariant, evidence: Exchange[]): string {
  return sha256(
    canonicalJson({
      ops: [...new Set(invariantOps(inv))].sort(),
      bodies: evidence.map((e) => `${e.method} ${e.path}${new URL(e.url).search} -> ${sha256(canonicalJson(e.responseBody ?? null))}`),
    }),
  );
}

/**
 * Evaluate every declared invariant over a body of evidence.
 *
 * An invariant that inspected nothing is reported as FAILING, not passing: an
 * unexercised invariant must never be mistaken for a satisfied one, the same
 * rule the per-operation gate applies to an operation with no holdout coverage.
 * Severity changes whether a failure blocks the connector; it never changes
 * whether a failing invariant counts as coverage.
 */
export function certifySemantics(spec: ConnectorSpec, exchanges: Exchange[]): SemanticCheck[] {
  return (spec.semanticInvariants ?? []).map((inv) => {
    const evidence = evidenceFor(inv, spec, exchanges);
    const { detail, samples } = checkCorpus(inv, spec, exchanges);
    const base = {
      id: inv.id,
      kind: inv.kind,
      severity: inv.severity,
      label: invariantLabel(inv),
      scope: [...new Set(invariantOps(inv))].sort(),
      evidenceSource: "holdout" as const,
      evidenceHash: evidenceHashOf(inv, evidence),
      samples,
    };
    if (samples === 0) return { ...base, pass: false, detail: "no holdout evidence exercises this invariant" };
    return detail ? { ...base, pass: false, detail } : { ...base, pass: true };
  });
}

/** Duplicate ids make the certificate's invariant set ambiguous, so they are refused up front. */
export function assertUniqueInvariantIds(spec: ConnectorSpec): void {
  const seen = new Set<string>();
  for (const inv of spec.semanticInvariants ?? []) {
    if (seen.has(inv.id)) throw new Error(`duplicate semantic invariant id "${inv.id}"`);
    seen.add(inv.id);
  }
}
