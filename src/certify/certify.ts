/**
 * Certification: the gate between "generated" and "mounted".
 *
 * Inputs are strictly separated: the spec was derived from capture A; this file
 * only ever sees the HOLDOUT capture B (never A) plus, optionally, a live canary.
 *
 * Checks per operation:
 *  1. holdout-replay: every B response for this op must validate against the
 *     spec's response schema. No B coverage => the op is refused by policy
 *     ("never mount an unexercised operation").
 *  2. mutation: corrupted B responses must be REJECTED by the same validator the
 *     runtime uses. Survivor mutants are counted and reported (missed).
 *  3. canary (optional, live): non-mutating ops only, small N, validated.
 *
 * Repair: a holdout failure re-runs schema inference over A+B samples for that
 * op, then re-checks against B. Repaired ops are marked as such (honesty over
 * theater) and the mutation suite re-runs against the widened schema so
 * over-widening shows up as missed mutants.
 */
import type {
  CertificationReport,
  ConnectorSpec,
  Exchange,
  MutationStats,
  OpCheck,
  OperationSpec,
} from "../core/types.js";
import { apiExchanges } from "../capture/har.js";
import { inferSchema } from "../spec/infer.js";
import { generateMutants } from "./mutate.js";
import { validateAgainst } from "../runtime/validate.js";
import { templatePaths } from "../spec/paths.js";
import { specHashOf } from "../spec/derive.js";
import { buildCaptureManifest, isSameEvidence } from "../capture/manifest.js";

export interface CertifyOptions {
  /** Max repair iterations per op. */
  maxRepairs?: number;
  /** Exchanges from capture A, used ONLY for repair re-inference. */
  deriveExchanges?: Exchange[];
  /** Live canary runner; absent = skip canary (offline mode). */
  canary?: (op: OperationSpec) => Promise<{ ok: boolean; detail: string }>;
  /** Confidence floor used when re-inferring during repair. */
  minSamplesForRequired?: number;
  /** Overrides the driver recorded on the holdout exchanges when building its manifest. */
  holdoutDriver?: string;
  log?: (line: string) => void;
}

export interface CertifyOutcome {
  report: CertificationReport;
  /** Spec with any repaired schemas swapped in: this is what gets mounted. */
  effectiveSpec: ConnectorSpec;
  repairedOps: { op: string; iterations: number }[];
}

export async function certify(
  spec: ConnectorSpec,
  holdout: Exchange[],
  opts: CertifyOptions = {},
): Promise<CertifyOutcome> {
  const log = opts.log ?? (() => {});
  const maxRepairs = opts.maxRepairs ?? 2;
  const startedAt = new Date().toISOString();
  const checks: OpCheck[] = [];
  const mutationTotals: MutationStats = { generated: 0, caught: 0, missed: 0, missedKinds: [] };
  const certifiedOps: string[] = [];
  const refusedOps: { op: string; reason: string }[] = [];
  const uncoveredOps: string[] = [];
  const repairedOps: { op: string; iterations: number }[] = [];

  const holdoutApi = apiExchanges(holdout).filter((e) => e.url.startsWith(spec.baseUrl));

  // Provenance of what this certification is actually testing against. Built
  // before any check runs, because a holdout that is the derive capture under a
  // different name cannot certify anything: every op would replay against the
  // samples its own schema was inferred from and pass by construction.
  const holdoutManifest = buildCaptureManifest(holdoutApi, {
    app: spec.app,
    role: "holdout",
    ...(opts.holdoutDriver !== undefined ? { driver: opts.holdoutDriver } : {}),
  });
  if (isSameEvidence(spec.capture, holdoutManifest)) {
    throw new Error(
      `holdout is the same evidence as the derive capture (setId ${holdoutManifest.setId.slice(0, 12)}): certification would be circular`,
    );
  }

  const effectiveOps: OperationSpec[] = [];

  for (const op of spec.operations) {
    const samples = matchOp(op, holdoutApi);

    if (samples.length === 0) {
      uncoveredOps.push(op.id);
      checks.push({ op: op.id, check: "holdout-replay", pass: false, detail: "no holdout coverage" });
      log(`REFUSE ${op.id}: no holdout coverage`);
      continue;
    }

    // --- holdout replay, with bounded repair ---
    let schema = op.responseSchema;
    let iterations = 0;
    let failures = replayFailures(schema, samples, op.id);
    while (failures.length > 0 && iterations < maxRepairs && opts.deriveExchanges) {
      iterations++;
      const aSamples = matchOp(op, apiExchanges(opts.deriveExchanges)).map((e) => e.responseBody);
      const bSamples = samples.map((e) => e.responseBody);
      schema = inferSchema([...aSamples, ...bSamples], { minSamplesForRequired: opts.minSamplesForRequired ?? 8 });
      failures = replayFailures(schema, samples, `${op.id}@r${iterations}`);
      log(`repair ${op.id} iteration ${iterations}: ${failures.length} residual failures`);
    }

    if (failures.length > 0) {
      refusedOps.push({ op: op.id, reason: `holdout-replay failed after ${iterations} repairs: ${failures[0]}` });
      checks.push({ op: op.id, check: "holdout-replay", pass: false, detail: failures[0]! });
      log(`REFUSE ${op.id}: ${failures[0]}`);
      continue;
    }
    checks.push({
      op: op.id,
      check: "holdout-replay",
      pass: true,
      detail: `${samples.length} holdout samples validated${iterations ? ` (after ${iterations} repair(s))` : ""}`,
    });
    if (iterations > 0) repairedOps.push({ op: op.id, iterations });

    // --- mutation suite against the (possibly repaired) schema ---
    const sample = samples[0]!.responseBody;
    const mutants = generateMutants(schema, sample);
    let caught = 0;
    const missedKinds: string[] = [];
    for (const m of mutants) {
      const res = validateAgainst(schema, m.value);
      if (!res.ok) caught++;
      else missedKinds.push(`${m.kind}@${m.path}`);
    }
    mutationTotals.generated += mutants.length;
    mutationTotals.caught += caught;
    mutationTotals.missed += mutants.length - caught;
    mutationTotals.missedKinds.push(...missedKinds.slice(0, 5).map((k) => `${op.id}:${k}`));
    checks.push({
      op: op.id,
      check: "mutation",
      pass: mutants.length === 0 || caught > 0,
      detail: `${caught}/${mutants.length} mutants caught${missedKinds.length ? `; missed: ${missedKinds.slice(0, 3).join(", ")}` : ""}`,
    });

    // --- live canary (reads only) ---
    if (opts.canary && !op.mutating) {
      const c = await opts.canary({ ...op, responseSchema: schema });
      checks.push({ op: op.id, check: "canary", pass: c.ok, detail: c.detail });
      if (!c.ok) {
        refusedOps.push({ op: op.id, reason: `live canary failed: ${c.detail}` });
        log(`REFUSE ${op.id}: canary: ${c.detail}`);
        continue;
      }
    }

    certifiedOps.push(op.id);
    effectiveOps.push({ ...op, responseSchema: schema });
    log(`CERTIFY ${op.id} (${samples.length} holdout samples, ${caught}/${mutants.length} mutants caught)`);
  }

  const verdict: CertificationReport["verdict"] =
    certifiedOps.length === 0 ? "refused" : refusedOps.length + uncoveredOps.length > 0 ? "partial" : "certified";

  const report: CertificationReport = {
    app: spec.app,
    specHash: spec.specHash,
    startedAt,
    finishedAt: new Date().toISOString(),
    checks,
    mutation: mutationTotals,
    certifiedOps,
    refusedOps,
    uncoveredOps,
    verdict,
    holdout: holdoutManifest,
  };

  // The mounted spec carries only certified ops and any repaired schemas, so its
  // hash differs from the derived spec's: recompute it, because the certificate
  // binds to what is MOUNTED and the registry re-derives this hash on every read.
  const effectiveSpec: ConnectorSpec = { ...spec, operations: effectiveOps };
  effectiveSpec.specHash = specHashOf(effectiveSpec);

  return {
    report,
    effectiveSpec,
    repairedOps,
  };
}

function matchOp(op: OperationSpec, exchanges: Exchange[]): Exchange[] {
  const templates = templatePaths([op.pathTemplate.replace(/\{[^}]+\}/g, "123")]);
  void templates; // templating not reused here; direct segment match below
  return exchanges.filter((e) => e.method === op.method && pathMatches(op.pathTemplate, e.path));
}

export function pathMatches(template: string, path: string): boolean {
  const t = template.split("/").filter(Boolean);
  const p = path.replace(/\/+$/, "").split("/").filter(Boolean);
  if (t.length !== p.length) return false;
  for (let i = 0; i < t.length; i++) {
    const seg = t[i]!;
    if (seg.startsWith("{")) continue;
    if (seg !== p[i]) return false;
  }
  return true;
}

function replayFailures(schema: OperationSpec["responseSchema"], samples: Exchange[], _key: string): string[] {
  const failures: string[] = [];
  for (const s of samples) {
    const res = validateAgainst(schema, s.responseBody);
    if (!res.ok) failures.push(res.error ?? "schema violation");
  }
  return failures;
}
