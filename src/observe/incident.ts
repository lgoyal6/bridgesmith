/**
 * Drift incidents: the moment a certified connector stops being right, captured
 * as the minimum safe evidence needed to replay the failure offline.
 *
 * Two kinds, kept apart on purpose because they are detected differently and
 * mean different things:
 *   - schema drift     the response stopped having the certified SHAPE
 *   - semantic false green   the shape is still perfect and a certified
 *                            invariant stopped holding
 * A system that reports one number for both cannot tell you which one happened,
 * and they have different fixes.
 *
 * An incident bundle is a replay bundle (src/replay/bundle.ts) carrying the
 * failing evidence instead of the certifying evidence, so it verifies and
 * replays through exactly the same gate - including the refusal to bundle
 * anything that still holds a credential.
 */
import { sha256 } from "../core/canon.js";
import type { BirthCertificate, CertificationReport, ConnectorSpec, Exchange } from "../core/types.js";
import type { CallResult } from "../codegen/adapter.js";
import { buildReplayBundle, type ReplayBundle } from "../replay/bundle.js";
import { safeDetail } from "../certify/semantic.js";
import { ATTR, Tracer } from "./trace.js";

export type DriftKind = "schema" | "semantic";

export interface DriftIncident {
  id: string;
  kind: DriftKind;
  app: string;
  op: string;
  certVersion: number;
  specHash: string;
  /** Redacted, clipped reason. Never a response body. */
  detail: string;
  /** Milliseconds from the first failing call to the breaker deciding. */
  detectionMs: number;
  detectedAt: string;
  /** The invariant that stopped holding, for semantic drift. */
  invariantId?: string;
  traceId: string;
}

export function classifyDrift(result: CallResult): DriftKind | null {
  if (result.outcome === "schema-violation") return "schema";
  if (result.outcome === "semantic-violation") return "semantic";
  return null;
}

/** `semantic invariant <id> (<label>): ...` -> `<id>`. */
export function invariantIdFrom(error: string | undefined): string | undefined {
  return /^semantic invariant (\S+) /.exec(error ?? "")?.[1];
}

export interface IncidentBundle {
  incident: DriftIncident;
  bundle: ReplayBundle;
  /** OTLP/JSON for the spans covering detection through replay. */
  otlp: unknown;
}

/**
 * Build the incident. `failing` is the evidence that produced the failure - the
 * smallest set that reproduces it, not the whole session.
 */
export function buildIncident(input: {
  kind: DriftKind;
  app: string;
  op: string;
  spec: ConnectorSpec;
  cert: BirthCertificate;
  report: CertificationReport;
  failing: Exchange[];
  result: CallResult;
  detectionMs: number;
  registryDir: string;
  tracer: Tracer;
  now?: () => Date;
}): IncidentBundle {
  const at = (input.now?.() ?? new Date()).toISOString();
  const detail = safeDetail(input.result.error ?? input.result.outcome);
  const incident: DriftIncident = {
    id: sha256(`${input.app}|${input.op}|${input.kind}|${input.spec.specHash}|${at}`).slice(0, 16),
    kind: input.kind,
    app: input.app,
    op: input.op,
    certVersion: input.cert.version,
    specHash: input.spec.specHash,
    detail,
    detectionMs: input.detectionMs,
    detectedAt: at,
    ...(() => {
      const invariantId = input.kind === "semantic" ? invariantIdFrom(input.result.error) : undefined;
      return invariantId !== undefined ? { invariantId } : {};
    })(),
    traceId: input.tracer.traceId,
  };

  input.tracer.record("runtime.breaker", {
    [ATTR.app]: input.app,
    [ATTR.op]: input.op,
    [ATTR.specHash]: input.spec.specHash,
    [ATTR.certVersion]: input.cert.version,
    [ATTR.driftKind]: input.kind,
    [ATTR.incidentId]: incident.id,
    [ATTR.outcome]: input.result.outcome,
    ...(incident.invariantId ? { [ATTR.invariant]: incident.invariantId } : {}),
    "bridgesmith.detection_ms": input.detectionMs,
  }, { code: "error", message: detail });

  const bundle = buildReplayBundle({
    kind: "drift-incident",
    spec: input.spec,
    cert: input.cert,
    report: input.report,
    exchanges: input.failing,
    registryDir: input.registryDir,
  });

  return { incident, bundle, otlp: input.tracer.toOtlp() };
}
