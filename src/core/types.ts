/**
 * Core domain model. Everything downstream of capture speaks these types.
 *
 * Design rule: the LLM (orchestrator) never touches these structures directly;
 * they are produced and consumed by deterministic code. See PLAN.md.
 */

import type { PermissionManifest } from "../runtime/permissions.js";

export type AccessTier =
  | "official-api" // T1: documented public API
  | "derived-api" // T2: spec reverse-engineered from the app's own traffic
  | "browser-bridge" // T3: UI automation (stub in v0)
  | "local-store"; // T4: desktop app's local datastore

/** A single HTTP exchange, normalized from HAR. Auth material is redacted at ingest. */
export interface Exchange {
  method: string;
  /** Full URL as observed. */
  url: string;
  /** Path portion only, e.g. /api/v2/events/123 */
  path: string;
  query: Record<string, string>;
  requestHeaders: Record<string, string>;
  requestBody?: unknown;
  status: number;
  responseHeaders: Record<string, string>;
  /** Parsed JSON body; undefined when non-JSON or empty. */
  responseBody?: unknown;
  /** Content-Type of the response. */
  responseType?: string;
  startedAt?: string;
  /** Capture driver that recorded this exchange, e.g. "har-ingest/0.1.0". Provenance. */
  capturedBy?: string;
}

/**
 * Provenance for one capture set: what evidence a certification actually ran
 * against. Built by src/capture/manifest.ts. The derive manifest is embedded in
 * the spec (so specHash covers it); both manifest hashes are signed into the
 * birth certificate.
 */
export interface CaptureManifest {
  app: string;
  role: "derive" | "holdout";
  /** Every origin seen in the set, sorted. */
  targetOrigins: string[];
  /** Driver that recorded the set, or "mixed(a+b)" when they disagree. */
  driver: string;
  capturedAt: string;
  /** Redacted exchanges in the set. */
  exchangeCount: number;
  /** Per-exchange request and response body hashes, in capture order. */
  bodies: { method: string; path: string; status: number; request: string; response: string }[];
  /** Identity of the EVIDENCE (hash over `bodies`, excluding the timestamp). */
  setId: string;
  secretScan: { clean: boolean; findings: string[] };
  toolchain: { node: string; bridgesmith: string };
}

/** JSON Schema subset we infer. Kept plain-object so it serializes into OpenAPI. */
export type JsonSchema = {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  nullable?: boolean;
  format?: string;
  additionalProperties?: boolean | JsonSchema;
  description?: string;
};

/** One templated operation discovered in traffic, e.g. GET /api/events/{id}. */
export interface OperationSpec {
  /** Stable id, e.g. get_api_events_by_id */
  id: string;
  method: string;
  /** Path template with {param} segments. */
  pathTemplate: string;
  /** Names of path parameters in order. */
  pathParams: string[];
  /** Query params observed, with whether they appeared in every sample. */
  queryParams: { name: string; required: boolean; example?: string }[];
  requestBodySchema?: JsonSchema;
  responseSchema: JsonSchema;
  /** Sample count this op was inferred from (capture A). */
  samples: number;
  /** True when the op performs a write (non-GET/HEAD). Writes are never canaried live. */
  mutating: boolean;
  description?: string;
}

/**
 * Whether an operation's effect can safely happen twice. Drives the retry
 * policy during workflow certification: non-idempotent steps are never retried.
 */
export type IdempotencyClass = "read-only" | "idempotent" | "non-idempotent";

/**
 * An opt-in assertion about MEANING, checked on data that already passed schema
 * validation. These are narrow, named properties - not a claim that a connector
 * is semantically correct in general, which is not something this system can
 * decide. Each kind exists because it is a real way an API lies while returning
 * perfectly well-typed JSON.
 *
 * Every invariant carries a STABLE id chosen by the author. The id, not the
 * invariant's contents, is what the certificate binds to, so an invariant can be
 * tightened without the registry mistaking it for a different one - and cannot
 * be dropped without the certificate noticing.
 */
export interface InvariantMeta {
  /** Stable, author-assigned identity. Never derived from the contents. */
  id: string;
  /**
   * blocking: a failure refuses the connector.
   * advisory: a failure is reported and the invariant is not mounted, but the
   * connector may still be served. Advisory is never a way to claim coverage -
   * a failing invariant is never listed as certified at either severity.
   */
  severity: "blocking" | "advisory";
  description?: string;
}

export type SemanticInvariant = InvariantMeta &
  (
    /** The same entity returned by two endpoints must agree on these fields. */
    | { kind: "id-agreement"; idField: string; fields: string[]; sources: { op: string; path: string }[] }
    /** A field is ordered within each returned collection (timestamps, sequence numbers). */
    | { kind: "monotonic"; op: string; path: string; field: string; direction: "increasing" | "decreasing" }
    /** Pages of one endpoint union cleanly: no id in two pages, and no gap against the reported total. */
    | { kind: "pagination-union"; op: string; path: string; idField: string; totalPath?: string }
    /** The collection a response returns has as many items as the response says it does. */
    | { kind: "total-matches"; op: string; path: string; totalPath: string }
    /** A field uses one vocabulary everywhere it appears. */
    | { kind: "enum-consistency"; field: string; allowed: string[]; sources: { op: string; path: string }[] }
    /** A numeric field is in the same unit everywhere (seconds vs milliseconds, cents vs dollars). */
    | { kind: "unit-consistency"; field: string; maxRatio: number; sources: { op: string; path: string }[] }
  );

/**
 * The deterministic record of evaluating one invariant. Two runs over the same
 * evidence produce an identical record, `evidenceHash` included, which is what
 * lets the certificate bind to WHAT was checked and not merely that something was.
 */
export interface SemanticCheck {
  id: string;
  kind: SemanticInvariant["kind"];
  severity: InvariantMeta["severity"];
  /** Human-readable identity, derived from the contents. For reports and logs. */
  label: string;
  /** Operations whose responses this invariant reads. */
  scope: string[];
  /** Which body of evidence it was evaluated over. Certification only ever uses the holdout. */
  evidenceSource: "holdout";
  /** Hash of the exact responses inspected. Stable across runs over the same evidence. */
  evidenceHash: string;
  pass: boolean;
  detail?: string;
  /** Number of values the invariant actually inspected. Zero means it never ran. */
  samples: number;
}

/** A declarative assertion over one step's (already schema-valid) response. */
export type Postcondition =
  /** `path` resolves to something present and non-empty. */
  | { kind: "non-empty"; path: string }
  /** `path` equals a value a previous step extracted into workflow state. */
  | { kind: "equals-state"; path: string; state: string }
  /** the array at `path` has exactly as many items as the count at `totalPath`. */
  | { kind: "count-matches"; path: string; totalPath: string };

/** One ordered step of a workflow. Data, not code: it lives in the spec. */
export interface WorkflowStep {
  id: string;
  /** Certified operation this step invokes. */
  op: string;
  /** State keys that must be bound (and fresh) before this step may run. */
  requires?: string[];
  /** Operation params taken from workflow state: param name -> state key. */
  params?: Record<string, string>;
  /** Operation params with literal values. */
  constParams?: Record<string, unknown>;
  /** State this step produces: state key -> path into the response. */
  extract?: Record<string, string>;
  /** State keys this step makes stale; later reuse is a certification failure. */
  invalidates?: string[];
  postconditions?: Postcondition[];
  /**
   * State keys whose newly extracted value must DIFFER from the value they held
   * before this step. This is what makes a cursor a cursor: a paginating step
   * whose cursor does not move is not making progress, it is looping.
   */
  mustAdvance?: string[];
  /**
   * Re-run this step while the named state key holds a truthy value, up to
   * `maxIterations`. Exhausting the budget is a failure, never a silent stop:
   * a pagination loop that never terminates must be loud.
   */
  repeat?: { whileState: string; maxIterations: number };
  /**
   * Scopes this step needs. Checked immediately BEFORE the step runs, every
   * time it runs, including on each repeat iteration - authorization granted at
   * step 1 is not authorization for step 5.
   */
  requiresAuth?: string[];
  /**
   * Whether this step has an effect worth re-authorizing. Defaults to true for
   * mutating operations; set explicitly to mark a read consequential.
   */
  consequential?: boolean;
  idempotency: IdempotencyClass;
  /** Run in reverse step order after the workflow; failure fails the workflow. */
  cleanup?: { op: string; params?: Record<string, string>; constParams?: Record<string, unknown> };
}

export interface WorkflowSpec {
  id: string;
  description?: string;
  steps: WorkflowStep[];
}

export type AuthScheme =
  | { kind: "none" }
  | { kind: "bearer"; header: string }
  | { kind: "cookie"; cookieNames: string[] }
  | { kind: "header"; header: string };

export interface ConnectorSpec {
  app: string;
  baseUrl: string;
  tier: AccessTier;
  auth: AuthScheme;
  operations: OperationSpec[];
  /** sha256 of the canonicalized spec JSON (excluding this field). */
  specHash: string;
  derivedAt: string;
  /** Capture session the spec was derived from (never the holdout). */
  derivedFrom: string;
  /** Provenance of the derive capture. Covered by specHash. */
  capture: CaptureManifest;
  /** Multi-step workflows offered by this connector. Covered by specHash. */
  workflows?: WorkflowSpec[];
  /** Opt-in semantic invariants. Covered by specHash. Empty means shape-only. */
  semanticInvariants?: SemanticInvariant[];
  /**
   * Capability manifest this connector runs under. Covered by specHash, and its
   * hash is signed into the certificate, so a connector cannot widen its own
   * permissions without re-certification. Absent means the connector has not
   * been given a capability budget and the runtime refuses every call.
   */
  permissions?: PermissionManifest;
}

/** Result of one certification check for one operation. */
export interface OpCheck {
  op: string;
  check: "holdout-replay" | "mutation" | "canary" | "fuzz";
  pass: boolean;
  detail: string;
}

export interface MutationStats {
  generated: number;
  /** Mutants the schema correctly rejected. */
  caught: number;
  /** Mutants that passed validation: schema too loose. */
  missed: number;
  missedKinds: string[];
}

export interface CertificationReport {
  app: string;
  specHash: string;
  startedAt: string;
  finishedAt: string;
  checks: OpCheck[];
  mutation: MutationStats;
  /** Ops that passed every applicable check. Only these are mounted. */
  certifiedOps: string[];
  /** Ops refused, with the failing check named. */
  refusedOps: { op: string; reason: string }[];
  /** Ops with no holdout coverage: refused by policy (never mount unexercised ops). */
  uncoveredOps: string[];
  /**
   * Three DISTINCT verdicts. A response can be well-typed and still mean the
   * wrong thing, so collapsing these into one number is exactly the mistake the
   * semantic layer exists to prevent.
   *   schemaVerdict   - per-operation shape certification (holdout replay + mutation)
   *   semanticVerdict - declared invariants over the holdout; "not-declared" when
   *                     the connector declares none, which is NOT the same as passing
   *   verdict         - the mount decision, never better than its inputs
   */
  schemaVerdict: "certified" | "partial" | "refused";
  semanticVerdict: "certified" | "partial" | "refused" | "not-declared";
  verdict: "certified" | "partial" | "refused";
  /** Provenance of the holdout capture this report was produced against. */
  holdout: CaptureManifest;
  /** Per-workflow certification outcomes. Only passing workflows are mounted. */
  workflows: { id: string; pass: boolean; failure?: string; detail?: string }[];
  /** Per-invariant semantic outcomes. Empty when the connector declares none. */
  semantic: SemanticCheck[];
}

/** The signed artifact. Verifiable with the registry public key. */
export interface BirthCertificate {
  app: string;
  version: number;
  tier: AccessTier;
  specHash: string;
  certifiedOps: string[];
  refusedOps: { op: string; reason: string }[];
  mutationStats: MutationStats;
  /** Workflows that passed workflow certification. Only these are mounted. */
  certifiedWorkflows: string[];
  /**
   * Semantic invariants that held over the holdout, by stable id plus the hash of
   * the evidence each was checked against. The registry requires the mounted spec
   * to declare exactly this set, so a connector cannot drop an invariant to make
   * itself pass, and cannot claim one it never ran.
   */
  certifiedInvariants: { id: string; evidenceHash: string }[];
  /** Hash of the certified permission manifest, or null when none was declared. */
  permissionsHash: string | null;
  /** Hash of the derive manifest embedded in the certified spec. */
  captureManifestHash: string;
  /** Hash of the holdout manifest certification ran against. Distinct by construction. */
  holdoutManifestHash: string;
  issuedAt: string;
  /**
   * The version this one supersedes, or null for the first. Signed, so lineage
   * cannot be rewritten after the fact to make a breaking change look like a
   * fresh start.
   */
  predecessor: { version: number; specHash: string } | null;
  /**
   * Declared compatibility with `predecessor`, from src/registry/compat.ts.
   * "initial" for a first version. Signed, so a breaking promotion cannot be
   * relabelled additive afterwards.
   */
  compat: string;
  /**
   * Identity of the executor configuration that will serve this version. The
   * adapter is data-driven rather than code-generated (src/codegen/adapter.ts),
   * so this is the hash of what parameterizes it - the certified operations plus
   * the runtime version - not a hash of emitted source. Named honestly for that
   * reason: it changes when behaviour changes, including on a runtime upgrade.
   */
  adapterHash: string;
  /** ed25519 signature (base64) over the canonicalized certificate sans signature. */
  signature: string;
  publicKey: string;
}

export interface TraceEvent {
  ts: string;
  app: string;
  op: string;
  outcome: "ok" | "schema-violation" | "semantic-violation" | "http-error" | "network-error" | "refused" | "anomaly";
  status?: number;
  ms: number;
  detail?: string;
}
