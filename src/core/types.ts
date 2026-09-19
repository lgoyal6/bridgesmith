/**
 * Core domain model. Everything downstream of capture speaks these types.
 *
 * Design rule: the LLM (orchestrator) never touches these structures directly;
 * they are produced and consumed by deterministic code. See PLAN.md.
 */

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
  verdict: "certified" | "partial" | "refused";
  /** Provenance of the holdout capture this report was produced against. */
  holdout: CaptureManifest;
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
  /** Hash of the derive manifest embedded in the certified spec. */
  captureManifestHash: string;
  /** Hash of the holdout manifest certification ran against. Distinct by construction. */
  holdoutManifestHash: string;
  issuedAt: string;
  /** ed25519 signature (base64) over the canonicalized certificate sans signature. */
  signature: string;
  publicKey: string;
}

export interface TraceEvent {
  ts: string;
  app: string;
  op: string;
  outcome: "ok" | "schema-violation" | "http-error" | "network-error" | "refused" | "anomaly";
  status?: number;
  ms: number;
  detail?: string;
}
