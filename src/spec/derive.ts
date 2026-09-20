/**
 * Spec derivation: Exchange[] (capture A) -> ConnectorSpec.
 * Deterministic. The holdout capture (B) must never flow through here;
 * certify.ts enforces that separation.
 */
import type { AccessTier, AuthScheme, ConnectorSpec, Exchange, JsonSchema, OperationSpec } from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import { apiExchanges } from "../capture/har.js";
import { inferSchema } from "./infer.js";
import { templatePaths } from "./paths.js";
import { REDACTED } from "../capture/redact.js";
import { buildCaptureManifest } from "../capture/manifest.js";
import { derivePermissions } from "../runtime/permissions.js";

const MIN_SAMPLES_PER_OP = 1;

export interface DeriveOptions {
  app: string;
  tier?: AccessTier;
  /** e.g. "partiful.com": exchanges from other hosts are dropped. */
  host?: string;
  captureLabel: string;
  /** Confidence floor for marking response fields required. See infer.ts. */
  minSamplesForRequired?: number;
  /** Overrides the driver recorded on the exchanges when building the manifest. */
  captureDriver?: string;
  /**
   * Permit mutating operations at runtime. Off by default: a derived connector
   * is read-only until someone decides otherwise, and that decision is recorded
   * in the certified permission manifest rather than assumed.
   */
  allowWrites?: boolean;
  /** Filesystem paths the connector may read (local-store tier). */
  filePaths?: string[];
}

export function deriveSpec(allExchanges: Exchange[], opts: DeriveOptions): ConnectorSpec {
  let exchanges = apiExchanges(allExchanges);
  if (opts.host) exchanges = exchanges.filter((e) => new URL(e.url).hostname.endsWith(opts.host!));
  if (exchanges.length === 0) {
    throw new Error(`no JSON API traffic found in capture "${opts.captureLabel}"${opts.host ? ` for host ${opts.host}` : ""}`);
  }

  const baseUrl = dominantOrigin(exchanges);
  const inScope = exchanges.filter((e) => e.url.startsWith(baseUrl));
  const templates = templatePaths(inScope.map((e) => e.path));

  // Group exchanges by (method, template).
  const groups = new Map<string, { method: string; template: string; params: string[]; members: Exchange[] }>();
  for (const ex of inScope) {
    for (const t of templates.values()) {
      const m = t.match(ex.path);
      if (m) {
        const key = `${ex.method} ${t.template}`;
        const g = groups.get(key) ?? { method: ex.method, template: t.template, params: t.params, members: [] };
        g.members.push(ex);
        groups.set(key, g);
        break;
      }
    }
  }

  const inferOpts = { minSamplesForRequired: opts.minSamplesForRequired ?? 8 };
  const operations: OperationSpec[] = [];
  for (const g of groups.values()) {
    if (g.members.length < MIN_SAMPLES_PER_OP) continue;
    const responseSchema = inferSchema(g.members.map((m) => m.responseBody), inferOpts);
    const mutating = !["GET", "HEAD"].includes(g.method);
    const bodySamples = g.members.map((m) => m.requestBody).filter((b) => b !== undefined);
    const requestBodySchema: JsonSchema | undefined = bodySamples.length > 0 ? inferSchema(bodySamples, inferOpts) : undefined;

    const queryNames = new Map<string, { count: number; example?: string }>();
    for (const m of g.members) {
      for (const [k, v] of Object.entries(m.query)) {
        const entry = queryNames.get(k) ?? { count: 0 };
        entry.count++;
        if (entry.example === undefined && v !== REDACTED) entry.example = v;
        queryNames.set(k, entry);
      }
    }

    operations.push({
      id: opId(g.method, g.template),
      method: g.method,
      pathTemplate: g.template,
      pathParams: g.params,
      queryParams: [...queryNames.entries()].map(([name, info]) => ({
        name,
        required: info.count === g.members.length,
        ...(info.example !== undefined ? { example: info.example } : {}),
      })),
      ...(requestBodySchema !== undefined ? { requestBodySchema } : {}),
      responseSchema,
      samples: g.members.length,
      mutating,
    });
  }

  operations.sort((a, b) => a.id.localeCompare(b.id));

  const spec: Omit<ConnectorSpec, "specHash"> = {
    app: opts.app,
    baseUrl,
    tier: opts.tier ?? "derived-api",
    auth: detectAuth(inScope),
    operations,
    derivedAt: new Date().toISOString(),
    derivedFrom: opts.captureLabel,
    // Provenance covers the IN-SCOPE exchanges the operations were inferred from,
    // not the raw capture: filtered-out assets and 4xx noise are not evidence.
    capture: buildCaptureManifest(inScope, {
      app: opts.app,
      role: "derive",
      ...(opts.captureDriver !== undefined ? { driver: opts.captureDriver } : {}),
    }),
  };
  // Least privilege, derived from what the spec actually contains. Every spec
  // carries a capability budget for the same reason every spec carries
  // provenance: a connector with no manifest would otherwise be a connector the
  // runtime has no basis to refuse.
  const withPerms: Omit<ConnectorSpec, "specHash"> = {
    ...spec,
    permissions: derivePermissions({ ...spec, specHash: "" } as ConnectorSpec, {
      ...(opts.allowWrites !== undefined ? { allowWrites: opts.allowWrites } : {}),
      ...(opts.filePaths !== undefined ? { filePaths: opts.filePaths } : {}),
    }),
  };
  return { ...withPerms, specHash: specHashOf(withPerms) };
}

/**
 * Content hash of a spec: everything except the two wall-clock timestamps and
 * the hash field itself. Stable across re-derivations of the same traffic, and
 * what a birth certificate binds to, so the registry can recompute it from
 * spec.json.
 *
 * `capture.capturedAt` is excluded for the same reason as `derivedAt` - two runs
 * over identical evidence must agree - but it is NOT unbound: the certificate
 * signs `manifestHash(spec.capture)`, which covers the timestamp, and the
 * registry checks that too (see Registry.load).
 */
export function specHashOf(spec: Omit<ConnectorSpec, "specHash"> | ConnectorSpec): string {
  const capture = spec.capture ? { ...spec.capture, capturedAt: undefined } : undefined;
  return sha256(canonicalJson({ ...spec, derivedAt: undefined, specHash: undefined, capture }));
}

function dominantOrigin(exchanges: Exchange[]): string {
  const counts = new Map<string, number>();
  for (const e of exchanges) {
    const origin = new URL(e.url).origin;
    counts.set(origin, (counts.get(origin) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]![0];
}

function detectAuth(exchanges: Exchange[]): AuthScheme {
  const sample = exchanges.slice(0, 50);
  if (sample.some((e) => "authorization" in e.requestHeaders)) return { kind: "bearer", header: "authorization" };
  const apiKeyHeader = ["x-api-key", "x-auth-token"].find((h) => sample.some((e) => h in e.requestHeaders));
  if (apiKeyHeader) return { kind: "header", header: apiKeyHeader };
  if (sample.some((e) => "cookie" in e.requestHeaders)) return { kind: "cookie", cookieNames: [] };
  return { kind: "none" };
}

export function opId(method: string, template: string): string {
  const slug = template
    .replace(/[{}]/g, "")
    .split("/")
    .filter(Boolean)
    .join("_")
    .replace(/[^a-zA-Z0-9_]+/g, "_");
  return `${method.toLowerCase()}_${slug}`.slice(0, 64);
}
