/**
 * The adapter core: ONE spec-driven executor that every surface (MCP + REST)
 * calls. It is data-driven rather than code-generated on purpose - a generic
 * executor parameterized by the certified spec has no generated-code failure
 * surface to certify, which is itself a reliability property. `emit.ts` can also
 * write a standalone package for the "leaves behind a reusable connector" story,
 * but the running system uses this.
 *
 * Every response is validated with the SAME validator certification used, so a
 * connector cannot return schema-invalid data at runtime without it being caught
 * and counted. If the certified spec declares runtime-checkable semantic
 * invariants, those run after schema validation and fail the call separately,
 * so a schema false green and a semantic false green are never the same number.
 */
import type { AuthScheme, ConnectorSpec, OperationSpec, TraceEvent } from "../core/types.js";
import { validateAgainst } from "../runtime/validate.js";
import { checkResponseInvariants } from "../certify/semantic.js";
import { check, guardedFetcher, PermissionError, type PermissionDecision } from "../runtime/permissions.js";

export interface Secrets {
  bearer?: string;
  apiKey?: string;
  cookie?: string;
}

export interface CallResult {
  ok: boolean;
  outcome: TraceEvent["outcome"];
  status?: number;
  data?: unknown;
  error?: string;
  ms: number;
}

export type Fetcher = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ status: number; json: () => Promise<unknown>; text: () => Promise<string>; headers: { get(n: string): string | null } }>;

export interface AdapterOptions {
  /**
   * Run without the permission guard. Certification and replay use this, because
   * they read from bundled evidence rather than reaching anything. Serving a
   * connector never does.
   */
  unguarded?: boolean;
  /** Notified on every refusal, with the rule that refused and never the value. */
  onDeny?: (d: PermissionDecision) => void;
  secrets?: Secrets;
  fetcher?: Fetcher;
  onTrace?: (t: TraceEvent) => void;
  /** Monotonic clock injection for deterministic tests. */
  now?: () => number;
}

export class Adapter {
  private readonly ops = new Map<string, OperationSpec>();

  constructor(
    private readonly spec: ConnectorSpec,
    private readonly opts: AdapterOptions = {},
  ) {
    for (const op of spec.operations) this.ops.set(op.id, op);
  }

  operations(): OperationSpec[] {
    return [...this.ops.values()];
  }

  async call(opId: string, params: Record<string, unknown> = {}): Promise<CallResult> {
    const clock = this.opts.now ?? (() => performance.now());
    const start = clock();
    const op = this.ops.get(opId);
    if (!op) {
      return this.trace(op, { ok: false, outcome: "refused", error: `unknown operation ${opId}`, ms: 0 });
    }

    // CAPABILITY GATE, before anything is built or sent. A connector with no
    // permission manifest has no capability budget, so it gets none: absent is
    // not permissive.
    const perms = this.spec.permissions;
    if (!this.opts.unguarded) {
      if (!perms) {
        return this.trace(op, { ok: false, outcome: "refused", error: "no permission manifest: this connector has no capability budget", ms: clock() - start });
      }
      const opDecision = check(perms, { kind: "http", op: op.id, method: op.method, url: safeUrl(this.spec.baseUrl, op.pathTemplate) });
      if (!opDecision.allowed) {
        this.opts.onDeny?.(opDecision);
        return this.trace(op, { ok: false, outcome: "refused", error: `permission denied: ${opDecision.reason}`, ms: clock() - start });
      }
    }

    // A missing path parameter is a caller error, not a crash: `call` must never
    // throw, because every caller of it (surfaces, workflows, replay) treats a
    // CallResult as the complete answer and an exception escapes all of that.
    let url: string;
    try {
      url = this.buildUrl(op, params);
    } catch (e) {
      return this.trace(op, { ok: false, outcome: "refused", error: (e as Error).message, ms: clock() - start });
    }
    let headers: Record<string, string>;
    try {
      headers = this.authHeaders();
    } catch (e) {
      if (e instanceof PermissionError) this.opts.onDeny?.(e.decision);
      return this.trace(op, { ok: false, outcome: "refused", error: (e as Error).message, ms: clock() - start });
    }
    const raw = this.opts.fetcher ?? defaultFetcher;
    const fetcher = this.opts.unguarded || !perms ? raw : guardedFetcher(perms, raw, (d) => this.opts.onDeny?.(d));
    let res;
    try {
      res = await fetcher(url, {
        method: op.method,
        headers,
        ...(op.mutating && params["body"] !== undefined ? { body: JSON.stringify(params["body"]) } : {}),
      });
    } catch (e) {
      if (e instanceof PermissionError) {
        return this.trace(op, { ok: false, outcome: "refused", error: e.message, ms: clock() - start });
      }
      return this.trace(op, {
        ok: false,
        outcome: "network-error",
        error: (e as Error).message,
        ms: clock() - start,
      });
    }

    if (res.status < 200 || res.status >= 300) {
      return this.trace(op, {
        ok: false,
        outcome: "http-error",
        status: res.status,
        error: `HTTP ${res.status}`,
        ms: clock() - start,
      });
    }

    const data = await res.json().catch(() => undefined);
    const validation = validateAgainst(op.responseSchema, data, `${this.spec.specHash}:${op.id}`);
    if (!validation.ok) {
      // The runtime gate: schema-invalid data is never returned to the caller.
      return this.trace(op, {
        ok: false,
        outcome: "schema-violation",
        status: res.status,
        error: validation.error ?? "schema violation",
        ms: clock() - start,
      });
    }

    // Semantic gate: shape-valid but meaning-wrong data is refused too, and
    // reported under its own outcome so the two false-green rates stay separate.
    const violations = checkResponseInvariants(this.spec.semanticInvariants, op.id, data);
    if (violations.length > 0) {
      const first = violations[0]!;
      return this.trace(op, {
        ok: false,
        outcome: "semantic-violation",
        status: res.status,
        // id first: attribution must be stable even when the readable label changes
        error: `semantic invariant ${first.id} (${first.label}): ${first.detail}`,
        ms: clock() - start,
      });
    }

    return this.trace(op, { ok: true, outcome: "ok", status: res.status, data, ms: clock() - start });
  }

  private buildUrl(op: OperationSpec, params: Record<string, unknown>): string {
    let path = op.pathTemplate;
    for (const p of op.pathParams) {
      const v = params[p];
      if (v === undefined) throw new Error(`missing path param "${p}" for ${op.id}`);
      path = path.replace(`{${p}}`, encodeURIComponent(String(v)));
    }
    const url = new URL(path, this.spec.baseUrl);
    for (const q of op.queryParams) {
      const v = params[q.name];
      if (v !== undefined) url.searchParams.set(q.name, String(v));
    }
    return url.toString();
  }

  /**
   * Reading a secret is a capability like any other. A connector whose manifest
   * declares no secret - or declares the `public` data class - cannot attach one
   * even if the caller hands it over, which is the case where a read-only public
   * connector quietly starts sending someone's token.
   */
  private authHeaders(): Record<string, string> {
    const s = this.opts.secrets ?? {};
    const headers: Record<string, string> = { accept: "application/json" };
    const auth: AuthScheme = this.spec.auth;
    if (auth.kind === "none") return headers;

    const value = auth.kind === "bearer" ? s.bearer : auth.kind === "header" ? s.apiKey : s.cookie;
    if (value === undefined) return headers;

    if (!this.opts.unguarded) {
      const perms = this.spec.permissions;
      const decision = perms
        ? check(perms, { kind: "secret", secretName: auth.kind })
        : ({ allowed: false, reason: "no permission manifest: no secret may be read" } as PermissionDecision);
      if (!decision.allowed) throw new PermissionError(decision);
    }

    switch (auth.kind) {
      case "bearer":
        headers[auth.header] = value.startsWith("Bearer ") ? value : `Bearer ${value}`;
        break;
      case "header":
        headers[auth.header] = value;
        break;
      case "cookie":
        headers["cookie"] = value;
        break;
    }
    return headers;
  }

  private trace(op: OperationSpec | undefined, r: Omit<CallResult, never>): CallResult {
    this.opts.onTrace?.({
      ts: new Date(0).toISOString(),
      app: this.spec.app,
      op: op?.id ?? "?",
      outcome: r.outcome,
      ...(r.status !== undefined ? { status: r.status } : {}),
      ms: Math.round(r.ms),
      ...(r.error !== undefined ? { detail: r.error } : {}),
    });
    return r;
  }
}

/** Best-effort URL for the pre-flight capability check, before params are bound. */
function safeUrl(baseUrl: string, pathTemplate: string): string {
  try {
    return new URL(pathTemplate.replace(/\{[^}]+\}/g, "_"), baseUrl).toString();
  } catch {
    return `${baseUrl}${pathTemplate}`;
  }
}

const defaultFetcher: Fetcher = async (url, init) => {
  const r = await fetch(url, { method: init.method, headers: init.headers, ...(init.body ? { body: init.body } : {}) });
  return {
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
    headers: { get: (n: string) => r.headers.get(n) },
  };
};
