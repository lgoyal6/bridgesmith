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
 * and counted.
 */
import type { AuthScheme, ConnectorSpec, OperationSpec, TraceEvent } from "../core/types.js";
import { validateAgainst } from "../runtime/validate.js";

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

    const url = this.buildUrl(op, params);
    const headers = this.authHeaders();
    const fetcher = this.opts.fetcher ?? defaultFetcher;
    let res;
    try {
      res = await fetcher(url, {
        method: op.method,
        headers,
        ...(op.mutating && params["body"] !== undefined ? { body: JSON.stringify(params["body"]) } : {}),
      });
    } catch (e) {
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

  private authHeaders(): Record<string, string> {
    const s = this.opts.secrets ?? {};
    const headers: Record<string, string> = { accept: "application/json" };
    const auth: AuthScheme = this.spec.auth;
    switch (auth.kind) {
      case "bearer":
        if (s.bearer) headers[auth.header] = s.bearer.startsWith("Bearer ") ? s.bearer : `Bearer ${s.bearer}`;
        break;
      case "header":
        if (s.apiKey) headers[auth.header] = s.apiKey;
        break;
      case "cookie":
        if (s.cookie) headers["cookie"] = s.cookie;
        break;
      case "none":
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

const defaultFetcher: Fetcher = async (url, init) => {
  const r = await fetch(url, { method: init.method, headers: init.headers, ...(init.body ? { body: init.body } : {}) });
  return {
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
    headers: { get: (n: string) => r.headers.get(n) },
  };
};
