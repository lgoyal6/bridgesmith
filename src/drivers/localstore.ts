/**
 * Local-store driver (access tier T4): apps with NO network API, whose data
 * lives in a local SQLite file (iMessage, Apple Notes, Safari). The trick that
 * keeps the architecture uniform: a local connector is just a ConnectorSpec with
 * a custom Fetcher. Each operation maps to a parametrized SQL query; the fetcher
 * runs it and returns rows as if they were an HTTP JSON response, so the SAME
 * derive/certify/adapter pipeline applies. Certification for a local store means
 * two independent query slices (A derive, B holdout) of the real DB.
 *
 * Uses the `sqlite3` CLI (present on macOS, and what reads the real chat.db once
 * Full Disk Access is granted) rather than a native module - nothing to compile,
 * nothing to break on stage.
 */
import { execa } from "execa";
import type { Exchange } from "../core/types.js";
import type { Fetcher } from "../codegen/adapter.js";

export interface LocalOp {
  id: string;
  /** Op path used in the synthetic spec, e.g. /recent_messages */
  path: string;
  /** SQL with :param placeholders substituted from query params (numbers/strings only). */
  sql: (params: Record<string, string>) => string;
  /** Query params this op accepts, with defaults used during capture. */
  params: { name: string; default: string }[];
}

export async function runSqliteJson(dbPath: string, sql: string): Promise<unknown[]> {
  const { stdout } = await execa("sqlite3", ["-json", "-readonly", dbPath, sql], { timeout: 15_000 });
  if (!stdout.trim()) return [];
  return JSON.parse(stdout) as unknown[];
}

/** Produce Exchange[] by running each op once with the given param set (one capture slice). */
export async function captureLocal(
  dbPath: string,
  ops: LocalOp[],
  origin: string,
  paramsByOp: Record<string, Record<string, string>> = {},
): Promise<Exchange[]> {
  const out: Exchange[] = [];
  for (const op of ops) {
    const params = paramsByOp[op.id] ?? Object.fromEntries(op.params.map((p) => [p.name, p.default]));
    const rows = await runSqliteJson(dbPath, op.sql(params));
    const url = new URL(op.path, origin);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    out.push({
      method: "GET",
      url: url.toString(),
      path: op.path,
      query: params,
      requestHeaders: { accept: "application/json" },
      status: 200,
      responseHeaders: { "content-type": "application/json" },
      responseBody: { rows },
      responseType: "application/json",
    });
  }
  return out;
}

/** Fetcher that maps adapter calls back to SQL against the local DB. */
export function localFetcher(dbPath: string, ops: LocalOp[]): Fetcher {
  const byPath = new Map(ops.map((o) => [o.path, o]));
  return async (url) => {
    const u = new URL(url);
    const op = byPath.get(u.pathname);
    if (!op) return { status: 404, json: async () => ({}), text: async () => "", headers: { get: () => null } };
    const params: Record<string, string> = {};
    for (const p of op.params) {
      const v = u.searchParams.get(p.name);
      params[p.name] = v ?? p.default;
    }
    try {
      const rows = await runSqliteJson(dbPath, op.sql(params));
      return {
        status: 200,
        json: async () => ({ rows }),
        text: async () => JSON.stringify({ rows }),
        headers: { get: (n: string) => (n.toLowerCase() === "content-type" ? "application/json" : null) },
      };
    } catch (e) {
      return { status: 500, json: async () => ({ error: (e as Error).message }), text: async () => "", headers: { get: () => null } };
    }
  };
}
