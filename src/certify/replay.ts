/**
 * Replay fetcher: serves recorded Exchanges through the same `Fetcher` interface
 * the live adapter uses, so a workflow can be certified against holdout evidence
 * with no network and no third-party writes.
 *
 * It also counts invocations per (method, path), which is what makes a duplicated
 * non-idempotent effect observable rather than theoretical.
 */
import type { Exchange } from "../core/types.js";
import type { Fetcher } from "../codegen/adapter.js";

export interface ReplayLog {
  /** Every call in order, as `METHOD /path`. */
  calls: string[];
  /** Invocation count per `METHOD /path`. */
  counts: Map<string, string[]>;
}

export interface ReplayOptions {
  /** Force the Nth call (0-based) to this `METHOD /path` to fail with this status. */
  failOnce?: { key: string; status: number };
}

function key(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

/** Match on method + path + query, falling back to method + path. */
function find(exchanges: Exchange[], method: string, url: URL): Exchange | undefined {
  const q = url.searchParams.toString();
  const byPath = exchanges.filter((e) => e.method === method.toUpperCase() && e.path === url.pathname);
  return byPath.find((e) => new URL(e.url).searchParams.toString() === q) ?? byPath[0];
}

export function replayFetcher(exchanges: Exchange[], opts: ReplayOptions = {}): { fetcher: Fetcher; log: ReplayLog } {
  const log: ReplayLog = { calls: [], counts: new Map() };
  let failed = false;
  const fetcher: Fetcher = async (url, init) => {
    const u = new URL(url);
    const k = key(init.method, u.pathname);
    log.calls.push(k);
    const seen = log.counts.get(k) ?? [];
    seen.push(u.search);
    log.counts.set(k, seen);

    if (opts.failOnce && opts.failOnce.key === k && !failed) {
      failed = true;
      const status = opts.failOnce.status;
      return { status, json: async () => ({}), text: async () => "", headers: { get: () => null } };
    }
    const ex = find(exchanges, init.method, u);
    if (!ex) return { status: 404, json: async () => ({}), text: async () => "", headers: { get: () => null } };
    return {
      status: ex.status,
      json: async () => ex.responseBody,
      text: async () => JSON.stringify(ex.responseBody ?? null),
      headers: { get: (n: string) => ex.responseHeaders[n.toLowerCase()] ?? null },
    };
  };
  return { fetcher, log };
}

export function invocationCount(log: ReplayLog, method: string, path: string): number {
  return log.counts.get(key(method, path))?.length ?? 0;
}
