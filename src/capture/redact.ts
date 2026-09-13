/**
 * Secrets never reach fixtures. Redaction is applied at HAR ingest, before any
 * Exchange is written to disk or fed to derivation. Auth material needed at
 * runtime lives separately in connectors/<app>/secrets.json (gitignored),
 * captured once via `toolsmith auth` - never from fixtures.
 */
import type { Exchange } from "../core/types.js";

const SECRET_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-csrf-token",
  "x-xsrf-token",
  "proxy-authorization",
]);

const SECRET_QUERY_PARAMS = [/token/i, /key$/i, /^api_?key/i, /secret/i, /session/i, /auth/i];

export const REDACTED = "TOOLSMITH-REDACTED";

export function redactExchange(ex: Exchange): Exchange {
  const requestHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(ex.requestHeaders)) {
    requestHeaders[k] = SECRET_HEADERS.has(k) ? REDACTED : v;
  }
  const responseHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(ex.responseHeaders)) {
    responseHeaders[k] = SECRET_HEADERS.has(k) ? REDACTED : v;
  }
  const query: Record<string, string> = {};
  for (const [k, v] of Object.entries(ex.query)) {
    query[k] = SECRET_QUERY_PARAMS.some((re) => re.test(k)) ? REDACTED : v;
  }
  return { ...ex, requestHeaders, responseHeaders, query };
}

/** Defense in depth: refuse to persist anything that still smells like a live secret. */
export function assertRedacted(exchanges: Exchange[]): void {
  for (const ex of exchanges) {
    for (const k of Object.keys(ex.requestHeaders)) {
      if (SECRET_HEADERS.has(k) && ex.requestHeaders[k] !== REDACTED) {
        throw new Error(`unredacted secret header "${k}" for ${ex.method} ${ex.path}`);
      }
    }
  }
}
