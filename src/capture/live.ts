/**
 * Live capture: fetch a set of real URLs and record them as Exchange[] (the same
 * shape loadHar produces), so a real app's traffic flows through the identical
 * derive/certify pipeline the fixtures use. Reads only; redaction still applies.
 *
 * This is the "capture" driver for endpoints we can reach directly. The mitmproxy
 * driver (for browser sessions) produces a HAR that loadHar() ingests instead;
 * both converge on Exchange[].
 */
import type { Exchange } from "../core/types.js";
import { redactExchange } from "./redact.js";

export async function captureUrls(urls: string[], opts: { headers?: Record<string, string>; delayMs?: number } = {}): Promise<Exchange[]> {
  const out: Exchange[] = [];
  for (const raw of urls) {
    const u = new URL(raw);
    const res = await fetch(raw, {
      headers: { accept: "application/json", "user-agent": "bridgesmith-capture/0.1", ...(opts.headers ?? {}) },
    });
    const text = await res.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    const responseHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => (responseHeaders[k] = v));
    out.push(
      redactExchange({
        method: "GET",
        url: raw,
        path: u.pathname,
        query: Object.fromEntries(u.searchParams.entries()),
        requestHeaders: { accept: "application/json" },
        status: res.status,
        responseHeaders,
        ...(body !== undefined ? { responseBody: body } : {}),
        ...(res.headers.get("content-type") ? { responseType: res.headers.get("content-type")! } : {}),
      }),
    );
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
  }
  return out;
}
