/**
 * HAR is the universal capture format: every access driver (mitmproxy, browser
 * devtools, agent-browser) produces a HAR; everything downstream consumes
 * Exchange[]. Redaction happens HERE, at ingest: fixtures on disk never contain
 * live credentials (see redact.ts).
 */
import { readFileSync } from "node:fs";
import type { Exchange } from "../core/types.js";
import { redactExchange } from "./redact.js";
import { BRIDGESMITH_VERSION } from "../core/version.js";

interface HarEntry {
  startedDateTime?: string;
  request: {
    method: string;
    url: string;
    headers: { name: string; value: string }[];
    queryString?: { name: string; value: string }[];
    postData?: { mimeType?: string; text?: string };
  };
  response: {
    status: number;
    headers: { name: string; value: string }[];
    content?: { mimeType?: string; text?: string; encoding?: string };
  };
}

function headerMap(headers: { name: string; value: string }[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of headers) out[h.name.toLowerCase()] = h.value;
  return out;
}

function tryJson(text: string | undefined, encoding?: string): unknown {
  if (!text) return undefined;
  const raw = encoding === "base64" ? Buffer.from(text, "base64").toString("utf8") : text;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

export function loadHar(path: string, opts: { hostFilter?: string } = {}): Exchange[] {
  const har = JSON.parse(readFileSync(path, "utf8"));
  const entries: HarEntry[] = har?.log?.entries ?? [];
  const out: Exchange[] = [];
  for (const e of entries) {
    let u: URL;
    try {
      u = new URL(e.request.url);
    } catch {
      continue;
    }
    if (opts.hostFilter && !u.hostname.endsWith(opts.hostFilter)) continue;
    const respType = headerMap(e.response.headers)["content-type"] ?? e.response.content?.mimeType;
    const ex: Exchange = {
      method: e.request.method.toUpperCase(),
      url: e.request.url,
      path: u.pathname,
      query: Object.fromEntries(u.searchParams.entries()),
      requestHeaders: headerMap(e.request.headers),
      requestBody: tryJson(e.request.postData?.text),
      status: e.response.status,
      responseHeaders: headerMap(e.response.headers),
      responseBody: tryJson(e.response.content?.text, e.response.content?.encoding),
      ...(respType !== undefined ? { responseType: respType } : {}),
      ...(e.startedDateTime !== undefined ? { startedAt: e.startedDateTime } : {}),
      capturedBy: `har-ingest/${BRIDGESMITH_VERSION}`,
    };
    out.push(redactExchange(ex));
  }
  return out;
}

/** Keep only JSON API traffic: the raw page/asset noise never reaches spec derivation. */
export function apiExchanges(exchanges: Exchange[]): Exchange[] {
  return exchanges.filter(
    (e) =>
      e.responseBody !== undefined &&
      (e.responseType ?? "").includes("json") &&
      e.status >= 200 &&
      e.status < 300,
  );
}
