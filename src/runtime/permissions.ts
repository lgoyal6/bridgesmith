/**
 * Connector permissions: an explicit, certified capability manifest, enforced at
 * the point where a connector can actually reach the outside world.
 *
 * WHY NOT A CODE SANDBOX (WASI, isolated-vm, a subprocess jail)
 * -------------------------------------------------------------
 * Those isolate untrusted CODE. Bridgesmith does not generate code: the adapter
 * is one hand-written, spec-driven executor (`src/codegen/adapter.ts`), and a
 * connector is DATA. Putting that executor in a WASI sandbox would isolate the
 * one component nobody needs protecting from, while the real capability - "which
 * origins, methods, paths, files and secrets may this spec reach" - would still
 * be decided by the spec on the other side of the boundary. A WASI module still
 * needs its host imports whitelisted, and that whitelist is exactly the manifest
 * below; the module boundary would add process cost and a second thing to keep
 * in sync without moving the decision.
 *
 * So the isolation layer here is capability mediation at egress, not code
 * confinement: nothing reaches the network or the filesystem except through a
 * guard that consults a certified manifest. This is the honest scope. If
 * Bridgesmith ever emits executable connector code (`emit.ts` writing a runnable
 * package is the obvious path), that code WOULD need real confinement, and WASI
 * becomes the right answer at that point - with this manifest as its import
 * whitelist rather than a replacement for it.
 *
 * Defaults are deny and read-only. A permission that is not written down does
 * not exist.
 */
import type { ConnectorSpec, OperationSpec } from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import type { Fetcher } from "../codegen/adapter.js";

export interface PermissionManifest {
  /** Operation ids this connector may invoke. Anything else is refused. */
  operations: string[];
  /** Origins it may reach, exactly. No wildcards, no suffix matching. */
  origins: string[];
  /** HTTP methods it may use. */
  methods: string[];
  /** Path templates it may request, as they appear in the spec. */
  pathTemplates: string[];
  /**
   * What kind of data this connector handles. `public` additionally forbids any
   * secret at all, which is the one data-class rule that can be mechanically
   * enforced rather than merely recorded.
   */
  dataClasses: ("public" | "user-private" | "credentialed")[];
  /** Named secrets it may read. Empty means it may read none. */
  secretNames: string[];
  /** Filesystem paths it may read (local-store tier). Empty means none. */
  filePaths: string[];
  /** Whether any mutating operation may run at all. Default false. */
  allowWrites: boolean;
  /** Redirect hops permitted, and only ever to an allowed origin. */
  maxRedirects: number;
}

export interface PermissionDecision {
  allowed: boolean;
  /** Names the rule that refused, never the value that tripped it. */
  reason?: string;
}

export interface CapabilityRequest {
  kind: "http" | "file" | "secret";
  op?: string;
  method?: string;
  url?: string;
  path?: string;
  secretName?: string;
}

/**
 * The least privilege that still lets a certified spec do its job. Writes are
 * off unless the spec actually certified a mutating operation, and even then the
 * caller must opt in: a generated default that quietly permits writes is not a
 * default, it is a loophole.
 */
export function derivePermissions(spec: ConnectorSpec, opts: { allowWrites?: boolean; secretNames?: string[]; filePaths?: string[] } = {}): PermissionManifest {
  const ops = spec.operations;
  const origin = (() => {
    try {
      return new URL(spec.baseUrl).origin;
    } catch {
      return spec.baseUrl;
    }
  })();
  const hasWrites = ops.some((o: OperationSpec) => o.mutating);
  const secretNames = opts.secretNames ?? (spec.auth.kind === "none" ? [] : [spec.auth.kind]);
  return {
    operations: ops.map((o) => o.id).sort(),
    origins: [origin],
    methods: [...new Set(ops.map((o) => o.method))].sort(),
    pathTemplates: [...new Set(ops.map((o) => o.pathTemplate))].sort(),
    dataClasses: secretNames.length ? ["credentialed"] : ["public"],
    secretNames: secretNames.sort(),
    filePaths: (opts.filePaths ?? []).sort(),
    allowWrites: Boolean(opts.allowWrites) && hasWrites,
    maxRedirects: 0,
  };
}

export function permissionsHashOf(m: PermissionManifest): string {
  return sha256(canonicalJson(m));
}

/** Does `template` (with {param} segments) describe `path`? */
function templateMatches(template: string, path: string): boolean {
  const t = template.split("/").filter(Boolean);
  const p = path.replace(/\/+$/, "").split("/").filter(Boolean);
  if (t.length !== p.length) return false;
  return t.every((seg, i) => seg.startsWith("{") || seg === p[i]);
}

/**
 * The single decision point. Every refusal names the rule, never the value, so a
 * denial can be logged and attributed without becoming a disclosure.
 */
export function check(m: PermissionManifest, req: CapabilityRequest): PermissionDecision {
  switch (req.kind) {
    case "secret": {
      if (m.dataClasses.includes("public") && !m.dataClasses.includes("credentialed")) {
        return { allowed: false, reason: `data class "public" forbids reading any secret` };
      }
      if (!req.secretName || !m.secretNames.includes(req.secretName)) {
        return { allowed: false, reason: `secret "${req.secretName ?? "(unnamed)"}" is outside the declared secret scope` };
      }
      return { allowed: true };
    }
    case "file": {
      if (!req.path) return { allowed: false, reason: "file access with no path" };
      const ok = m.filePaths.some((p) => req.path === p || req.path!.startsWith(p.endsWith("/") ? p : `${p}/`));
      return ok ? { allowed: true } : { allowed: false, reason: `path is outside the declared filesystem scope` };
    }
    case "http": {
      if (req.op && !m.operations.includes(req.op)) return { allowed: false, reason: `operation "${req.op}" is not in the permission manifest` };
      const method = (req.method ?? "GET").toUpperCase();
      if (!m.methods.includes(method)) return { allowed: false, reason: `method ${method} is not permitted` };
      if (!m.allowWrites && !["GET", "HEAD", "OPTIONS"].includes(method)) {
        return { allowed: false, reason: `connector is read-only: ${method} is refused` };
      }
      let u: URL;
      try {
        u = new URL(req.url ?? "");
      } catch {
        return { allowed: false, reason: "unparseable request URL" };
      }
      if (!m.origins.includes(u.origin)) return { allowed: false, reason: `origin ${u.origin} is not a permitted destination` };
      if (!m.pathTemplates.some((t) => templateMatches(t, u.pathname))) {
        return { allowed: false, reason: `path ${u.pathname} matches no permitted path template` };
      }
      return { allowed: true };
    }
  }
}

export class PermissionError extends Error {
  constructor(public readonly decision: PermissionDecision) {
    super(`permission denied: ${decision.reason}`);
    this.name = "PermissionError";
  }
}

/**
 * Wrap a Fetcher so nothing leaves without a decision.
 *
 * Redirects are followed MANUALLY and re-checked at every hop. A redirect is the
 * classic way an allowed origin becomes a disallowed one: the first request is
 * fine, the 302 is where the data actually goes. `maxRedirects` defaults to 0,
 * so by default a redirect is simply refused.
 */
export function guardedFetcher(
  m: PermissionManifest,
  inner: Fetcher,
  onDeny?: (d: PermissionDecision, req: CapabilityRequest) => void,
): Fetcher {
  return async (url, init) => {
    let current = url;
    for (let hop = 0; ; hop++) {
      const req: CapabilityRequest = { kind: "http", method: init.method, url: current };
      const decision = check(m, req);
      if (!decision.allowed) {
        onDeny?.(decision, req);
        throw new PermissionError(decision);
      }
      const res = await inner(current, init);
      if (res.status < 300 || res.status >= 400) return res;

      const location = res.headers.get("location");
      if (!location) return res;
      if (hop >= m.maxRedirects) {
        const d: PermissionDecision = { allowed: false, reason: `redirect refused: ${hop + 1} hop(s) exceeds the permitted ${m.maxRedirects}` };
        onDeny?.(d, req);
        throw new PermissionError(d);
      }
      current = new URL(location, current).toString();
      // loop re-checks `current` against the manifest before following it
    }
  };
}

/** A Fetcher over the real network that does NOT follow redirects, so the guard can see them. */
export const manualRedirectFetcher: Fetcher = async (url, init) => {
  const r = await fetch(url, { method: init.method, headers: init.headers, redirect: "manual", ...(init.body ? { body: init.body } : {}) });
  return {
    status: r.status,
    json: () => r.json(),
    text: () => r.text(),
    headers: { get: (n: string) => r.headers.get(n) },
  };
};
