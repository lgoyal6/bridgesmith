/**
 * Capture provenance. A certificate says an operation passed certification; a
 * capture manifest says WHAT EVIDENCE it passed against. Without it, "certified"
 * is unfalsifiable after the fact: you cannot tell whether the holdout was a real
 * independent slice of the app or a copy of the derive capture, whether the
 * evidence was scanned for secrets, or which driver and toolchain produced it.
 *
 * One manifest per capture set. It records the set's content identity (a hash
 * over per-exchange body hashes, so replacing any single response changes it),
 * the driver that recorded it, the secret scan verdict, and the toolchain.
 *
 * The derive manifest is embedded in the spec, so `specHash` covers it and the
 * registry's existing spec<->certificate binding already refuses a spec whose
 * provenance was edited. The certificate additionally carries the derive and
 * holdout manifest hashes as signed fields, which is what proves the two sets
 * were distinct.
 */
import type { CaptureManifest, Exchange } from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import { BRIDGESMITH_VERSION } from "../core/version.js";
import { scanForSecrets } from "./redact.js";

export interface ManifestOptions {
  app: string;
  role: CaptureManifest["role"];
  /** Overrides the driver recorded on the exchanges themselves. */
  driver?: string;
  /** Injected in tests so a manifest hash is reproducible. */
  now?: () => Date;
}

/** sha256 of a body, or the empty-body marker. Bodies are canonicalized first. */
function bodyHash(body: unknown): string {
  return body === undefined ? "none" : sha256(canonicalJson(body));
}

export function buildCaptureManifest(exchanges: Exchange[], opts: ManifestOptions): CaptureManifest {
  const bodies = exchanges.map((e) => ({
    method: e.method,
    path: e.path,
    status: e.status,
    request: bodyHash(e.requestBody),
    response: bodyHash(e.responseBody),
  }));
  const origins = new Set<string>();
  for (const e of exchanges) {
    try {
      origins.add(new URL(e.url).origin);
    } catch {
      origins.add("(unparseable)");
    }
  }
  const drivers = new Set(exchanges.map((e) => e.capturedBy ?? "unrecorded"));
  const manifest: CaptureManifest = {
    app: opts.app,
    role: opts.role,
    targetOrigins: [...origins].sort(),
    driver: opts.driver ?? (drivers.size === 1 ? [...drivers][0]! : `mixed(${[...drivers].sort().join("+")})`),
    capturedAt: (opts.now?.() ?? new Date()).toISOString(),
    exchangeCount: exchanges.length,
    bodies,
    // setId deliberately excludes the timestamp: it is the identity of the
    // EVIDENCE, so two captures of identical traffic collide here on purpose.
    // That is how a holdout that merely copies the derive capture is detected.
    setId: sha256(canonicalJson(bodies)),
    secretScan: scanForSecrets(exchanges),
    toolchain: { node: process.version, bridgesmith: BRIDGESMITH_VERSION },
  };
  return manifest;
}

/** Content hash of a whole manifest, timestamp included: this is what the certificate signs. */
export function manifestHash(m: CaptureManifest): string {
  return sha256(canonicalJson(m));
}

/**
 * True when derive and holdout are the same evidence wearing two labels.
 * Certification against a holdout that is a copy of the derive capture proves
 * nothing, so certify() refuses it rather than reporting a green verdict.
 */
export function isSameEvidence(a: CaptureManifest, b: CaptureManifest): boolean {
  return a.setId === b.setId;
}
