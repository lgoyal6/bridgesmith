/**
 * Birth certificates: signed, verifiable proof that a connector version passed
 * certification. Signed with an ed25519 key generated per-registry (kept in
 * connectors/.registry-key, gitignored).
 *
 * Verification is anchored: a certificate is valid only if it verifies under the
 * registry's OWN public key (`.registry-key.pub`). The `publicKey` field inside
 * the certificate is informational and must match that anchor; it is never used
 * as the verification key on its own, because anything the certificate carries
 * about itself is under the forger's control.
 */
import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { canonicalJson } from "../core/canon.js";
import { manifestHash } from "../capture/manifest.js";

function keyPaths(dir: string) {
  return { priv: `${dir}/.registry-key`, pub: `${dir}/.registry-key.pub` };
}

export function ensureRegistryKey(dir: string): { privatePem: string; publicPem: string } {
  const { priv, pub } = keyPaths(dir);
  if (existsSync(priv) && existsSync(pub)) {
    return { privatePem: readFileSync(priv, "utf8"), publicPem: readFileSync(pub, "utf8") };
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  mkdirSync(dirname(priv), { recursive: true });
  writeFileSync(priv, privatePem, { mode: 0o600 });
  writeFileSync(pub, publicPem);
  return { privatePem, publicPem };
}

/**
 * The registry's trust anchor: its own public key, or null if this registry has
 * never issued a certificate. With no anchor nothing can be trusted (fail closed).
 */
export function loadTrustAnchor(dir: string): string | null {
  const { pub } = keyPaths(dir);
  return existsSync(pub) ? readFileSync(pub, "utf8") : null;
}

function signable(cert: Omit<BirthCertificate, "signature">): string {
  return canonicalJson({ ...cert, signature: undefined });
}

export function issueCertificate(
  spec: ConnectorSpec,
  report: CertificationReport,
  version: number,
  registryDir: string,
): BirthCertificate {
  const { privatePem, publicPem } = ensureRegistryKey(registryDir);
  const unsigned: Omit<BirthCertificate, "signature"> = {
    app: spec.app,
    version,
    tier: spec.tier,
    specHash: spec.specHash,
    certifiedOps: report.certifiedOps,
    refusedOps: report.refusedOps,
    mutationStats: report.mutation,
    certifiedWorkflows: report.workflows.filter((w) => w.pass).map((w) => w.id),
    captureManifestHash: manifestHash(spec.capture),
    holdoutManifestHash: manifestHash(report.holdout),
    issuedAt: new Date().toISOString(),
    publicKey: publicPem,
  };
  const sig = edSign(null, Buffer.from(signable(unsigned)), createPrivateKey(privatePem));
  return { ...unsigned, signature: sig.toString("base64") };
}

/** Compare two public keys by their SPKI DER encoding, not by PEM text. */
function sameKey(pemA: string, pemB: string): boolean {
  const a = createPublicKey(pemA).export({ type: "spki", format: "der" });
  const b = createPublicKey(pemB).export({ type: "spki", format: "der" });
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * True only if `cert` was signed by `trustedPublicPem` and claims that same key.
 * A certificate that verifies under the key it carries but not under the
 * registry's key is a forgery, not a certificate.
 */
export function verifyCertificate(cert: BirthCertificate, trustedPublicPem: string): boolean {
  try {
    if (typeof cert?.signature !== "string" || typeof cert.publicKey !== "string") return false;
    if (!sameKey(cert.publicKey, trustedPublicPem)) return false;
    const { signature, ...rest } = cert;
    return edVerify(
      null,
      Buffer.from(signable(rest as Omit<BirthCertificate, "signature">)),
      createPublicKey(trustedPublicPem),
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}
