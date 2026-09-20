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
import { canonicalJson, sha256 } from "../core/canon.js";
import { manifestHash } from "../capture/manifest.js";
import { BRIDGESMITH_VERSION } from "../core/version.js";
import { permissionsHashOf } from "../runtime/permissions.js";

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

/**
 * Short, stable identity for a signing key: the first 16 bytes of the SHA-256 of
 * its SPKI DER. Lets an artifact name WHICH key it expects without carrying the
 * key, so "signed by the wrong registry" is a readable failure rather than a
 * signature mismatch with no explanation.
 */
export function keyId(publicPem: string): string {
  return sha256(createPublicKey(publicPem).export({ type: "spki", format: "der" }).toString("base64")).slice(0, 32);
}

/** Sign an arbitrary payload with the registry key. Used for artifacts other than certificates. */
export function signPayload(registryDir: string, payload: unknown): { signature: string; keyId: string } {
  const { privatePem, publicPem } = ensureRegistryKey(registryDir);
  const sig = edSign(null, Buffer.from(canonicalJson(payload)), createPrivateKey(privatePem));
  return { signature: sig.toString("base64"), keyId: keyId(publicPem) };
}

/** Verify a payload signature against a trust anchor, including the key identity it names. */
export function verifyPayload(payload: unknown, signature: string, expectKeyId: string, trustedPublicPem: string): boolean {
  try {
    if (keyId(trustedPublicPem) !== expectKeyId) return false;
    return edVerify(null, Buffer.from(canonicalJson(payload)), createPublicKey(trustedPublicPem), Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

function signable(cert: Omit<BirthCertificate, "signature">): string {
  return canonicalJson({ ...cert, signature: undefined });
}

/**
 * Identity of the executor configuration for a spec. There is no generated
 * source to hash - the adapter is one spec-driven executor - so this hashes what
 * actually determines behaviour: the mounted operations, the declared
 * invariants, the workflows, and the runtime version.
 *
 * Everything here except `runtime` is already covered by specHash. The runtime
 * component is what this adds: a certificate issued by one executor version does
 * not silently carry over to another version that may interpret the same spec
 * differently. See the note on test C15 for what that does and does not prove.
 */
export function adapterHashOf(spec: ConnectorSpec, runtime: string = BRIDGESMITH_VERSION): string {
  return sha256(
    canonicalJson({
      specHash: spec.specHash,
      runtime,
      operations: spec.operations.map((o) => ({ id: o.id, method: o.method, path: o.pathTemplate, schema: o.responseSchema })),
      invariants: (spec.semanticInvariants ?? []).map((i) => i.id).sort(),
      permissions: spec.permissions ? permissionsHashOf(spec.permissions) : null,
      workflows: (spec.workflows ?? []).map((w) => `${w.id}:${w.steps.map((s) => s.id).join(">")}`).sort(),
    }),
  );
}

export interface Lineage {
  predecessor: BirthCertificate["predecessor"];
  compat: string;
}

export function issueCertificate(
  spec: ConnectorSpec,
  report: CertificationReport,
  version: number,
  registryDir: string,
  lineage: Lineage = { predecessor: null, compat: "initial" },
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
    certifiedInvariants: report.semantic
      .filter((c) => c.pass)
      .map((c) => ({ id: c.id, evidenceHash: c.evidenceHash })),
    predecessor: lineage.predecessor,
    compat: lineage.compat,
    adapterHash: adapterHashOf(spec),
    permissionsHash: spec.permissions ? permissionsHashOf(spec.permissions) : null,
    captureManifestHash: manifestHash(spec.capture),
    holdoutManifestHash: manifestHash(report.holdout),
    issuedAt: new Date().toISOString(),
    publicKey: publicPem,
  };
  const sig = edSign(null, Buffer.from(signable(unsigned)), createPrivateKey(privatePem));
  return { ...unsigned, signature: sig.toString("base64") };
}

/**
 * Compare two public keys by their SPKI DER encoding, not by PEM text.
 *
 * HONEST NOTE ON WHAT THIS BUYS: `publicKey` is inside the signed body, so a
 * certificate carrying a key other than the anchor already fails the signature
 * check (test V3). Verified by mutation, deleting this line fails no test: it is
 * unreachable today. It stays as an explicit tripwire - if `signable()` is ever
 * narrowed to exclude `publicKey`, this becomes the only thing standing between
 * a genuine signature and an attacker-supplied verification key.
 */
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
