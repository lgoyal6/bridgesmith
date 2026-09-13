/**
 * Birth certificates: signed, verifiable proof that a connector version passed
 * certification. Signed with an ed25519 key generated per-registry (kept in
 * connectors/.registry-key, gitignored). Anyone with the public key can verify a
 * certificate without trusting us.
 */
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { canonicalJson } from "../core/canon.js";

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
    issuedAt: new Date().toISOString(),
    publicKey: publicPem,
  };
  const sig = edSign(null, Buffer.from(signable(unsigned)), createPrivateKey(privatePem));
  return { ...unsigned, signature: sig.toString("base64") };
}

export function verifyCertificate(cert: BirthCertificate): boolean {
  const { signature, ...rest } = cert;
  try {
    return edVerify(
      null,
      Buffer.from(signable(rest as Omit<BirthCertificate, "signature">)),
      createPublicKey(cert.publicKey),
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}
