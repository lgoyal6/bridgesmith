/**
 * Signs connector certificates and verifies the registry's active trust key.
 * Registry.load uses this module to refuse retired keys and invalid state.
 * One lifecycle snapshot keeps the signing key and signed history together.
 * A shared mutation lock prevents initialization, issuance and rotation races.
 */
import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import { manifestHash } from "../capture/manifest.js";
import { BRIDGESMITH_VERSION } from "../core/version.js";
import { permissionsHashOf } from "../runtime/permissions.js";

function keyPaths(dir: string) {
  return { priv: `${dir}/.registry-key`, pub: `${dir}/.registry-key.pub` };
}
interface RegistryKeyState { privatePem: string; publicPem: string; ring?: Keyring }
function readKeyState(dir: string): RegistryKeyState | null {
  const path = `${dir}/.registry-state.json`;
  if (!existsSync(path)) return null;
  try {
    const state = JSON.parse(readFileSync(path, "utf8")) as RegistryKeyState;
    if (typeof state.privatePem !== "string" || typeof state.publicPem !== "string" || (state.ring !== undefined && typeof state.ring !== "object")) {
      throw new Error("invalid lifecycle state schema");
    }
    return state;
  } catch (error) {
    throw new Error("registry lifecycle state is corrupt; refusing legacy key mirrors", { cause: error });
  }
}

export function ensureRegistryKey(dir: string): { privatePem: string; publicPem: string } {
  return withKeyringLock(dir, () => ensureRegistryKeyLocked(dir));
}

// Lifecycle writers already hold the lock and must not acquire it twice.
function ensureRegistryKeyLocked(dir: string): { privatePem: string; publicPem: string } {
  const { priv, pub } = keyPaths(dir);
  const state = readKeyState(dir);
  if (state) return { privatePem: state.privatePem, publicPem: state.publicPem };
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
  try {
    const state = readKeyState(dir);
    if (state) return state.publicPem;
  } catch { return null; }
  return existsSync(pub) ? readFileSync(pub, "utf8") : null;
}

export interface KeyringRecord {
  keyId: string;
  publicKey: string;
  status: "active" | "revoked";
  changedAt: string;
  reason: string;
  signerKeyId: string | null;
  signature: string;
}
export interface Keyring { version: 1; sequence: number; previousHead: string | null; records: KeyringRecord[]; head: string }

function keyringBody(ring: Omit<Keyring, "head">): string { return canonicalJson(ring); }
function keyringHead(ring: Omit<Keyring, "head">): string { return sha256(keyringBody(ring)); }
function atomicJson(path: string, value: unknown): void {
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  try { renameSync(tmp, path); } catch (e) { rmSync(tmp, { force: true }); throw e; }
}
function atomicText(path: string, value: string): void {
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, value, { mode: 0o600 });
  try { renameSync(tmp, path); } catch (e) { rmSync(tmp, { force: true }); throw e; }
}
function signRecord(record: Omit<KeyringRecord, "signature">, privatePem: string): KeyringRecord {
  return { ...record, signature: edSign(null, Buffer.from(canonicalJson(record)), createPrivateKey(privatePem)).toString("base64") };
}
function verifyRecord(record: KeyringRecord, signer: string): boolean {
  const { signature, ...body } = record;
  return edVerify(null, Buffer.from(canonicalJson(body)), createPublicKey(signer), Buffer.from(signature, "base64"));
}

/** Validate the entire chain against a caller-pinned root and optional out-of-band head. */
export function verifyKeyring(ring: Keyring, pinnedRoot: string, expectedHead?: string): string | null {
  try {
    const { head, ...body } = ring;
    if (ring.version !== 1 || head !== keyringHead(body) || (expectedHead && expectedHead !== head)) return null;
    let signer = pinnedRoot;
    let priorKey = keyId(pinnedRoot);
    if (!Number.isSafeInteger(ring.sequence) || ring.sequence < 0 || ring.sequence > ring.records.length) return null;
    for (const [i, rec] of ring.records.entries()) {
      if (rec.signerKeyId !== (i === 0 ? null : priorKey) || !rec.keyId || keyId(rec.publicKey) !== rec.keyId) return null;
      if (i === 0) {
        if (!sameKey(rec.publicKey, pinnedRoot) || rec.status !== "active" || rec.signature !== "root") return null;
      } else if (!verifyRecord(rec, signer)) return null;
      signer = rec.publicKey;
      priorKey = rec.keyId;
    }
    const active = ring.records.at(-1)?.status === "active" ? ring.records.at(-1) : undefined;
    return active?.publicKey ?? null;
  } catch { return null; }
}

function readKeyring(dir: string): Keyring | null {
  const state = readKeyState(dir);
  if (state?.ring) return state.ring;
  if (existsSync(`${dir}/.registry-state.json`)) return null;
  try { return JSON.parse(readFileSync(`${dir}/.registry-keyring.json`, "utf8")) as Keyring; } catch { return null; }
}

function persistKeyState(dir: string, state: RegistryKeyState): void {
  atomicJson(`${dir}/.registry-state.json`, state);
  // Compatibility mirrors are deliberately non-authoritative. A crash during
  // mirror refresh cannot split signing and verification state.
  if (state.ring) atomicJson(`${dir}/.registry-keyring.json`, state.ring);
  atomicText(`${dir}/.registry-key`, state.privatePem);
  atomicText(`${dir}/.registry-key.pub`, state.publicPem);
}

/** Verify the on-disk chain against a separately pinned root and optional out-of-band head. */
export function verifyRegistryKeyring(dir: string, pinnedRoot: string, expectedHead?: string): string | null {
  try {
    const ring = readKeyring(dir);
    return ring ? verifyKeyring(ring, pinnedRoot, expectedHead) : null;
  } catch { return null; }
}

/** Initialize an anchored keyring for existing single-key registries. */
export function ensureKeyring(dir: string): Keyring {
  const existing = readKeyring(dir);
  if (existing) return existing;
  return withKeyringLock(dir, () => ensureKeyringLocked(dir));
}

// Recheck after taking the lock so a completed initializer is never replaced.
function ensureKeyringLocked(dir: string): Keyring {
  const existing = readKeyring(dir);
  if (existing) return existing;
  const { privatePem, publicPem } = ensureRegistryKeyLocked(dir);
  const root = { version: 1 as const, sequence: 0, previousHead: null, records: [{ keyId: keyId(publicPem), publicKey: publicPem, status: "active" as const, changedAt: new Date().toISOString(), reason: "initial trust root", signerKeyId: null, signature: "root" }] };
  const ring = { ...root, head: keyringHead(root) };
  atomicText(`${dir}/.registry-key-root.pub`, publicPem);
  persistKeyState(dir, { privatePem, publicPem, ring });
  void privatePem;
  return ring;
}

function withKeyringLock<T>(dir: string, fn: () => T): T {
  mkdirSync(dir, { recursive: true });
  const lock = `${dir}/.registry-keyring.lock`;
  mkdirSync(lock);
  try { return fn(); } finally { rmSync(lock, { recursive: true, force: true }); }
}

/** Rotate to a new key. Old certificates cease to mount because only the latest active key is accepted. */
export function rotateRegistryKey(dir: string, reason = "key rotation"): Keyring {
  return withKeyringLock(dir, () => rotateRegistryKeyLocked(dir, reason));
}
function rotateRegistryKeyLocked(dir: string, reason: string): Keyring {
  const ring = ensureKeyringLocked(dir);
  const { privatePem } = ensureRegistryKeyLocked(dir);
  const previous = ring.records.at(-1);
  if (!previous) throw new Error("keyring has no active key");
  if (previous.status === "active") {
    const retired = signRecord({ keyId: previous.keyId, publicKey: previous.publicKey, status: "revoked", changedAt: new Date().toISOString(), reason, signerKeyId: previous.keyId }, privatePem);
    ring.records = [...ring.records, retired];
  }
  const generated = generateKeyPairSync("ed25519");
  const publicPem = generated.publicKey.export({ type: "spki", format: "pem" }).toString();
  const next = signRecord({ keyId: keyId(publicPem), publicKey: publicPem, status: "active", changedAt: new Date().toISOString(), reason, signerKeyId: previous.keyId }, privatePem);
  const body = { version: 1 as const, sequence: ring.sequence + 1, previousHead: ring.head, records: [...ring.records, next] };
  const out = { ...body, head: keyringHead(body) };
  persistKeyState(dir, { privatePem: generated.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), publicPem, ring: out });
  return out;
}

/** Revoke the active key. No certificate remains mountable until a fresh key is rotated in. */
export function revokeRegistryKey(dir: string, reason: string): Keyring {
  return withKeyringLock(dir, () => revokeRegistryKeyLocked(dir, reason));
}
function revokeRegistryKeyLocked(dir: string, reason: string): Keyring {
  if (!reason.trim()) throw new Error("revocation reason is required");
  const ring = ensureKeyringLocked(dir);
  const active = ring.records.at(-1);
  if (!active || active.status !== "active") throw new Error("keyring has no active key");
  const { privatePem } = ensureRegistryKeyLocked(dir);
  const revoked = signRecord({ keyId: active.keyId, publicKey: active.publicKey, status: "revoked", changedAt: new Date().toISOString(), reason, signerKeyId: active.keyId }, privatePem);
  const body = { version: 1 as const, sequence: ring.sequence + 1, previousHead: ring.head, records: [...ring.records, revoked] };
  const out = { ...body, head: keyringHead(body) };
  persistKeyState(dir, { ...ensureRegistryKeyLocked(dir), ring: out });
  return out;
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
  // Validation and signing must use the same key generation across processes.
  return withKeyringLock(registryDir, () => issueCertificateLocked(spec, report, version, registryDir, lineage));
}

function issueCertificateLocked(
  spec: ConnectorSpec,
  report: CertificationReport,
  version: number,
  registryDir: string,
  lineage: Lineage,
): BirthCertificate {
  if (report.app !== spec.app) throw new Error("certification report does not match the connector app");
  const ring = ensureKeyringLocked(registryDir);
  const activeRecord = ring.records.at(-1);
  if (!activeRecord || activeRecord.status !== "active") throw new Error("registry has no active signing key");
  const certifiedAt = Date.parse(report.startedAt);
  const keyActiveAt = Date.parse(activeRecord.changedAt);
  if (!Number.isFinite(certifiedAt) || !Number.isFinite(keyActiveAt) || (ring.sequence > 0 && certifiedAt < keyActiveAt)) {
    throw new Error("certification must start after activation of the active registry key");
  }
  const { privatePem, publicPem } = ensureRegistryKeyLocked(registryDir);
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
    keyId: keyId(publicPem),
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
