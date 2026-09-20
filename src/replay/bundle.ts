/**
 * Replay bundles: everything needed to reproduce one certified run offline, and
 * a signed manifest that says so.
 *
 * The certificate proves an operation passed certification. It does not let
 * anyone else RE-RUN that certification, which means a disputed result has no
 * resolution better than "run it again against a live service and hope the
 * service has not moved". A bundle closes that: redacted evidence, the mounted
 * spec, the certificate, and a manifest binding all of it, signed through the
 * same registry trust anchor the certificate uses.
 *
 * What the manifest binds, and why each field is in the signature:
 *   - target identity + origins   cross-target replay is refused by name
 *   - capture driver + toolchain  evidence recorded by a different tool is not the same evidence
 *   - capture time                when, not just what
 *   - ORDERED exchange hashes     order is semantic for pagination; reordering is tampering
 *   - redaction policy + result   which rules ran, and what they found
 *   - mounted spec hash           the spec that will be replayed is the certified one
 *   - adapter hash + runtime      the executor that will run it is the certified one
 *   - workflow step ordering      a workflow replay is the same sequence, or it is not a replay
 *   - certificate identity + key  which certificate, signed by which registry key
 *
 * Verification reports WHICH field failed, because "invalid" is not actionable.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
  BirthCertificate,
  CertificationReport,
  ConnectorSpec,
  Exchange,
} from "../core/types.js";
import { canonicalJson, sha256 } from "../core/canon.js";
import { BRIDGESMITH_VERSION } from "../core/version.js";
import { REDACTION_POLICY, scanForSecrets } from "../capture/redact.js";
import { adapterHashOf, keyId, loadTrustAnchor, signPayload, verifyCertificate, verifyPayload } from "../registry/certificate.js";
import { specHashOf } from "../spec/derive.js";
import { manifestHash } from "../capture/manifest.js";
import { replayFetcher } from "../certify/replay.js";
import { Adapter } from "../codegen/adapter.js";
import { runWorkflow } from "../certify/workflow.js";

export type BundleKind = "certification" | "drift-incident";

export interface ReplayManifest {
  bundleVersion: 1;
  kind: BundleKind;
  /** Target identity: the app this evidence belongs to, and where it came from. */
  app: string;
  targetOrigins: string[];
  /** Capture driver and toolchain that produced the evidence. */
  driver: string;
  toolchain: { node: string; bridgesmith: string };
  capturedAt: string;
  /** Ordered hashes of the replay inputs. Order is part of the signature. */
  exchanges: { method: string; path: string; search: string; status: number; bodyHash: string }[];
  exchangeCount: number;
  /** Which redaction rules ran, and the hash of what they found. */
  redaction: { policy: typeof REDACTION_POLICY; resultHash: string; clean: boolean };
  /** The spec that will be replayed, and the executor that will run it. */
  specHash: string;
  captureManifestHash: string;
  adapterHash: string;
  runtime: string;
  /** Workflow identities and their step ordering. */
  workflows: { id: string; steps: string[] }[];
  /** Which certificate this bundle reproduces, and which key signed it. */
  certificate: { app: string; version: number; signature: string; keyId: string };
  /** What a correct replay must produce. */
  expected: { certifiedOps: string[]; certifiedInvariants: string[]; schemaVerdict: string; semanticVerdict: string };
  createdAt: string;
}

export interface SignedReplayManifest {
  manifest: ReplayManifest;
  signature: string;
  keyId: string;
}

export interface ReplayBundle {
  signed: SignedReplayManifest;
  spec: ConnectorSpec;
  cert: BirthCertificate;
  report: CertificationReport;
  exchanges: Exchange[];
}

function exchangeDigest(e: Exchange): ReplayManifest["exchanges"][number] {
  let search = "";
  try {
    search = new URL(e.url).search;
  } catch {
    search = "";
  }
  return { method: e.method, path: e.path, search, status: e.status, bodyHash: sha256(canonicalJson(e.responseBody ?? null)) };
}

export function buildReplayBundle(input: {
  kind: BundleKind;
  spec: ConnectorSpec;
  cert: BirthCertificate;
  report: CertificationReport;
  exchanges: Exchange[];
  registryDir: string;
  now?: () => Date;
}): ReplayBundle {
  const { spec, cert, report, exchanges, registryDir } = input;
  const scan = scanForSecrets(exchanges);
  // Refuse to build a bundle around evidence that still carries a credential.
  // A bundle is made to be shared; that is exactly when a leak stops being local.
  if (!scan.clean) {
    throw new Error(`refusing to bundle unredacted evidence: ${scan.findings[0]}`);
  }
  const origins = new Set<string>();
  for (const e of exchanges) {
    try {
      origins.add(new URL(e.url).origin);
    } catch {
      origins.add("(unparseable)");
    }
  }
  const drivers = new Set(exchanges.map((e) => e.capturedBy ?? "unrecorded"));

  const manifest: ReplayManifest = {
    bundleVersion: 1,
    kind: input.kind,
    app: spec.app,
    targetOrigins: [...origins].sort(),
    driver: drivers.size === 1 ? [...drivers][0]! : `mixed(${[...drivers].sort().join("+")})`,
    toolchain: { node: process.version, bridgesmith: BRIDGESMITH_VERSION },
    capturedAt: spec.capture.capturedAt,
    exchanges: exchanges.map(exchangeDigest),
    exchangeCount: exchanges.length,
    redaction: { policy: REDACTION_POLICY, resultHash: sha256(canonicalJson(scan)), clean: scan.clean },
    specHash: spec.specHash,
    captureManifestHash: manifestHash(spec.capture),
    adapterHash: adapterHashOf(spec),
    runtime: BRIDGESMITH_VERSION,
    workflows: (spec.workflows ?? []).map((w) => ({ id: w.id, steps: w.steps.map((s) => s.id) })),
    certificate: { app: cert.app, version: cert.version, signature: cert.signature, keyId: keyId(cert.publicKey) },
    expected: {
      certifiedOps: [...report.certifiedOps].sort(),
      certifiedInvariants: report.semantic.filter((c) => c.pass).map((c) => c.id).sort(),
      schemaVerdict: report.schemaVerdict,
      semanticVerdict: report.semanticVerdict,
    },
    createdAt: (input.now?.() ?? new Date()).toISOString(),
  };
  const { signature, keyId: kid } = signPayload(registryDir, manifest);
  return { signed: { manifest, signature, keyId: kid }, spec, cert, report, exchanges };
}

/* ---------------------------------------------------------------- *
 * Verification
 * ---------------------------------------------------------------- */

export interface BundleVerification {
  ok: boolean;
  /** Every failed check, named. An empty list means every bound field matched. */
  failures: string[];
}

export function verifyBundle(bundle: ReplayBundle, trustedPublicPem: string | null): BundleVerification {
  const f: string[] = [];
  const m = bundle.signed.manifest;

  if (!trustedPublicPem) return { ok: false, failures: ["no trust anchor: nothing in this bundle can be trusted"] };
  if (m.bundleVersion !== 1) f.push(`unsupported bundle version ${m.bundleVersion}`);
  if (!verifyPayload(m, bundle.signed.signature, bundle.signed.keyId, trustedPublicPem)) {
    f.push("manifest signature does not verify under the trust anchor");
  }
  if (!verifyCertificate(bundle.cert, trustedPublicPem)) f.push("certificate does not verify under the trust anchor");

  // target identity
  if (m.app !== bundle.spec.app) f.push(`manifest names app "${m.app}" but the spec is "${bundle.spec.app}"`);
  if (m.certificate.app !== bundle.cert.app) f.push("manifest and certificate disagree about the app");
  if (m.certificate.version !== bundle.cert.version) f.push("manifest and certificate disagree about the version");
  if (m.certificate.signature !== bundle.cert.signature) f.push("manifest names a different certificate");
  if (m.certificate.keyId !== keyId(trustedPublicPem)) f.push("certificate was signed by a different registry key");

  // the spec that will actually be replayed
  if (bundle.spec.specHash !== m.specHash || specHashOf(bundle.spec) !== m.specHash) f.push("spec does not hash to the manifest's specHash");
  if (bundle.cert.specHash !== m.specHash) f.push("certificate is not bound to this spec");
  if (manifestHash(bundle.spec.capture) !== m.captureManifestHash) f.push("capture provenance does not match the manifest");
  if (adapterHashOf(bundle.spec) !== m.adapterHash) f.push("executor configuration does not match the manifest");
  if (m.runtime !== BRIDGESMITH_VERSION) f.push(`bundle was built by runtime ${m.runtime}, this is ${BRIDGESMITH_VERSION}`);

  // evidence: content AND order
  if (bundle.exchanges.length !== m.exchangeCount) f.push(`bundle holds ${bundle.exchanges.length} exchanges, manifest says ${m.exchangeCount}`);
  const actual = bundle.exchanges.map(exchangeDigest);
  for (let i = 0; i < Math.min(actual.length, m.exchanges.length); i++) {
    const a = actual[i]!;
    const e = m.exchanges[i]!;
    if (canonicalJson(a) !== canonicalJson(e)) {
      f.push(`replay input ${i} does not match the manifest (${e.method} ${e.path}${e.search} expected)`);
      break;
    }
  }

  // redaction is a bound claim, re-checked rather than trusted
  const scan = scanForSecrets(bundle.exchanges);
  if (sha256(canonicalJson(scan)) !== m.redaction.resultHash) f.push("redaction result does not match the manifest");
  if (!scan.clean) f.push(`bundle carries unredacted evidence: ${scan.findings[0]}`);
  if (m.redaction.policy.version !== REDACTION_POLICY.version) {
    f.push(`bundle was redacted under policy v${m.redaction.policy.version}, this runtime uses v${REDACTION_POLICY.version}`);
  }

  // workflow ordering
  const wfNow = (bundle.spec.workflows ?? []).map((w) => ({ id: w.id, steps: w.steps.map((s) => s.id) }));
  if (canonicalJson(wfNow) !== canonicalJson(m.workflows)) f.push("workflow steps or their ordering differ from the manifest");

  return { ok: f.length === 0, failures: f };
}

/* ---------------------------------------------------------------- *
 * On-disk form
 * ---------------------------------------------------------------- */

const FILES = {
  manifest: "replay-manifest.json",
  spec: "spec.json",
  cert: "certificate.json",
  report: "report.json",
  exchanges: "exchanges.json",
} as const;

export function writeBundle(dir: string, bundle: ReplayBundle): string {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, FILES.manifest), JSON.stringify(bundle.signed, null, 2));
  writeFileSync(join(dir, FILES.spec), JSON.stringify(bundle.spec, null, 2));
  writeFileSync(join(dir, FILES.cert), JSON.stringify(bundle.cert, null, 2));
  writeFileSync(join(dir, FILES.report), JSON.stringify(bundle.report, null, 2));
  writeFileSync(join(dir, FILES.exchanges), JSON.stringify(bundle.exchanges, null, 2));
  return dir;
}

export function readBundle(dir: string): ReplayBundle {
  const missing = Object.values(FILES).filter((f) => !existsSync(join(dir, f)));
  if (missing.length) throw new Error(`incomplete replay bundle, missing: ${missing.join(", ")}`);
  const read = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));
  return {
    signed: read(FILES.manifest),
    spec: read(FILES.spec),
    cert: read(FILES.cert),
    report: read(FILES.report),
    exchanges: read(FILES.exchanges),
  };
}

/** The trust anchor a bundle is verified against: the registry's, or one shipped beside the bundle. */
export function bundleAnchor(dir: string, registryDir?: string): string | null {
  if (registryDir) return loadTrustAnchor(registryDir);
  const local = join(dir, ".registry-key.pub");
  return existsSync(local) ? readFileSync(local, "utf8") : null;
}

/* ---------------------------------------------------------------- *
 * Offline replay
 * ---------------------------------------------------------------- */

export interface ReplayResult {
  verified: BundleVerification;
  /** Per-operation replay outcomes against the bundled evidence. No network. */
  ops: { op: string; ok: boolean; outcome: string; detail?: string; skipped?: boolean }[];
  workflows: { id: string; pass: boolean; failure?: string; detail?: string }[];
  /**
   * Whether the bundle reproduced what it claims, which means OPPOSITE things
   * for the two kinds and so is decided by the manifest's kind, not by the
   * caller:
   *   certification  - every certified operation and workflow still passes
   *   drift-incident - the failure is still there, with the same outcome
   * A drift bundle whose evidence suddenly passes has not reproduced anything;
   * it has silently become a different artifact.
   */
  reproduced: boolean;
}

/**
 * Replay a bundle with no network access at all: every response comes from the
 * bundled evidence through the replay fetcher. The bundle is verified FIRST and
 * a failed verification short-circuits, because replaying unverified evidence
 * produces a number that means nothing.
 */
export async function runBundle(bundle: ReplayBundle, trustedPublicPem: string | null): Promise<ReplayResult> {
  const verified = verifyBundle(bundle, trustedPublicPem);
  if (!verified.ok) return { verified, ops: [], workflows: [], reproduced: false };

  const { fetcher } = replayFetcher(bundle.exchanges);
  const adapter = new Adapter(bundle.spec, { fetcher, unguarded: true });
  const ops: ReplayResult["ops"] = [];
  for (const op of bundle.spec.operations) {
    const params: Record<string, unknown> = {};
    // Drive each operation from an exchange the bundle actually holds, so replay
    // exercises the recorded path rather than a synthesized one.
    const sample = bundle.exchanges.find((e) => e.method === op.method && e.path.split("/").length === op.pathTemplate.split("/").length);
    if (!sample) {
      // No evidence for this operation in this bundle. An incident bundle carries
      // only what reproduces the incident, so this is expected; reporting it as a
      // failure would make every incident bundle look broken.
      ops.push({ op: op.id, ok: false, outcome: "no-evidence", skipped: true });
      continue;
    }
    {
      const segs = sample.path.split("/").filter(Boolean);
      const tsegs = op.pathTemplate.split("/").filter(Boolean);
      tsegs.forEach((t, i) => {
        if (t.startsWith("{")) params[t.slice(1, -1)] = segs[i];
      });
      for (const q of op.queryParams) {
        const v = sample.query[q.name];
        if (v !== undefined) params[q.name] = v;
      }
    }
    const r = await adapter.call(op.id, params);
    ops.push({ op: op.id, ok: r.ok, outcome: r.outcome, ...(r.error ? { detail: r.error } : {}) });
  }

  const certifiedOps = new Set(bundle.cert.certifiedOps);
  const workflows: ReplayResult["workflows"] = [];
  for (const wf of bundle.spec.workflows ?? []) {
    const { fetcher: wfFetcher } = replayFetcher(bundle.exchanges);
    const r = await runWorkflow(bundle.spec, wf, certifiedOps, { fetcher: wfFetcher });
    workflows.push({ id: wf.id, pass: r.pass, ...(r.failure ? { failure: r.failure } : {}), ...(r.detail ? { detail: r.detail } : {}) });
  }

  const exercised = ops.filter((o) => certifiedOps.has(o.op) && !o.skipped);
  const reproduced =
    bundle.signed.manifest.kind === "drift-incident"
      ? exercised.length > 0 && exercised.some((o) => !o.ok)
      : exercised.every((o) => o.ok) && workflows.every((w) => w.pass);
  return { verified, ops, workflows, reproduced };
}

/** Bundles present under a directory, for the CLI. */
export function listBundles(root: string): string[] {
  if (!existsSync(root)) return [];
  return readdirSync(root).filter((d) => existsSync(join(root, d, FILES.manifest)));
}
