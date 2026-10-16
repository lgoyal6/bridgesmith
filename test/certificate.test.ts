/**
 * Checks certificate mounting against real held-out connector certification.
 * Uses Registry and certificate.ts with private trust roots and fixtures.
 * Rejects forgery, stale certification, rotation replay and corrupt state.
 * Valid controls confirm that approved connectors still mount.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign, createPrivateKey } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, cpSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { canonicalJson } from "../src/core/canon.js";
import { ensureRegistryKey, signPayload, issueCertificate, verifyCertificate, rotateRegistryKey, revokeRegistryKey, verifyRegistryKeyring } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../src/core/types.js";
import { captureA, captureB } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "ts-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

/** A registry dir holding one genuinely certified connector version (v1). */
async function legitRegistry(): Promise<{
  dir: string;
  reg: Registry;
  spec: ConnectorSpec;
  report: CertificationReport;
  cert: BirthCertificate;
  trusted: string;
}> {
  const dir = mkdtempSync(join(tmpdir(), "reg-"));
  const reg = new Registry(dir);
  const derived = deriveSpec(loadHar(harFile(captureA())), { app: "events", captureLabel: "A", host: "example-events.com" });
  const { report, effectiveSpec } = await certify(derived, loadHar(harFile(captureB())), {
    deriveExchanges: loadHar(harFile(captureA())),
  });
  const cert = issueCertificate(effectiveSpec, report, reg.nextVersion("events"), dir);
  reg.store(effectiveSpec, report, cert);
  const trusted = ensureRegistryKey(dir).publicPem;
  return { dir, reg, spec: effectiveSpec, report, cert, trusted };
}

async function recertify(spec: ConnectorSpec): Promise<{ spec: ConnectorSpec; report: CertificationReport }> {
  const derive = loadHar(harFile(captureA()));
  const result = await certify(spec, loadHar(harFile(captureB())), { deriveExchanges: derive });
  return { spec: result.effectiveSpec, report: result.report };
}

/** Sign an arbitrary certificate body with an ATTACKER's fresh ed25519 key. */
function forge(body: Omit<BirthCertificate, "signature" | "publicKey">): BirthCertificate {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const unsigned = { ...body, publicKey: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const sig = edSign(null, Buffer.from(canonicalJson({ ...unsigned, signature: undefined })), createPrivateKey(privateKey.export({ type: "pkcs8", format: "pem" }).toString()));
  return { ...unsigned, signature: sig.toString("base64") };
}

function writeVersion(dir: string, app: string, version: number, spec: ConnectorSpec, cert: BirthCertificate, report: CertificationReport) {
  const vdir = join(dir, app, `v${version}`);
  mkdirSync(vdir, { recursive: true });
  writeFileSync(join(vdir, "spec.json"), JSON.stringify(spec, null, 2));
  writeFileSync(join(vdir, "report.json"), JSON.stringify(report, null, 2));
  writeFileSync(join(vdir, "certificate.json"), JSON.stringify(cert, null, 2));
  return vdir;
}

describe("certificate: genuine certificates still work", () => {
  it("V0 a certificate issued by the registry key verifies against the trust anchor and is served", async () => {
    const { reg, cert, spec, trusted } = await legitRegistry();
    expect(verifyCertificate(cert, trusted)).toBe(true);
    const latest = reg.latest("events");
    expect(latest?.cert.version).toBe(1);
    expect(latest?.spec.specHash).toBe(spec.specHash);
    expect(reg.list().map((r) => r.valid)).toEqual([true]);
  });

  it("V0b two genuine versions: the newest valid one wins", async () => {
    const { dir, reg, spec, report } = await legitRegistry();
    const cert2 = issueCertificate(spec, report, 2, dir);
    reg.store(spec, report, cert2);
    expect(reg.latest("events")?.cert.version).toBe(2);
  });

  it("V0c rotation invalidates old-key certificates and freshly certified versions mount", async () => {
    const { dir, reg, spec, report, cert } = await legitRegistry();
    const pinnedRoot = readFileSync(join(dir, ".registry-key-root.pub"), "utf8");
    const rotated = rotateRegistryKey(dir, "scheduled rotation");
    expect(verifyRegistryKeyring(dir, pinnedRoot, rotated.head)).not.toBeNull();
    expect(verifyCertificate(cert, ensureRegistryKey(dir).publicPem)).toBe(false);
    expect(reg.latest("events")).toBeNull();
    expect(() => issueCertificate(spec, report, 2, dir)).toThrow(/certification must start after activation/);
    const freshEvidence = await recertify(spec);
    const fresh = issueCertificate(freshEvidence.spec, freshEvidence.report, 2, dir);
    reg.store(freshEvidence.spec, freshEvidence.report, fresh);
    expect(reg.latest("events")?.cert.version).toBe(2);
    expect(reg.at("events", 1)).toBeNull();
  });

  it("V0d revocation immediately invalidates certificates and a later key requires fresh certification", async () => {
    const { dir, reg, spec, report, cert } = await legitRegistry();
    const oldKey = ensureRegistryKey(dir).publicPem;
    const revoked = revokeRegistryKey(dir, "suspected compromise");
    expect(verifyRegistryKeyring(dir, readFileSync(join(dir, ".registry-key-root.pub"), "utf8"), revoked.head)).toBeNull();
    expect(verifyCertificate(cert, oldKey)).toBe(true);
    expect(reg.latest("events")).toBeNull();
    rotateRegistryKey(dir, "recovery after revocation");
    expect(() => issueCertificate(spec, report, 2, dir)).toThrow(/certification must start after activation/);
    const freshEvidence = await recertify(spec);
    const fresh = issueCertificate(freshEvidence.spec, freshEvidence.report, 2, dir);
    reg.store(freshEvidence.spec, freshEvidence.report, fresh);
    expect(reg.latest("events")?.cert.version).toBe(2);
    expect(reg.at("events", 1)).toBeNull();
  });

  it("V0e interrupted compatibility-mirror updates cannot split active signing and verification state", async () => {
    const { dir, reg, spec, report } = await legitRegistry();
    const pinnedRoot = readFileSync(join(dir, ".registry-key-root.pub"), "utf8");
    rotateRegistryKey(dir, "crash consistency test");
    const committedState = readFileSync(join(dir, ".registry-state.json"), "utf8");
    // Model termination after the atomic state commit but before all legacy mirrors refresh.
    writeFileSync(join(dir, ".registry-key.pub"), "stale public key");
    writeFileSync(join(dir, ".registry-key"), "stale private key");
    writeFileSync(join(dir, ".registry-keyring.json"), "stale keyring");
    const freshEvidence = await recertify(spec);
    const fresh = issueCertificate(freshEvidence.spec, freshEvidence.report, 2, dir);
    reg.store(freshEvidence.spec, freshEvidence.report, fresh);
    expect(verifyRegistryKeyring(dir, pinnedRoot)).toBe(ensureRegistryKey(dir).publicPem);
    expect(reg.latest("events")?.cert.version).toBe(2);
    writeFileSync(join(dir, ".registry-state.json"), "{");
    expect(verifyRegistryKeyring(dir, pinnedRoot)).toBeNull();
    expect(reg.latest("events")).toBeNull();
    expect(() => issueCertificate(freshEvidence.spec, freshEvidence.report, 3, dir)).toThrow(/lifecycle state is corrupt/);
    writeFileSync(join(dir, ".registry-state.json"), committedState);
  });

  it("V0f lifecycle matrix isolates two apps and versions across two trust roots", async () => {
    const registries = [mkdtempSync(join(tmpdir(), "reg-matrix-a-")), mkdtempSync(join(tmpdir(), "reg-matrix-b-"))];
    for (const dir of registries) new Registry(dir);
    const appArtifacts: { app: string; spec: ConnectorSpec; report: CertificationReport }[] = [];
    for (const app of ["events", "calendar"]) {
      const derive = loadHar(harFile(captureA()));
      const spec = deriveSpec(derive, { app, captureLabel: "A", host: "example-events.com" });
      const holdout = loadHar(harFile(captureB()));
      const result = await certify(spec, holdout, { deriveExchanges: derive });
      appArtifacts.push({ app, spec: result.effectiveSpec, report: result.report });
    }
    for (const dir of registries) {
      const registry = new Registry(dir);
      for (const artifact of appArtifacts) {
        const cert = issueCertificate(artifact.spec, artifact.report, 1, dir);
        registry.store(artifact.spec, artifact.report, cert);
        expect(registry.latest(artifact.app)?.cert.version).toBe(1);
      }
      rotateRegistryKey(dir, "matrix rotation");
      for (const artifact of appArtifacts) expect(registry.latest(artifact.app)).toBeNull();
      for (const artifact of appArtifacts) {
        expect(() => issueCertificate(artifact.spec, artifact.report, 2, dir)).toThrow(/certification must start after activation/);
        const freshEvidence = await recertify(artifact.spec);
        const cert = issueCertificate(freshEvidence.spec, freshEvidence.report, 2, dir);
        registry.store(freshEvidence.spec, freshEvidence.report, cert);
        expect(registry.latest(artifact.app)?.cert.version).toBe(2);
        expect(registry.at(artifact.app, 1)).toBeNull();
      }
    }
    const foreign = new Registry(registries[1]!);
    expect(foreign.latest("events")?.cert.version).toBe(2);
    expect(verifyCertificate(foreign.at("events", 2)!.cert, ensureRegistryKey(registries[0]!).publicPem)).toBe(false);
  });
});

describe("certificate: lifecycle mutations serialize issuance", () => {
  it("refuses issuance while another lifecycle writer holds the lock", async () => {
    const { dir, reg, spec, report } = await legitRegistry();
    mkdirSync(join(dir, ".registry-keyring.lock"));
    try {
      expect(() => issueCertificate(spec, report, 2, dir)).toThrow(/EEXIST/);
      expect(reg.latest("events")?.cert.version).toBe(1);
    } finally {
      rmSync(join(dir, ".registry-keyring.lock"), { recursive: true });
    }
    expect(issueCertificate(spec, report, 2, dir).version).toBe(2);
  });
});

describe("certificate: forgery and substitution are refused", () => {
  it("V1 a certificate signed by an attacker's own key does NOT verify, even though it is self-consistent", async () => {
    const { cert, trusted } = await legitRegistry();
    const { signature: _s, publicKey: _p, ...body } = cert;
    const forged = forge({ ...body, certifiedOps: [...body.certifiedOps, "delete_everything"] });
    // self-consistency is exactly what an attacker can always produce:
    expect(verifyCertificate(forged, forged.publicKey)).toBe(true);
    // ...and exactly what the registry must not accept:
    expect(verifyCertificate(forged, trusted)).toBe(false);
  });

  it("V2 a forged higher version dropped into the registry is skipped; the genuine v1 is still served", async () => {
    const { dir, reg, cert, spec, report } = await legitRegistry();
    const { signature: _s, publicKey: _p, ...body } = cert;
    const forged = forge({ ...body, version: 99, certifiedOps: [...body.certifiedOps, "delete_everything"] });
    writeVersion(dir, "events", 99, { ...spec, operations: [...spec.operations, { ...spec.operations[0]!, id: "delete_everything" }] }, forged, report);
    const latest = reg.latest("events");
    expect(latest?.cert.version).toBe(1);
    expect(latest?.cert.certifiedOps).not.toContain("delete_everything");
    expect(reg.list().find((r) => r.version === 99)?.valid).toBe(false);
  });

  it("V3 key substitution: genuine signature, attacker public key swapped in", async () => {
    const { cert, trusted } = await legitRegistry();
    const attacker = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifyCertificate({ ...cert, publicKey: attacker }, trusted)).toBe(false);
  });

  it("V4 every signed field is tamper-evident, and a flipped signature bit fails", async () => {
    const { cert, trusted } = await legitRegistry();
    const tampers: Partial<BirthCertificate>[] = [
      { app: "other" },
      { version: cert.version + 1 },
      { tier: "official-api" as BirthCertificate["tier"] },
      { specHash: "0".repeat(64) },
      { certifiedOps: [...cert.certifiedOps, "smuggled"] },
      { refusedOps: [{ op: "get_api_events", reason: "tampered" }] },
      { mutationStats: { ...cert.mutationStats, missed: cert.mutationStats.missed + 1 } },
      { issuedAt: "2020-01-01T00:00:00.000Z" },
    ];
    for (const t of tampers) expect(verifyCertificate({ ...cert, ...t }, trusted), JSON.stringify(t)).toBe(false);
    const sig = Buffer.from(cert.signature, "base64");
    sig[0] = sig[0]! ^ 0x01;
    expect(verifyCertificate({ ...cert, signature: sig.toString("base64") }, trusted)).toBe(false);
  });

  // NOTE ON WHAT THIS PROVES: verified by mutation, the refusal here comes from the
  // spec<->certificate hash binding, NOT from the `cert.app !== app` guard in
  // Registry.load. Because specHash covers the spec's `app` field, no spec naming
  // app Y can ever hash to a certificate issued for app X, so that guard is
  // unreachable defense-in-depth and deleting it fails no test. The replay is still
  // refused; the claim is just narrower than "the cert names the wrong app".
  it("V5 a genuine certificate for app X does not mount a connector under app Y (spec binding refuses the replay)", async () => {
    const { dir, reg, cert, spec, report } = await legitRegistry();
    writeVersion(dir, "payments", 1, { ...spec, app: "payments" }, cert, report);
    expect(reg.latest("payments")).toBeNull();
    // the cert itself is untouched and still genuine, so the refusal is the binding
    expect(verifyCertificate(cert, ensureRegistryKey(dir).publicPem)).toBe(true);
  });

  it("V6 spec.json swapped under a genuine certificate (new op smuggled into the spec) is refused", async () => {
    const { dir, reg, cert, spec } = await legitRegistry();
    const vdir = join(dir, "events", "v1");
    const swapped: ConnectorSpec = {
      ...spec,
      operations: [...spec.operations, { ...spec.operations[0]!, id: "get_api_events_event_id", pathTemplate: "/admin/dump" }],
    };
    writeFileSync(join(vdir, "spec.json"), JSON.stringify(swapped, null, 2));
    expect(reg.latest("events")).toBeNull();
    // and the untouched certificate on its own is still fine, so the refusal is the spec binding, not a side effect
    expect(verifyCertificate(cert, ensureRegistryKey(dir).publicPem)).toBe(true);
  });

  it("V6b spec.json edited in place (baseUrl redirected) under a genuine certificate is refused", async () => {
    const { dir, reg, spec } = await legitRegistry();
    writeFileSync(join(dir, "events", "v1", "spec.json"), JSON.stringify({ ...spec, baseUrl: "https://evil.example" }, null, 2));
    expect(reg.latest("events")).toBeNull();
  });

  it("V7 a malformed certificate.json is skipped without crashing, and does not shadow a genuine lower version", async () => {
    const { dir, reg } = await legitRegistry();
    const vdir = join(dir, "events", "v2");
    mkdirSync(vdir, { recursive: true });
    writeFileSync(join(vdir, "certificate.json"), '{"app":"events","version":2,"certifiedOps":["x"'); // truncated
    writeFileSync(join(vdir, "spec.json"), "{}");
    expect(() => reg.latest("events")).not.toThrow();
    expect(reg.latest("events")?.cert.version).toBe(1);
  });

  it("V8 with no trust anchor on disk nothing is served (fail closed), even a certificate that would self-verify", async () => {
    const { dir, reg, cert } = await legitRegistry();
    rmSync(join(dir, ".registry-key.pub"));
    rmSync(join(dir, ".registry-key"));
    rmSync(join(dir, ".registry-state.json"));
    expect(verifyCertificate(cert, cert.publicKey)).toBe(true); // self-consistent...
    expect(reg.latest("events")).toBeNull(); // ...but not trusted
    expect(reg.list().every((r) => r.valid === false)).toBe(true);
  });

  it("V10 re-signing with an untrusted key fails even when the embedded publicKey matches the anchor", async () => {
    const { cert, trusted } = await legitRegistry();
    // The subtlest forgery: claim the right key in the right field, sign with another.
    // Checking publicKey == anchor is necessary and nowhere near sufficient - the
    // signature must verify UNDER the anchor, not merely be accompanied by it.
    const attacker = generateKeyPairSync("ed25519");
    const { signature: _s, ...body } = { ...cert, certifiedOps: [...cert.certifiedOps, "delete_everything"] };
    const resigned: BirthCertificate = {
      ...body,
      publicKey: trusted, // identical to the trust anchor, byte for byte
      signature: edSign(
        null,
        Buffer.from(canonicalJson({ ...body, publicKey: trusted, signature: undefined })),
        createPrivateKey(attacker.privateKey.export({ type: "pkcs8", format: "pem" }).toString()),
      ).toString("base64"),
    };
    expect(resigned.publicKey).toBe(trusted);
    expect(verifyCertificate(resigned, trusted)).toBe(false);
  });

  it("V9 a certificate copied from a DIFFERENT registry (different key) is refused here", async () => {
    const mine = await legitRegistry();
    const theirs = await legitRegistry();
    // copy their genuine v1 over my v1
    rmSync(join(mine.dir, "events"), { recursive: true });
    cpSync(join(theirs.dir, "events"), join(mine.dir, "events"), { recursive: true });
    expect(JSON.parse(readFileSync(join(mine.dir, "events/v1/certificate.json"), "utf8")).version).toBe(1);
    expect(mine.reg.latest("events")).toBeNull();
  });
});


describe("exported key initialization lock", () => {
  it("refuses low-level initialization and payload signing while another writer holds the lock", () => {
    const dir = mkdtempSync(join(tmpdir(), "reg-direct-lock-"));
    try {
      mkdirSync(join(dir, ".registry-keyring.lock"));
      expect(() => ensureRegistryKey(dir)).toThrow(/EEXIST/);
      expect(() => signPayload(dir, { event: "test" })).toThrow(/EEXIST/);
      rmSync(join(dir, ".registry-keyring.lock"), { recursive: true });
      const pair = ensureRegistryKey(dir);
      expect(pair.publicPem).toContain("BEGIN PUBLIC KEY");
      expect(signPayload(dir, { event: "test" }).signature).toBeTruthy();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
