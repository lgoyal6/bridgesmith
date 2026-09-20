/**
 * On-disk connector registry. Each certified connector version is a directory:
 *   connectors/<app>/v<N>/{spec.json, certificate.json, report.json}
 * Uncertified attempts are never written here (refusal leaves no artifact to
 * accidentally mount).
 *
 * A version is served only if all of the following hold, checked on every read:
 *   1. certificate.json parses and verifies under this registry's own public key
 *      (`.registry-key.pub`, the trust anchor; absent anchor => nothing is valid);
 *   2. the certificate names this app;
 *   3. spec.json parses, names this app, and hashes to the certificate's specHash,
 *      so the operations that get mounted are exactly the ones that were certified;
 *   4. the capture manifest embedded in the spec hashes to the certificate's
 *      captureManifestHash, so the recorded provenance is the provenance that was
 *      signed (specHash alone excludes the capture timestamp, this does not);
 *   5. the semantic invariants the spec declares are exactly the ones the
 *      certificate certifies, so a mounted connector cannot enforce an invariant
 *      nobody certified, nor silently drop one that was;
 *   6. the adapter hash on the certificate matches the executor configuration the
 *      spec implies, so the thing that will run is the thing that was certified.
 *
 * The certificate also carries `permissionsHash`, but there is deliberately no
 * check for it here. Its only input is `spec.permissions`, which check 3 already
 * covers in full, so a registry-side comparison could never fail when check 3
 * passes - it would be a check that proves nothing while looking like it proves
 * something. The field earns its place as a SIGNED record: it states which
 * capability budget was certified, tamper-evidently (test N19), and lets an
 * external verifier or a replay bundle check that without re-hashing the spec.
 * Widening a connector's permissions is refused by check 3 (test N18).
 * Anything else is skipped, and an older version that does pass is served instead.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { adapterHashOf, issueCertificate, loadTrustAnchor, verifyCertificate } from "./certificate.js";
import { diffSpecs, type SpecDiff } from "./compat.js";
import { specHashOf } from "../spec/derive.js";
import { manifestHash } from "../capture/manifest.js";

export class Registry {
  constructor(private readonly root: string) {
    mkdirSync(root, { recursive: true });
  }

  nextVersion(app: string): number {
    const dir = `${this.root}/${app}`;
    if (!existsSync(dir)) return 1;
    const versions = readdirSync(dir)
      .filter((d) => /^v\d+$/.test(d))
      .map((d) => Number(d.slice(1)));
    return versions.length ? Math.max(...versions) + 1 : 1;
  }

  store(spec: ConnectorSpec, report: CertificationReport, cert: BirthCertificate): string {
    const dir = `${this.root}/${spec.app}/v${cert.version}`;
    mkdirSync(dir, { recursive: true });
    writeFileSync(`${dir}/spec.json`, JSON.stringify(spec, null, 2));
    writeFileSync(`${dir}/report.json`, JSON.stringify(report, null, 2));
    writeFileSync(`${dir}/certificate.json`, JSON.stringify(cert, null, 2));
    return dir;
  }

  /** Latest version whose certificate verifies under the trust anchor and whose spec is bound to it. */
  latest(app: string): { spec: ConnectorSpec; cert: BirthCertificate; dir: string } | null {
    const dir = `${this.root}/${app}`;
    if (!existsSync(dir)) return null;
    const versions = readdirSync(dir)
      .filter((d) => /^v\d+$/.test(d))
      .map((d) => Number(d.slice(1)))
      .sort((a, b) => b - a);
    for (const v of versions) {
      const vdir = `${dir}/v${v}`;
      const loaded = this.load(app, vdir);
      if (loaded) return { ...loaded, dir: vdir };
    }
    return null;
  }

  /** Every version number present on disk, newest first. Includes invalid ones. */
  versions(app: string): number[] {
    const dir = `${this.root}/${app}`;
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((d) => /^v\d+$/.test(d))
      .map((d) => Number(d.slice(1)))
      .sort((a, b) => b - a);
  }

  /**
   * One specific version, subject to every check `latest` applies. This is what
   * keeps a superseded version replayable: rollback and comparison read through
   * exactly the same gate as promotion, never a relaxed one.
   */
  at(app: string, version: number): { spec: ConnectorSpec; cert: BirthCertificate; dir: string } | null {
    const vdir = `${this.root}/${app}/v${version}`;
    if (!existsSync(vdir)) return null;
    const loaded = this.load(app, vdir);
    return loaded ? { ...loaded, dir: vdir } : null;
  }

  /**
   * Certify-then-promote with an explicit compatibility decision.
   *
   * A re-certification that passes says the new spec matches the new evidence.
   * It says nothing about what it breaks for a caller already using the current
   * version, so that question is asked separately and fails closed: anything at
   * or above `conditional` - a narrowed vocabulary, a newly required field, a
   * removed operation, a dropped semantic invariant, or a change this code
   * cannot classify - needs `approve: true` from a caller that has seen the diff.
   */
  promote(
    spec: ConnectorSpec,
    report: CertificationReport,
    opts: { approve?: boolean; approvedBy?: string } = {},
  ): { stored: false; diff: SpecDiff; reason: string } | { stored: true; dir: string; cert: BirthCertificate; diff: SpecDiff | null } {
    const current = this.latest(spec.app);
    const version = this.nextVersion(spec.app);

    if (!current) {
      const cert = issueCertificate(spec, report, version, this.root);
      return { stored: true, dir: this.store(spec, report, cert), cert, diff: null };
    }

    const diff = diffSpecs(current.spec, spec, { from: current.cert.version, to: version });
    if (!diff.autoPromotable && !opts.approve) {
      return {
        stored: false,
        diff,
        reason: `promotion to v${version} is ${diff.overall} and needs explicit approval: ${diff.blockedBy.join("; ")}`,
      };
    }
    const cert = issueCertificate(spec, report, version, this.root, {
      predecessor: { version: current.cert.version, specHash: current.spec.specHash },
      compat: diff.overall,
    });
    return { stored: true, dir: this.store(spec, report, cert), cert, diff };
  }

  list(): { app: string; version: number; tier: string; ops: number; valid: boolean }[] {
    if (!existsSync(this.root)) return [];
    const out: { app: string; version: number; tier: string; ops: number; valid: boolean }[] = [];
    for (const app of readdirSync(this.root)) {
      const appDir = `${this.root}/${app}`;
      let stat;
      try {
        stat = readdirSync(appDir);
      } catch {
        continue;
      }
      for (const v of stat.filter((d) => /^v\d+$/.test(d))) {
        try {
          const cert: BirthCertificate = JSON.parse(readFileSync(`${appDir}/${v}/certificate.json`, "utf8"));
          out.push({
            app,
            version: cert.version,
            tier: cert.tier,
            ops: cert.certifiedOps.length,
            valid: this.load(app, `${appDir}/${v}`) !== null,
          });
        } catch {
          /* skip malformed */
        }
      }
    }
    return out;
  }

  /** The four checks above, or null. Never throws: a malformed artifact is just not served. */
  private load(app: string, vdir: string): { spec: ConnectorSpec; cert: BirthCertificate } | null {
    const anchor = loadTrustAnchor(this.root);
    if (!anchor) return null;
    try {
      const cert: BirthCertificate = JSON.parse(readFileSync(`${vdir}/certificate.json`, "utf8"));
      // `cert.app !== app` is defense-in-depth only: specHash covers the spec's app,
      // so check 3 below already refuses any cross-app replay (see test V5).
      if (cert.app !== app || !verifyCertificate(cert, anchor)) return null;
      const spec: ConnectorSpec = JSON.parse(readFileSync(`${vdir}/spec.json`, "utf8"));
      if (spec.app !== app || spec.specHash !== cert.specHash || specHashOf(spec) !== cert.specHash) return null;
      if (manifestHash(spec.capture) !== cert.captureManifestHash) return null;
      // Integrity between the two artifacts, not an attacker defense: specHash
      // already covers `semanticInvariants`, so an edit to spec.json is caught by
      // check 3. This catches the case check 3 cannot see - a spec and a
      // certificate produced by different paths that disagree about which
      // invariants were certified - and keeps the adapter from being the thing
      // that decides what it passed.
      const declared = (spec.semanticInvariants ?? []).map((i) => i.id).sort();
      const certified = (cert.certifiedInvariants ?? []).map((i) => i.id).sort();
      if (declared.length !== certified.length || declared.some((id, i) => id !== certified[i])) return null;
      if (cert.adapterHash !== adapterHashOf(spec)) return null;
      return { spec, cert };
    } catch {
      return null;
    }
  }
}
