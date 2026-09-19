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
 *      so the operations that get mounted are exactly the ones that were certified.
 * Anything else is skipped, and an older version that does pass is served instead.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { loadTrustAnchor, verifyCertificate } from "./certificate.js";
import { specHashOf } from "../spec/derive.js";

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

  /** The three checks above, or null. Never throws: a malformed artifact is just not served. */
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
      return { spec, cert };
    } catch {
      return null;
    }
  }
}
