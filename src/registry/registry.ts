/**
 * On-disk connector registry. Each certified connector version is a directory:
 *   connectors/<app>/v<N>/{spec.json, certificate.json, report.json}
 * Uncertified attempts are never written here (refusal leaves no artifact to
 * accidentally mount).
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import type { BirthCertificate, CertificationReport, ConnectorSpec } from "../core/types.js";
import { verifyCertificate } from "./certificate.js";

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

  /** Latest certified version whose certificate signature still verifies. */
  latest(app: string): { spec: ConnectorSpec; cert: BirthCertificate; dir: string } | null {
    const dir = `${this.root}/${app}`;
    if (!existsSync(dir)) return null;
    const versions = readdirSync(dir)
      .filter((d) => /^v\d+$/.test(d))
      .map((d) => Number(d.slice(1)))
      .sort((a, b) => b - a);
    for (const v of versions) {
      const vdir = `${dir}/v${v}`;
      const cert: BirthCertificate = JSON.parse(readFileSync(`${vdir}/certificate.json`, "utf8"));
      if (verifyCertificate(cert)) {
        const spec: ConnectorSpec = JSON.parse(readFileSync(`${vdir}/spec.json`, "utf8"));
        return { spec, cert, dir: vdir };
      }
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
            valid: verifyCertificate(cert),
          });
        } catch {
          /* skip malformed */
        }
      }
    }
    return out;
  }
}
