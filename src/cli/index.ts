#!/usr/bin/env node
/**
 * bridgesmith CLI - the product surface.
 *   bridgesmith forge <app> --derive <url,url> --holdout <url,url> [--host h]
 *       capture two independent slices, derive, certify against holdout, sign,
 *       register. Refuses (non-zero exit) if nothing certifies.
 *   bridgesmith list                 show the connector registry + certificate validity
 *   bridgesmith inspect <app>        show the latest certificate + certified ops
 *   bridgesmith serve <app> [--port] run the REST facade for a certified connector
 *   bridgesmith call <app> <op> [--param k=v ...]   invoke one certified op
 *   bridgesmith bundle <app> --out <dir>   write a signed, offline-replayable bundle
 *   bridgesmith replay <dir>               verify and replay a bundle with NO network
 *   bridgesmith diff <app> <fromV> <toV>   compatibility diff between two certified versions
 */
import { Command } from "commander";
import { captureUrls } from "../capture/live.js";
import { deriveSpec } from "../spec/derive.js";
import { certify } from "../certify/certify.js";
import { issueCertificate } from "../registry/certificate.js";
import { Registry } from "../registry/registry.js";
import { Adapter } from "../codegen/adapter.js";
import { buildRestApp } from "../surfaces/rest.js";
import { buildReplayBundle, bundleAnchor, readBundle, runBundle, writeBundle } from "../replay/bundle.js";
import { diffSpecs, renderDiff } from "../registry/compat.js";
import { loadTrustAnchor } from "../registry/certificate.js";
import { readFileSync } from "node:fs";

const REG_DIR = "connectors";

const program = new Command();
program.name("bridgesmith").description("Manufacture and certify your own app connectors").version("0.1.0");

program
  .command("forge")
  .argument("<app>", "connector name")
  .requiredOption("--derive <urls>", "comma-separated URLs for the derive capture")
  .requiredOption("--holdout <urls>", "comma-separated URLs for the independent holdout capture")
  .option("--host <host>", "restrict to this host")
  .option("--min-required <n>", "confidence floor for required fields", "8")
  .action(async (app: string, opts: { derive: string; holdout: string; host?: string; minRequired: string }) => {
    const minSamplesForRequired = Number.parseInt(opts.minRequired, 10) || 8;
    console.log(`forging "${app}"...`);
    const a = await captureUrls(opts.derive.split(",").map((s) => s.trim()), { delayMs: 300 });
    const b = await captureUrls(opts.holdout.split(",").map((s) => s.trim()), { delayMs: 300 });
    const spec = deriveSpec(a, { app, tier: "derived-api", captureLabel: "forge", minSamplesForRequired, ...(opts.host ? { host: opts.host } : {}) });
    console.log(`  derived ${spec.operations.length} operation(s), specHash=${spec.specHash.slice(0, 12)}`);
    const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired, log: (l) => console.log("  " + l) });
    console.log(`  verdict=${report.verdict} certified=${report.certifiedOps.length} refused=${report.refusedOps.length} mutants=${report.mutation.caught}/${report.mutation.generated}`);
    if (report.verdict === "refused") {
      console.error("REFUSED: no operation certified; nothing mounted.");
      process.exit(1);
    }
    const reg = new Registry(REG_DIR);
    const cert = issueCertificate(effectiveSpec, report, reg.nextVersion(app), REG_DIR);
    const dir = reg.store(effectiveSpec, report, cert);
    console.log(`  ✓ certificate v${cert.version} -> ${dir}`);
  });

program
  .command("list")
  .action(() => {
    const rows = new Registry(REG_DIR).list();
    if (rows.length === 0) return console.log("(no connectors)");
    for (const r of rows) console.log(`${r.valid ? "✓" : "✗"} ${r.app} v${r.version} [${r.tier}] ${r.ops} certified ops`);
  });

program
  .command("inspect")
  .argument("<app>")
  .action((app: string) => {
    const latest = new Registry(REG_DIR).latest(app);
    if (!latest) return console.error(`no valid connector for "${app}"`), process.exit(1);
    console.log(JSON.stringify({ certificate: latest.cert, operations: latest.spec.operations.map((o) => `${o.method} ${o.pathTemplate}`) }, null, 2));
  });

program
  .command("serve")
  .argument("<app>")
  .option("--port <n>", "port", "8787")
  .option("--key <key>", "require this x-bridgesmith-key on /op routes")
  .action((app: string, opts: { port: string; key?: string }) => {
    const latest = new Registry(REG_DIR).latest(app);
    if (!latest) return console.error(`no valid connector for "${app}"`), process.exit(1);
    const restApp = buildRestApp(latest.spec, latest.cert, opts.key ? { apiKey: opts.key } : {});
    const port = Number.parseInt(opts.port, 10);
    restApp.listen(port, () => console.log(`serving ${app} v${latest.cert.version} on http://localhost:${port} (GET /manifest, POST /op/:opId)`));
  });

program
  .command("call")
  .argument("<app>")
  .argument("<op>")
  .option("--param <kv...>", "param as key=value", [])
  .action(async (app: string, op: string, opts: { param: string[] }) => {
    const latest = new Registry(REG_DIR).latest(app);
    if (!latest) return console.error(`no valid connector for "${app}"`), process.exit(1);
    const params = Object.fromEntries(opts.param.map((kv) => { const i = kv.indexOf("="); return [kv.slice(0, i), kv.slice(i + 1)]; }));
    const result = await new Adapter(latest.spec).call(op, params);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exit(1);
  });

program
  .command("bundle")
  .description("write a signed bundle that reproduces this connector's certification offline")
  .argument("<app>")
  .requiredOption("--out <dir>", "directory to write the bundle into")
  .option("--evidence <file>", "JSON array of redacted Exchanges to bundle (defaults to the registry's holdout record)")
  .action((app: string, opts: { out: string; evidence?: string }) => {
    const reg = new Registry(REG_DIR);
    const latest = reg.latest(app);
    if (!latest) return console.error(`no valid connector for "${app}"`), process.exit(1);
    const report = JSON.parse(readFileSync(`${latest.dir}/report.json`, "utf8"));
    if (!opts.evidence) {
      console.error("--evidence is required: a bundle must carry the redacted exchanges it replays");
      process.exit(1);
    }
    const exchanges = JSON.parse(readFileSync(opts.evidence, "utf8"));
    const bundle = buildReplayBundle({ kind: "certification", spec: latest.spec, cert: latest.cert, report, exchanges, registryDir: REG_DIR });
    writeBundle(opts.out, bundle);
    console.log(`bundle written to ${opts.out} (${bundle.exchanges.length} replay inputs, cert v${latest.cert.version})`);
  });

program
  .command("replay")
  .description("verify and replay a bundle offline; makes no network calls")
  .argument("<dir>", "bundle directory")
  .option("--registry <dir>", "registry whose key is the trust anchor", REG_DIR)
  .action(async (dir: string, opts: { registry: string }) => {
    const bundle = readBundle(dir);
    const anchor = bundleAnchor(dir, opts.registry);
    const result = await runBundle(bundle, anchor);
    if (!result.verified.ok) {
      console.error("BUNDLE REJECTED:");
      for (const f of result.verified.failures) console.error(`  - ${f}`);
      process.exit(1);
    }
    console.log(`verified ${bundle.signed.manifest.app} v${bundle.cert.version} (key ${bundle.signed.keyId})`);
    for (const o of result.ops) console.log(`  ${o.ok ? "ok " : "FAIL"} ${o.op} (${o.outcome})${o.detail ? `: ${o.detail}` : ""}`);
    for (const w of result.workflows) console.log(`  ${w.pass ? "ok " : "FAIL"} workflow ${w.id}${w.failure ? `: ${w.failure}` : ""}`);
    console.log(result.reproduced ? "REPRODUCED: every certified result replayed offline" : "NOT REPRODUCED");
    if (!result.reproduced) process.exit(1);
  });

program
  .command("diff")
  .description("compatibility diff between two certified versions")
  .argument("<app>")
  .argument("<from>", "version number")
  .argument("<to>", "version number")
  .action((app: string, from: string, to: string) => {
    const reg = new Registry(REG_DIR);
    const a = reg.at(app, Number.parseInt(from, 10));
    const b = reg.at(app, Number.parseInt(to, 10));
    if (!a || !b) return console.error("one or both versions are missing or fail verification"), process.exit(1);
    const d = diffSpecs(a.spec, b.spec, { from: a.cert.version, to: b.cert.version });
    console.log(renderDiff(d));
    if (!d.autoPromotable) process.exit(2);
  });

void loadTrustAnchor;

program.parseAsync().catch((e) => { console.error(e.message); process.exit(1); });
