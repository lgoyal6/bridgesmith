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
 */
import { Command } from "commander";
import { captureUrls } from "../capture/live.js";
import { deriveSpec } from "../spec/derive.js";
import { certify } from "../certify/certify.js";
import { issueCertificate } from "../registry/certificate.js";
import { Registry } from "../registry/registry.js";
import { Adapter } from "../codegen/adapter.js";
import { buildRestApp } from "../surfaces/rest.js";

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

program.parseAsync().catch((e) => { console.error(e.message); process.exit(1); });
