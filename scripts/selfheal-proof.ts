/**
 * Self-heal timeline on REAL drift. We mount a local-store connector over a
 * synthetic SQLite db, serve it green, then MUTATE the db so a certified op
 * starts returning a differently-typed field (real drift). The breaker trips,
 * the manager re-captures + re-certifies against the drifted shape, hot-swaps,
 * and serving resumes - all unattended. Then we induce UNCERTIFIABLE drift
 * (drop the table) and show it DEMOTE and refuse rather than serve garbage.
 * Run: pnpm tsx .agent-work/selfheal-proof.ts
 */
import { execa } from "execa";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LocalOp } from "../src/drivers/localstore.js";
import { captureLocal, localFetcher } from "../src/drivers/localstore.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { ConnectorManager, type HealEvent } from "../src/runtime/selfheal.js";

const ORIGIN = "http://widgets.local";
const OPS: LocalOp[] = [
  { id: "list_widgets", path: "/widgets", params: [{ name: "limit", default: "20" }],
    sql: (p) => `SELECT id, name, price, in_stock FROM widget LIMIT ${Number.parseInt(p.limit ?? "20", 10) || 20}` },
];

async function sql(db: string, statements: string) {
  await execa("sqlite3", [db], { input: statements });
}

async function seed(db: string, priceType: "REAL" | "TEXT", n: number, tag: string) {
  await sql(db, `DROP TABLE IF EXISTS widget;
CREATE TABLE widget (id INTEGER PRIMARY KEY, name TEXT, price ${priceType}, in_stock INTEGER);
${Array.from({ length: n }, (_, i) => `INSERT INTO widget VALUES (${i + 1}, 'w-${tag}-${i}', ${priceType === "REAL" ? (9.99 + i) : `'$${9 + i}.99'`}, ${i % 2});`).join("\n")}`);
}

const line = (e: HealEvent) => {
  const map: Record<HealEvent["t"], string> = {
    mounted: "🟢 MOUNTED", call: "  ·", "breaker-open": "🔴 BREAKER OPEN", recapture: "🔁 RE-CAPTURE",
    recertify: "🧪 RE-CERTIFY", "hot-swap": "♻️  HOT-SWAP", demoted: "⛔ DEMOTED",
  };
  const extra =
    e.t === "call" ? `${e.op} ${e.ok ? "ok" : "FAIL:" + e.outcome}` :
    e.t === "mounted" ? `v${e.version} (${e.certifiedOps} ops)` :
    e.t === "recertify" ? `verdict=${e.verdict} ops=${e.certifiedOps}` :
    e.t === "hot-swap" ? `v${e.fromVersion} → v${e.toVersion}` :
    e.t === "demoted" ? e.reason : e.t === "breaker-open" ? `after ${e.consecutive} failures` : "";
  console.log(`${map[e.t]} ${extra}`);
};

const main = async () => {
  const dir = mkdtempSync(join(tmpdir(), "heal-"));
  const db = join(dir, "widgets.db");
  const registryDir = join(dir, "registry");

  // Initial: price is REAL (numeric).
  await seed(db, "REAL", 20, "A");
  const a = await captureLocal(db, OPS, ORIGIN);
  const spec = deriveSpec(a, { app: "widgets", tier: "local-store", captureLabel: "A", minSamplesForRequired: 5 });
  const b = await captureLocal(db, OPS, ORIGIN);
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 5 });
  const cert = issueCertificate(effectiveSpec, report, 1, registryDir);
  console.log(`initial certification: verdict=${report.verdict}, price typed as ${JSON.stringify(effectiveSpec.operations[0]!.responseSchema.properties?.rows?.items?.properties?.price?.type)}\n`);

  const mgr = new ConnectorManager(
    effectiveSpec, cert,
    {
      recapture: () => captureLocal(db, OPS, ORIGIN),
      recaptureHoldout: () => captureLocal(db, OPS, ORIGIN),
      fetcher: localFetcher(db, OPS),
      deriveOpts: { app: "widgets", tier: "local-store", minSamplesForRequired: 5 },
      registryDir,
    },
    line,
  );

  console.log("\n-- serving green --");
  for (let i = 0; i < 2; i++) await mgr.call("get_widgets", { limit: "5" });

  console.log("\n-- upstream drifts: price REAL → TEXT (real schema change) --");
  await seed(db, "TEXT", 20, "B");
  for (let i = 0; i < 3; i++) await mgr.call("get_widgets", { limit: "5" }); // trips breaker
  await mgr.settle();

  console.log("\n-- serving again post-heal --");
  const after = await mgr.call("get_widgets", { limit: "5" });
  console.log(`  post-heal call ok=${after.ok}, connector now v${mgr.version}`);

  console.log("\n-- uncertifiable drift: table dropped --");
  await sql(db, "DROP TABLE widget;");
  for (let i = 0; i < 3; i++) await mgr.call("get_widgets", { limit: "5" });
  await mgr.settle();
  const dead = await mgr.call("get_widgets", { limit: "5" });
  console.log(`  after uncertifiable drift: demoted=${mgr.isDemoted}, call ok=${dead.ok} outcome=${dead.outcome}`);

  rmSync(dir, { recursive: true, force: true });
};

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
