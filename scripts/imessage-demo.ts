/**
 * Local-store tier demo: give iMessage — an app with no network API — a
 * certified connector, read-only, from its SQLite database. Uses a small
 * generated sample DB so it runs anywhere (no real messages, no credentials).
 * Run: pnpm tsx scripts/imessage-demo.ts
 */
import { execa } from "execa";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureLocal, localFetcher, runSqliteJson } from "../src/drivers/localstore.js";
import { IMESSAGE_OPS } from "../src/drivers/imessage.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";

const ORIGIN = "http://imessage.local";
const G = "\x1b[38;5;215m", C = "\x1b[38;5;79m", OK = "\x1b[38;5;79m", D = "\x1b[2m", B = "\x1b[1m", R = "\x1b[0m";

async function makeSampleDb(): Promise<string> {
  const db = join(mkdtempSync(join(tmpdir(), "imsg-")), "chat.db");
  const rows: string[] = [
    "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);",
    "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, is_from_me INTEGER, text TEXT, date INTEGER);",
  ];
  const contacts = 34;
  for (let i = 1; i <= contacts; i++) rows.push(`INSERT INTO handle VALUES (${i}, '+1555${1000000 + i}');`);
  let rid = 0;
  for (let i = 1; i <= contacts; i++) {
    const n = 15 + ((i * 7) % 40);
    for (let j = 0; j < n; j++) rows.push(`INSERT INTO message (handle_id,is_from_me,text,date) VALUES (${i}, ${rid % 2}, '[sample]', ${++rid * 1000000000});`);
  }
  await execa("sqlite3", [db], { input: rows.join("\n") });
  return db;
}

const main = async () => {
  const db = await makeSampleDb();
  process.stdout.write(`${D}sample database (no real messages) …${R}\n`);
  const a = await captureLocal(db, IMESSAGE_OPS, ORIGIN);
  const spec = deriveSpec(a, { app: "imessage", tier: "local-store", captureLabel: "A", minSamplesForRequired: 1 });
  const b = await captureLocal(db, IMESSAGE_OPS, ORIGIN);
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 1 });

  const reg = new Registry("connectors");
  const cert = issueCertificate(effectiveSpec, report, reg.nextVersion("imessage"), "connectors");
  reg.store(effectiveSpec, report, cert);
  process.stdout.write(`${OK}  CERTIFY ${report.certifiedOps.join(", ")}  ·  ${report.mutation.caught}/${report.mutation.generated} mutants caught${R}\n`);
  process.stdout.write(`${G}  ✓ birth certificate v${cert.version}  →  connectors/imessage/v${cert.version}  (local-store, read-only, ed25519 signed)${R}\n\n`);

  const adapter = new Adapter(effectiveSpec, { fetcher: localFetcher(db, IMESSAGE_OPS) });
  const recent = await adapter.call("get_recent_messages", { limit: "3" });
  const ok = recent.ok ? "ok" : recent.outcome;
  process.stdout.write(`${D}  call get_recent_messages(limit=3) → ${ok}, schema-validated${R}\n`);
  const totals = (await runSqliteJson(db, "SELECT count(*) AS m, count(DISTINCT handle_id) AS c FROM message"))[0] as { m: number; c: number };
  process.stdout.write(`${B}  aggregate (no message content): ${totals.m} messages across ${totals.c} contacts${R}\n`);
};

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
