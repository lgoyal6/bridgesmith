import { describe, it, expect, beforeAll } from "vitest";
import { execa } from "execa";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureLocal, localFetcher } from "../src/drivers/localstore.js";
import { IMESSAGE_OPS, IMESSAGE_ORIGIN } from "../src/drivers/imessage.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";

/**
 * Builds a synthetic chat.db with Apple's real table shape (message, handle),
 * so the local-store tier is exercised end-to-end without reading real iMessage
 * data. Two independent inserts give us derive (A) and holdout (B) slices.
 */
function buildChatDb(dir: string, n: number, seed: number): string {
  const db = join(dir, `chat-${seed}.db`);
  const contacts = ["+15551234567", "alice@example.com", "+15559876543", "bob@example.com"];
  const rows: string[] = [];
  rows.push(`CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);`);
  rows.push(`CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, is_from_me INTEGER, text TEXT, date INTEGER);`);
  contacts.forEach((c, i) => rows.push(`INSERT INTO handle VALUES (${i + 1}, '${c}');`));
  for (let i = 0; i < n; i++) {
    const handle = (i % contacts.length) + 1;
    const fromMe = (i + seed) % 2;
    const date = (1_700_000_000 - 978307200 + i * 60 + seed * 3600) * 1_000_000_000;
    rows.push(`INSERT INTO message (handle_id, is_from_me, text, date) VALUES (${handle}, ${fromMe}, 'msg ${seed}-${i}', ${date});`);
  }
  const sqlFile = join(dir, `seed-${seed}.sql`);
  writeFileSync(sqlFile, rows.join("\n"));
  return db;
}

describe("local-store tier (iMessage-shaped synthetic db)", () => {
  let dir: string;
  let dbA: string;
  let dbB: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "imsg-"));
    dbA = buildChatDb(dir, 25, 1);
    dbB = buildChatDb(dir, 15, 2);
    // Apply schema+data via the sqlite3 CLI (same tool the driver uses).
    await execa("sqlite3", [dbA], { input: `.read ${join(dir, "seed-1.sql")}` });
    await execa("sqlite3", [dbB], { input: `.read ${join(dir, "seed-2.sql")}` });
  });

  it("captures, derives, certifies, and serves local SQL as a connector", async () => {
    const a = await captureLocal(dbA, IMESSAGE_OPS, IMESSAGE_ORIGIN);
    expect(a.length).toBe(IMESSAGE_OPS.length);

    const spec = deriveSpec(a, { app: "imessage", tier: "local-store", captureLabel: "A", minSamplesForRequired: 1 });
    // baseUrl derivation uses origin; local:// has no host filter needed
    expect(spec.operations.length).toBe(2);

    const b = await captureLocal(dbB, IMESSAGE_OPS, IMESSAGE_ORIGIN);
    const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 1 });
    expect(report.verdict).not.toBe("refused");
    expect(report.certifiedOps.length).toBe(2);

    // Serve it: the adapter answers via the local fetcher against db A.
    const adapter = new Adapter(effectiveSpec, { fetcher: localFetcher(dbA, IMESSAGE_OPS) });
    const recent = await adapter.call("get_recent_messages", { limit: "5" });
    expect(recent.ok).toBe(true);
    const data = recent.data as { rows: unknown[] };
    expect(Array.isArray(data.rows)).toBe(true);
    expect(data.rows.length).toBe(5);
  });
});
