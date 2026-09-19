import { describe, it, expect } from "vitest";
import { execa } from "execa";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LocalOp } from "../src/drivers/localstore.js";
import { captureLocal, localFetcher } from "../src/drivers/localstore.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { ConnectorManager, type HealEvent } from "../src/runtime/selfheal.js";

const ORIGIN = "http://w.local";
// Derive and holdout must be INDEPENDENT slices of the store, so they are taken
// with different limits and therefore different row sets. Taking both with the
// same params makes the holdout a copy of the derive capture, and certify()
// refuses that as circular.
const DERIVE_PARAMS = { list: { limit: "20" } };
const HOLDOUT_PARAMS = { list: { limit: "7" } };
const OPS: LocalOp[] = [
  { id: "list", path: "/w", params: [{ name: "limit", default: "20" }], sql: (p) => `SELECT id, price FROM w LIMIT ${Number.parseInt(p.limit ?? "20", 10) || 20}` },
];

async function seed(db: string, priceType: "REAL" | "TEXT", n: number) {
  await execa("sqlite3", [db], {
    input: `DROP TABLE IF EXISTS w; CREATE TABLE w (id INTEGER PRIMARY KEY, price ${priceType});
${Array.from({ length: n }, (_, i) => `INSERT INTO w VALUES (${i + 1}, ${priceType === "REAL" ? 1.5 + i : `'$${i}'`});`).join("\n")}`,
  });
}

describe("self-heal", () => {
  it("hot-swaps on certifiable drift and demotes on uncertifiable drift", async () => {
    const dir = mkdtempSync(join(tmpdir(), "heal-"));
    const db = join(dir, "w.db");
    await seed(db, "REAL", 20);
    const a = await captureLocal(db, OPS, ORIGIN, DERIVE_PARAMS);
    const spec = deriveSpec(a, { app: "w", tier: "local-store", captureLabel: "A", minSamplesForRequired: 5 });
    const { report, effectiveSpec } = await certify(spec, await captureLocal(db, OPS, ORIGIN, HOLDOUT_PARAMS), { deriveExchanges: a, minSamplesForRequired: 5 });
    const cert = issueCertificate(effectiveSpec, report, 1, join(dir, "reg"));

    const events: HealEvent[] = [];
    const mgr = new ConnectorManager(
      effectiveSpec, cert,
      { recapture: () => captureLocal(db, OPS, ORIGIN, DERIVE_PARAMS), recaptureHoldout: () => captureLocal(db, OPS, ORIGIN, HOLDOUT_PARAMS), fetcher: localFetcher(db, OPS), deriveOpts: { app: "w", tier: "local-store", minSamplesForRequired: 5 }, registryDir: join(dir, "reg") },
      (e) => events.push(e),
    );

    expect((await mgr.call("get_w", { limit: "5" })).ok).toBe(true);

    // certifiable drift
    await seed(db, "TEXT", 20);
    for (let i = 0; i < 3; i++) await mgr.call("get_w", { limit: "5" });
    await mgr.settle();
    expect(mgr.version).toBe(2);
    expect(events.some((e) => e.t === "hot-swap")).toBe(true);
    expect((await mgr.call("get_w", { limit: "5" })).ok).toBe(true);

    // uncertifiable drift
    await execa("sqlite3", [db], { input: "DROP TABLE w;" });
    for (let i = 0; i < 3; i++) await mgr.call("get_w", { limit: "5" });
    await mgr.settle();
    expect(mgr.isDemoted).toBe(true);
    const dead = await mgr.call("get_w", { limit: "5" });
    expect(dead.ok).toBe(false);
    expect(dead.outcome).toBe("refused");
  });
});
