/**
 * End-to-end proof that a certification can be reproduced offline.
 *
 *   pnpm tsx scripts/replay-proof.ts          # live capture from a public, no-auth API
 *   pnpm tsx scripts/replay-proof.ts --offline-capture   # same flow from committed fixtures
 *
 * The last stage is the one that matters: before replaying, global fetch is
 * replaced with a function that throws. If anything in the replay path reached
 * the network, the run fails loudly instead of quietly re-certifying against a
 * live service that may have moved since.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureUrls } from "../src/capture/live.js";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Registry } from "../src/registry/registry.js";
import { loadTrustAnchor } from "../src/registry/certificate.js";
import { buildReplayBundle, readBundle, runBundle, writeBundle } from "../src/replay/bundle.js";
import type { ConnectorSpec, Exchange, SemanticInvariant } from "../src/core/types.js";

const OFFLINE = process.argv.includes("--offline-capture");

const PAGES = (ns: number[]) => ns.map((n) => `https://devpost.com/api/hackathons?page=${n}`);

const INVARIANT: SemanticInvariant = {
  id: "devpost.hackathons.pages-do-not-overlap",
  severity: "blocking",
  kind: "pagination-union",
  op: "get_api_hackathons",
  path: "hackathons",
  idField: "id",
};

function fixtureExchanges(label: string): Exchange[] {
  // A tiny two-page fixture with the same shape, for running with no network at all.
  const page = (n: number, ids: number[]) => ({
    startedDateTime: "2026-09-19T00:00:00Z",
    request: { method: "GET", url: `https://devpost.com/api/hackathons?page=${n}&src=${label}`, headers: [{ name: "Accept", value: "application/json" }], queryString: [] },
    response: {
      status: 200,
      headers: [{ name: "Content-Type", value: "application/json" }],
      content: {
        mimeType: "application/json",
        text: JSON.stringify({
          hackathons: ids.map((i) => ({ id: i, title: `Hack ${i}`, open_state: i % 2 ? "open" : "upcoming", url: `https://x.test/${i}`, submission_period_dates: "Oct 1 - Oct 3, 2026" })),
          meta: { total_count: 999 },
        }),
      },
    },
  });
  const entries = label === "derive" ? [1, 2, 3, 4, 5, 6].map((n) => page(n, [n * 10, n * 10 + 1, n * 10 + 2, n * 10 + 3, n * 10 + 4, n * 10 + 5, n * 10 + 6, n * 10 + 7])) : [7, 8, 9, 10].map((n) => page(n, [n * 10, n * 10 + 1, n * 10 + 2]));
  const p = join(mkdtempSync(join(tmpdir(), "rp-")), `${label}.har`);
  writeFileSync(p, JSON.stringify({ log: { version: "1.2", entries } }));
  return loadHar(p);
}

async function main() {
  const registryDir = mkdtempSync(join(tmpdir(), "replay-proof-reg-"));
  const bundleDir = join(mkdtempSync(join(tmpdir(), "replay-proof-")), "devpost-v1");

  console.log(`1. capture (${OFFLINE ? "committed fixtures" : "live, credential-free, read-only"})`);
  const a = OFFLINE ? fixtureExchanges("derive") : await captureUrls(PAGES([1, 2, 3, 4, 5, 6]), { delayMs: 250 });
  const b = OFFLINE ? fixtureExchanges("holdout") : await captureUrls(PAGES([7, 8, 9, 10]), { delayMs: 250 });
  console.log(`   derive=${a.length} holdout=${b.length} exchanges`);

  console.log("2. derive + certify against the independent holdout");
  const derived = deriveSpec(a, { app: "devpost", tier: "derived-api", host: "devpost.com", captureLabel: "replay-proof", minSamplesForRequired: 4 });
  const spec: ConnectorSpec = { ...derived, semanticInvariants: [INVARIANT] };
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 4 });
  console.log(`   schemaVerdict=${report.schemaVerdict} semanticVerdict=${report.semanticVerdict} certified=${report.certifiedOps.length} mutants=${report.mutation.caught}/${report.mutation.generated}`);
  if (report.certifiedOps.length === 0) throw new Error(`nothing certified: ${JSON.stringify(report.refusedOps)}`);

  console.log("3. promote + sign");
  const reg = new Registry(registryDir);
  const promoted = reg.promote(effectiveSpec, report);
  if (!promoted.stored) throw new Error(promoted.reason);
  console.log(`   v${promoted.cert.version} compat=${promoted.cert.compat} invariants=${promoted.cert.certifiedInvariants.map((i) => i.id).join(",") || "none"}`);

  console.log("4. write a signed replay bundle");
  const bundle = buildReplayBundle({
    kind: "certification",
    spec: effectiveSpec,
    cert: promoted.cert,
    report,
    exchanges: b.filter((e) => e.status === 200 && e.responseBody !== undefined),
    registryDir,
  });
  writeBundle(bundleDir, bundle);
  console.log(`   ${bundleDir} (${bundle.exchanges.length} replay inputs, key ${bundle.signed.keyId})`);

  console.log("5. replay with the network PHYSICALLY DISABLED");
  const realFetch = globalThis.fetch;
  let attempted = 0;
  globalThis.fetch = (() => {
    attempted++;
    throw new Error("network access during replay");
  }) as typeof fetch;
  let result;
  try {
    result = await runBundle(readBundle(bundleDir), loadTrustAnchor(registryDir));
  } finally {
    globalThis.fetch = realFetch;
  }
  console.log(`   network calls attempted: ${attempted}`);
  for (const o of result.ops) console.log(`   ${o.ok ? "ok  " : "FAIL"} ${o.op} (${o.outcome})`);
  for (const w of result.workflows) console.log(`   ${w.pass ? "ok  " : "FAIL"} workflow ${w.id}`);

  if (attempted !== 0) throw new Error("replay touched the network");
  if (!result.verified.ok) throw new Error(`bundle rejected: ${result.verified.failures.join("; ")}`);
  if (!result.reproduced) throw new Error("replay did not reproduce the certified result");
  console.log("\nREPRODUCED offline, zero network calls, manifest verified under the registry trust anchor.");
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
