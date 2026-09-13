/**
 * Reproducible eval: runs the full pipeline against real connectors and prints
 * the reliability table (the numbers cited in the brief). Includes a runtime
 * generalization probe on UNSEEN inputs -> the false-green rate. No secrets.
 * Run: pnpm tsx .agent-work/eval.ts
 */
import { captureUrls } from "../src/capture/live.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { ConnectorMonitor } from "../src/runtime/breaker.js";
import type { Exchange } from "../src/core/types.js";

interface Target {
  app: string;
  host: string;
  derive: string[];
  holdout: string[];
  probe: { op?: string; params: Record<string, string> }[]; // unseen inputs
  minReq: number;
}

const TARGETS: Target[] = [
  {
    app: "chesscom",
    host: "chess.com",
    derive: ["magnuscarlsen", "hikaru", "fabianocaruana", "gothamchess", "anishgiri", "danielnaroditsky", "vishyanand", "wesley_so", "lachesisq", "levonaronian"].map((p) => `https://api.chess.com/pub/player/${p}`),
    holdout: ["chessbrah", "gmwso", "nihalsarin2004", "firouzja2003", "lyonbeast", "rpragchess", "polish_fighter3000", "chesswarrior7197"].map((p) => `https://api.chess.com/pub/player/${p}`),
    probe: ["levyrozman", "nemsko", "ghandeevam2003", "cutemouse83"].map((p) => ({ params: { player_id: p } })),
    minReq: 8,
  },
  {
    app: "devpost",
    host: "devpost.com",
    derive: [1, 2, 3, 4, 5, 6].map((n) => `https://devpost.com/api/hackathons?page=${n}`),
    holdout: [7, 8, 9, 10].map((n) => `https://devpost.com/api/hackathons?page=${n}`),
    probe: [11, 12, 13, 14, 15].map((n) => ({ params: { page: String(n) } })),
    minReq: 4,
  },
];

async function run(t: Target) {
  const a = await captureUrls(t.derive, { delayMs: 250 });
  const b = await captureUrls(t.holdout, { delayMs: 250 });
  const spec = deriveSpec(a, { app: t.app, tier: "derived-api", host: t.host, captureLabel: "eval", minSamplesForRequired: t.minReq });
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: t.minReq });

  const monitor = new ConnectorMonitor(new Set(report.certifiedOps));
  const adapter = new Adapter(effectiveSpec, { onTrace: () => {} });
  const opId = report.certifiedOps[0]!;
  let probeOk = 0;
  for (const p of t.probe) {
    const r = await adapter.call(opId, p.params);
    monitor.record(opId, r);
    if (r.ok) probeOk++;
  }
  const fg = monitor.falseGreenRate();
  return {
    app: t.app,
    tier: effectiveSpec.tier,
    ops: effectiveSpec.operations.length,
    certified: report.certifiedOps.length,
    refused: report.refusedOps.length,
    uncovered: report.uncoveredOps.length,
    holdout: b.length,
    mutants: `${report.mutation.caught}/${report.mutation.generated}`,
    probe: `${probeOk}/${t.probe.length}`,
    falseGreen: `${(fg.rate * 100).toFixed(0)}% (${fg.falseGreen}/${fg.certified})`,
  };
}

const main = async () => {
  const rows: Awaited<ReturnType<typeof run>>[] = [];
  for (const t of TARGETS) {
    process.stderr.write(`evaluating ${t.app}...\n`);
    rows.push(await run(t));
  }
  console.log("\n| Connector | Tier | Ops | Certified | Refused | Uncovered | Holdout samples | Mutants caught | Unseen-input probe | False-green rate |");
  console.log("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of rows) {
    console.log(`| ${r.app} | ${r.tier} | ${r.ops} | ${r.certified} | ${r.refused} | ${r.uncovered} | ${r.holdout} | ${r.mutants} | ${r.probe} | ${r.falseGreen} |`);
  }
};

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
