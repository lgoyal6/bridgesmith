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
import type { Exchange, SemanticInvariant } from "../src/core/types.js";

interface Target {
  app: string;
  host: string;
  derive: string[];
  holdout: string[];
  probe: { op?: string; params: Record<string, string> }[]; // unseen inputs
  minReq: number;
  /** Declared semantic invariants. Absent means this connector is certified shape-only. */
  invariants?: SemanticInvariant[];
}

const TARGETS: Target[] = [
  {
    app: "chesscom",
    host: "chess.com",
    derive: ["magnuscarlsen", "hikaru", "fabianocaruana", "gothamchess", "anishgiri", "danielnaroditsky", "vishyanand", "wesley_so", "lachesisq", "levonaronian"].map((p) => `https://api.chess.com/pub/player/${p}`),
    holdout: ["chessbrah", "gmwso", "nihalsarin2004", "firouzja2003", "lyonbeast", "rpragchess", "polish_fighter3000", "chesswarrior7197"].map((p) => `https://api.chess.com/pub/player/${p}`),
    probe: ["levyrozman", "nemsko", "ghandeevam2003", "cutemouse83"].map((p) => ({ params: { player_id: p } })),
    minReq: 8,
    invariants: [
      {
        id: "chesscom.player.status-vocabulary",
        severity: "blocking",
        kind: "enum-consistency",
        field: "status",
        allowed: ["basic", "premium", "staff", "mod", "closed", "closed:fair_play_violations", "closed:abuse", "closed:disabled"],
        sources: [{ op: "get_pub_player_player_id", path: "$" }],
      },
    ],
  },
  {
    app: "devpost",
    host: "devpost.com",
    derive: [1, 2, 3, 4, 5, 6].map((n) => `https://devpost.com/api/hackathons?page=${n}`),
    holdout: [7, 8, 9, 10].map((n) => `https://devpost.com/api/hackathons?page=${n}`),
    probe: [11, 12, 13, 14, 15].map((n) => ({ params: { page: String(n) } })),
    minReq: 4,
    invariants: [
      {
        id: "devpost.hackathons.pages-do-not-overlap",
        severity: "blocking",
        kind: "pagination-union",
        op: "get_api_hackathons",
        path: "hackathons",
        idField: "id",
      },
    ],
  },
];

async function run(t: Target) {
  const a = await captureUrls(t.derive, { delayMs: 250 });
  const b = await captureUrls(t.holdout, { delayMs: 250 });
  const derived = deriveSpec(a, { app: t.app, tier: "derived-api", host: t.host, captureLabel: "eval", minSamplesForRequired: t.minReq });
  const spec = t.invariants ? { ...derived, semanticInvariants: t.invariants } : derived;
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
  const pct = (n: number) => `${(n * 100).toFixed(0)}%`;
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
    schemaVerdict: report.schemaVerdict,
    semanticVerdict: report.semanticVerdict,
    invariants: report.semantic.length ? `${report.semantic.filter((c) => c.pass).length}/${report.semantic.length}` : "none declared",
    // The two false-green axes are reported SEPARATELY and never summed. A
    // connector with no declared invariants has no semantic axis to report, which
    // is a statement about coverage, not a clean bill of health.
    schemaFalseGreen: `${pct(fg.rate)} (${fg.falseGreen}/${fg.certified})`,
    semanticFalseGreen: report.semantic.length ? `${pct(fg.semanticRate)} (${fg.semanticFalseGreen}/${fg.certified})` : "n/a",
  };
}

const main = async () => {
  const rows: Awaited<ReturnType<typeof run>>[] = [];
  for (const t of TARGETS) {
    process.stderr.write(`evaluating ${t.app}...\n`);
    rows.push(await run(t));
  }
  console.log("\n| Connector | Tier | Ops | Certified | Refused | Uncovered | Holdout samples | Mutants caught | Unseen-input probe | Schema verdict | Semantic verdict | Invariants held | Schema false-green | Semantic false-green |");
  console.log("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const r of rows) {
    console.log(
      `| ${r.app} | ${r.tier} | ${r.ops} | ${r.certified} | ${r.refused} | ${r.uncovered} | ${r.holdout} | ${r.mutants} | ${r.probe} | ${r.schemaVerdict} | ${r.semanticVerdict} | ${r.invariants} | ${r.schemaFalseGreen} | ${r.semanticFalseGreen} |`,
    );
  }
};

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
