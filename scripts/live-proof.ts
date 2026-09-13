/**
 * Kill-condition proof on REAL traffic: Chess.com public API (zero auth, public
 * data). Capture A (one set of players) derives the spec; capture B (a DIFFERENT
 * set of players) is the holdout. Then mount and make a live call.
 * Run: pnpm tsx .agent-work/live-proof.ts
 */
import { captureUrls } from "../src/capture/live.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import type { OperationSpec } from "../src/core/types.js";

// Capture A and B are INDEPENDENT sets of real players. Enough samples that
// `required` inference is meaningful (confidence floor = 8).
const A = [
  "magnuscarlsen", "hikaru", "fabianocaruana", "gothamchess", "anishgiri",
  "danielnaroditsky", "vishyanand", "wesley_so", "lachesisq", "levonaronian",
].map((p) => `https://api.chess.com/pub/player/${p}`);
const B = [
  "chesswarrior7197", "chessbrah", "gmwso", "polish_fighter3000", "nihalsarin2004",
  "firouzja2003", "lyonbeast", "rpragchess",
].map((p) => `https://api.chess.com/pub/player/${p}`);

const main = async () => {
  console.log("== capture A (derive) ==");
  const a = await captureUrls(A, { delayMs: 300 });
  console.log(a.map((e) => `${e.status} ${e.path}`).join("\n"));

  console.log("\n== derive spec ==");
  const spec = deriveSpec(a, { app: "chesscom", tier: "derived-api", host: "chess.com", captureLabel: "A" });
  console.log(`baseUrl=${spec.baseUrl} specHash=${spec.specHash.slice(0, 12)} ops=${spec.operations.length}`);
  for (const op of spec.operations) console.log(`  ${op.method} ${op.pathTemplate}  (${op.samples} samples, ${op.responseSchema.required?.length ?? 0} required fields)`);

  console.log("\n== capture B (holdout) ==");
  const b = await captureUrls(B, { delayMs: 300 });

  console.log("\n== certify against holdout ==");
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, log: (l) => console.log("  " + l) });
  console.log(`verdict=${report.verdict} certified=${report.certifiedOps.length} refused=${report.refusedOps.length} uncovered=${report.uncoveredOps.length}`);
  console.log(`mutation: ${report.mutation.caught}/${report.mutation.generated} caught`);

  console.log("\n== mount + live call (real, unseen player) ==");
  const adapter = new Adapter(effectiveSpec, { onTrace: (t) => console.log(`  trace: ${t.op} ${t.outcome} ${t.status ?? ""} ${t.ms}ms`) });
  const opId = (effectiveSpec.operations.find((o: OperationSpec) => o.pathTemplate.includes("{")) ?? effectiveSpec.operations[0])!.id;
  const paramName = effectiveSpec.operations.find((o) => o.id === opId)!.pathParams[0] ?? "player_id";
  const result = await adapter.call(opId, { [paramName]: "levyrozman" });
  console.log(`  call ${opId}: ok=${result.ok} outcome=${result.outcome}`);
  if (result.ok) {
    const d = result.data as Record<string, unknown>;
    console.log(`  -> username=${d["username"]} followers=${d["followers"]} country=${(d["country"] as string ?? "").split("/").pop()}`);
  } else {
    console.log(`  -> error: ${result.error}`);
  }

  console.log("\n== negative control: feed it garbage, expect schema-violation ==");
  const badAdapter = new Adapter(effectiveSpec, {
    fetcher: async () => ({ status: 200, headers: { get: () => "application/json" }, json: async () => ({ nonsense: true }), text: async () => "" }),
    onTrace: (t) => console.log(`  trace: ${t.op} ${t.outcome}`),
  });
  const bad = await badAdapter.call(opId, { [paramName]: "levyrozman" });
  console.log(`  garbage call: ok=${bad.ok} outcome=${bad.outcome} (expected ok=false schema-violation)`);
};

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
