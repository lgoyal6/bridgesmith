/**
 * Second real target: Devpost public hackathons API (public JSON, no auth).
 * Capture A = page 1, capture B (holdout) = page 2 (independent slice). Derive,
 * certify, mount, and emit a real result the orchestrator writes to Notion.
 * Run: pnpm tsx .agent-work/devpost-proof.ts
 */
import { captureUrls } from "../src/capture/live.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import { writeFileSync } from "node:fs";

const base = "https://devpost.com/api/hackathons";

const main = async () => {
  // Two independent slices of the same endpoint shape.
  console.log("== capture A (page 1) + B (page 2) ==");
  const a = await captureUrls([`${base}?page=1`, `${base}?page=2`], { delayMs: 400 });
  const b = await captureUrls([`${base}?page=3`, `${base}?page=4`], { delayMs: 400 });
  console.log(a.concat(b).map((e) => `${e.status} ${e.path}?${new URLSearchParams(e.query)}`).join("\n"));

  console.log("\n== derive ==");
  const spec = deriveSpec(a, { app: "devpost", tier: "derived-api", host: "devpost.com", captureLabel: "page1-2", minSamplesForRequired: 2 });
  console.log(`baseUrl=${spec.baseUrl} ops=${spec.operations.length} specHash=${spec.specHash.slice(0, 12)}`);
  for (const op of spec.operations) {
    const arr = op.responseSchema.properties?.["hackathons"];
    console.log(`  ${op.method} ${op.pathTemplate} required=[${(op.responseSchema.required ?? []).join(",")}] listItemFields=${arr?.items?.properties ? Object.keys(arr.items.properties).length : "n/a"}`);
  }

  console.log("\n== certify against holdout ==");
  const { report, effectiveSpec } = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 2, log: (l) => console.log("  " + l) });
  console.log(`verdict=${report.verdict} certified=${report.certifiedOps.length} mutation=${report.mutation.caught}/${report.mutation.generated}`);

  console.log("\n== sign + register ==");
  const reg = new Registry("connectors");
  const cert = issueCertificate(effectiveSpec, report, reg.nextVersion("devpost"), "connectors");
  const dir = reg.store(effectiveSpec, report, cert);
  console.log(`  certificate v${cert.version} stored at ${dir}`);

  console.log("\n== mount + live call ==");
  const adapter = new Adapter(effectiveSpec, { onTrace: (t) => console.log(`  trace: ${t.op} ${t.outcome} ${t.status ?? ""} ${t.ms}ms`) });
  const listOp = effectiveSpec.operations.find((o) => !o.pathTemplate.includes("{"))!;
  const result = await adapter.call(listOp.id, { page: "5" });
  if (!result.ok) {
    console.log(`  FAILED: ${result.outcome} ${result.error}`);
    process.exit(1);
  }
  const data = result.data as { hackathons?: { title: string; submission_period_dates?: string; prize_amount?: string }[] };
  const list = (data.hackathons ?? []).slice(0, 8).map((h) => ({
    title: h.title,
    dates: h.submission_period_dates ?? "",
    prize: (h.prize_amount ?? "").replace(/<[^>]+>/g, ""),
  }));
  console.log(`  got ${data.hackathons?.length ?? 0} hackathons; sample:`);
  for (const h of list.slice(0, 5)) console.log(`   - ${h.title} (${h.dates})`);

  // Emit a result artifact for the orchestrator (Claude) to write into Notion.
  writeFileSync(".agent-work/devpost-result.json", JSON.stringify({ certifiedOps: report.certifiedOps, specHash: spec.specHash, hackathons: list }, null, 2));
  console.log("\n  wrote .agent-work/devpost-result.json for the Notion write step");
};

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
