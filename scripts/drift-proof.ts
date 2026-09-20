/**
 * Two drift incidents, end to end: detection -> incident bundle -> offline
 * replay -> corrected certification.
 *
 *   pnpm tsx scripts/drift-proof.ts
 *
 * One is a SCHEMA drift (the response stops having the certified shape) and one
 * is a SEMANTIC false green (the shape is still perfect and a certified
 * invariant stops holding). They are reported on separate axes throughout,
 * because the whole point is that a shape-only gate reports the second as a
 * clean bill of health.
 *
 * Every number printed is measured in this run. The timings are a local,
 * scripted exercise against replayed fixtures - they are detection latency
 * inside this process, and nothing here is a production mean-time-to-recovery.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { Adapter } from "../src/codegen/adapter.js";
import { ConnectorMonitor } from "../src/runtime/breaker.js";
import { Registry } from "../src/registry/registry.js";
import { loadTrustAnchor } from "../src/registry/certificate.js";
import { replayFetcher } from "../src/certify/replay.js";
import { readBundle, runBundle, writeBundle } from "../src/replay/bundle.js";
import { buildIncident, classifyDrift } from "../src/observe/incident.js";
import { ATTR, assertNoPayload, Tracer } from "../src/observe/trace.js";
import type { ConnectorSpec, Exchange, SemanticInvariant } from "../src/core/types.js";

const INVARIANT: SemanticInvariant = {
  id: "events.list.total-matches",
  severity: "blocking",
  kind: "total-matches",
  op: "get_api_events",
  path: "events",
  totalPath: "total",
};

/* ---- fixtures: a tiny events API, captured twice ---- */
const evt = (n: number) => ({
  id: `evt_${1000 + n}`,
  title: `Event ${n}`,
  status: n % 3 === 0 ? "cancelled" : "published",
  startDate: `2026-09-${String((n % 27) + 1).padStart(2, "0")}T18:00:00Z`,
  capacity: 50 + n,
});
const entry = (url: string, body: unknown) => ({
  startedDateTime: "2026-09-19T10:00:00Z",
  request: { method: "GET", url, headers: [{ name: "Accept", value: "application/json" }], queryString: [] },
  response: { status: 200, headers: [{ name: "Content-Type", value: "application/json" }], content: { mimeType: "application/json", text: JSON.stringify(body) } },
});
const BASE = "https://api.example-events.com";
function har(entries: unknown[]): Exchange[] {
  const p = join(mkdtempSync(join(tmpdir(), "drift-")), "c.har");
  writeFileSync(p, JSON.stringify({ log: { version: "1.2", entries } }));
  return loadHar(p);
}
const deriveCapture = () =>
  har([
    ...[1, 2, 3, 4, 5].map((n) => entry(`${BASE}/api/events?limit=3&page=${n}`, { events: [evt(n), evt(n + 10), evt(n + 20)], total: 3 })),
    ...[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => entry(`${BASE}/api/events/evt_${1000 + n}`, evt(n))),
  ]);
const holdoutCapture = () =>
  har([
    ...[6, 7, 8].map((n) => entry(`${BASE}/api/events?limit=3&page=${n}`, { events: [evt(n + 30), evt(n + 40), evt(n + 50)], total: 3 })),
    ...[31, 32].map((n) => entry(`${BASE}/api/events/evt_${1000 + n}`, evt(n))),
  ]);

/** Live traffic with the certified SHAPE broken: capacity becomes a string. */
const schemaDrift = () =>
  har([entry(`${BASE}/api/events?limit=3&page=99`, { events: [{ ...evt(99), capacity: "fifty" }], total: 1 })]);

/** Live traffic that is perfectly well-typed and lies: total disagrees with the array. */
const semanticDrift = () =>
  har([entry(`${BASE}/api/events?limit=3&page=99`, { events: [evt(99), evt(98)], total: 47 })]);

async function main() {
  const registryDir = mkdtempSync(join(tmpdir(), "drift-reg-"));
  const tracer = new Tracer();
  const reg = new Registry(registryDir);

  const a = deriveCapture();
  const b = holdoutCapture();

  const spec: ConnectorSpec = await tracer.span("derive", { [ATTR.app]: "events" }, () => ({
    ...deriveSpec(a, { app: "events", captureLabel: "A", host: "example-events.com", minSamplesForRequired: 5 }),
    semanticInvariants: [INVARIANT],
  }));

  const { report, effectiveSpec } = await tracer.span("certify", { [ATTR.app]: "events", [ATTR.specHash]: spec.specHash }, async (ctx) => {
    const out = await certify(spec, b, { deriveExchanges: a, minSamplesForRequired: 5 });
    ctx.setAttribute(ATTR.schemaVerdict, out.report.schemaVerdict);
    ctx.setAttribute(ATTR.semanticVerdict, out.report.semanticVerdict);
    return out;
  });
  if (report.certifiedOps.length === 0) throw new Error(`nothing certified: ${JSON.stringify(report.refusedOps)}`);

  const promoted = await tracer.span("registry.promote", { [ATTR.app]: "events" }, () => reg.promote(effectiveSpec, report));
  if (!promoted.stored) throw new Error(promoted.reason);
  const cert = promoted.cert;

  console.log(`certified v${cert.version}: schema=${report.schemaVerdict} semantic=${report.semanticVerdict} ` +
    `ops=${report.certifiedOps.length} mutants=${report.mutation.caught}/${report.mutation.generated} ` +
    `invariants=${cert.certifiedInvariants.map((i) => i.id).join(",")}\n`);

  const anchor = loadTrustAnchor(registryDir);
  const results: Record<string, { detectionMs: number; reproduced: boolean; schemaRate: number; semanticRate: number; attributedTo: string }> = {};

  for (const [label, evidence] of [["schema drift", schemaDrift()], ["semantic false green", semanticDrift()]] as const) {
    const monitor = new ConnectorMonitor(new Set(report.certifiedOps), 1);
    const { fetcher } = replayFetcher(evidence);
    const adapter = new Adapter(effectiveSpec, { fetcher, unguarded: true });

    const t0 = performance.now();
    const r = await tracer.span("runtime.invoke", { [ATTR.app]: "events", [ATTR.op]: "get_api_events" }, async (ctx) => {
      const out = await adapter.call("get_api_events", { limit: "3", page: "99" });
      ctx.setAttribute(ATTR.outcome, out.outcome);
      return out;
    });
    monitor.record("get_api_events", r);
    const detectionMs = performance.now() - t0;

    const kind = classifyDrift(r);
    if (!kind) throw new Error(`${label}: expected a drift, got ${r.outcome}`);

    const { incident, bundle } = buildIncident({
      kind, app: "events", op: "get_api_events", spec: effectiveSpec, cert, report,
      failing: evidence, result: r, detectionMs, registryDir, tracer,
    });

    const bundleDir = join(mkdtempSync(join(tmpdir(), "incident-")), `events-${incident.id}`);
    writeBundle(bundleDir, bundle);

    // Replay it offline, with the network physically disabled.
    const realFetch = globalThis.fetch;
    let attempted = 0;
    globalThis.fetch = (() => { attempted++; throw new Error("network during replay"); }) as typeof fetch;
    let replayed;
    try {
      replayed = await tracer.span("replay", { [ATTR.incidentId]: incident.id, [ATTR.bundleDir]: "(local)" }, async (ctx) => {
        const out = await runBundle(readBundle(bundleDir), anchor);
        ctx.setAttribute(ATTR.reproduced, out.reproduced);
        return out;
      });
    } finally {
      globalThis.fetch = realFetch;
    }
    if (attempted !== 0) throw new Error("replay touched the network");
    if (!replayed.verified.ok) throw new Error(`incident bundle rejected: ${replayed.verified.failures.join("; ")}`);

    // A drift bundle REPRODUCES when replaying the failing evidence fails the same way.
    const failedAgain = replayed.ops.find((o) => o.op === "get_api_events");
    const reproduced = replayed.reproduced && failedAgain?.outcome === r.outcome;

    const rates = monitor.falseGreenRate();
    results[label] = {
      detectionMs,
      reproduced,
      schemaRate: rates.rate,
      semanticRate: rates.semanticRate,
      attributedTo: incident.invariantId ?? r.outcome,
    };

    console.log(`${label}`);
    console.log(`  detected as            ${kind} (${r.outcome})`);
    console.log(`  attributed to          ${incident.invariantId ?? "the response schema"}`);
    console.log(`  reason                 ${incident.detail}`);
    console.log(`  detection latency      ${detectionMs.toFixed(2)} ms (in-process, replayed fixture)`);
    console.log(`  incident bundle        ${bundle.exchanges.length} replay input(s), verified under the trust anchor`);
    console.log(`  offline replay         network calls attempted: ${attempted}; same outcome: ${reproduced}`);
    console.log(`  schema false-green     ${(rates.rate * 100).toFixed(0)}% (${rates.falseGreen}/${rates.certified})`);
    console.log(`  semantic false-green   ${(rates.semanticRate * 100).toFixed(0)}% (${rates.semanticFalseGreen}/${rates.certified})`);
    console.log(`  breaker                ${monitor.breakerState}\n`);
  }

  // Corrected certification: re-derive including the drifted evidence and re-certify.
  const corrected = await tracer.span("certify", { [ATTR.app]: "events", "bridgesmith.stage": "corrected" }, async (ctx) => {
    const widened = [...a, ...schemaDrift()];
    const s2: ConnectorSpec = {
      ...deriveSpec(widened, { app: "events", captureLabel: "A+drift", host: "example-events.com", minSamplesForRequired: 5 }),
      semanticInvariants: [INVARIANT],
    };
    const out = await certify(s2, b, { deriveExchanges: widened, minSamplesForRequired: 5 });
    ctx.setAttribute(ATTR.schemaVerdict, out.report.schemaVerdict);
    return out;
  });
  const promotion = reg.promote(corrected.effectiveSpec, corrected.report);
  console.log("corrected certification");
  console.log(`  schemaVerdict          ${corrected.report.schemaVerdict}`);
  console.log(`  promotion              ${promotion.stored ? `v${promotion.cert.version} compat=${promotion.cert.compat}` : `REFUSED (${promotion.reason})`}`);
  if (!promotion.stored) console.log(`  -> the widened shape is a compatibility decision, not an automatic promotion`);

  const spans = tracer.all();
  for (const s of spans) assertNoPayload(s);
  console.log(`\ntrace ${tracer.traceId}: ${spans.length} spans (${[...new Set(spans.map((s) => s.name))].join(", ")})`);
  console.log(`OTLP payload bytes: ${JSON.stringify(tracer.toOtlp()).length}; no span attribute carries response content.`);

  const ok = Object.values(results).every((r) => r.reproduced);
  if (!ok) throw new Error("an incident did not reproduce offline");
  console.log("\nBoth incidents detected, attributed, bundled, and reproduced offline with zero network calls.");
}

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
