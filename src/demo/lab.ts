/** Runs the existing connector gates against a bounded, in-process catalog.
 * Each request owns its temporary registry and trust root. No network fetcher
 * or caller-supplied destination enters the adapter.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { Adapter, type Fetcher } from "../codegen/adapter.js";
import { certify } from "../certify/certify.js";
import type { BirthCertificate, Exchange } from "../core/types.js";
import { deriveSpec, specHashOf } from "../spec/derive.js";
import { Registry } from "../registry/registry.js";
import { keyId, loadTrustAnchor, revokeRegistryKey, rotateRegistryKey, verifyCertificate, verifyRegistryKeyring } from "../registry/certificate.js";

export const labInput = z.strictObject({
  count: z.number().int().min(1).max(12),
  seed: z.number().int().min(0).max(9999),
  query: z.string().max(48),
  fault: z.enum(["none", "schema", "total", "vocabulary"]),
  faultAt: z.enum(["holdout", "runtime"]),
  trust: z.enum(["current", "tampered", "wrong-root", "retired", "revoked", "recertified", "expired"]),
});
export type LabInput = z.infer<typeof labInput>;
const ORIGIN = "https://catalog.synthetic.invalid";
const OP = "get_api_catalog";
type Fault = LabInput["fault"];

function catalog(seed: number, count: number, query: string, fault: Fault): unknown {
  const names = ["Cedar", "Harbor", "Orchard", "Summit"];
  const items = Array.from({ length: count }, (_, i) => ({
    id: seed * 100 + i,
    title: `${names[(seed + i) % names.length]} ${i + 1}`,
    status: i % 2 ? "draft" : "published",
  })).filter((item) => item.title.toLowerCase().includes(query.toLowerCase()));
  if (fault === "vocabulary" && items[0]) items[0].status = "unreviewed";
  return { items, total: fault === "schema" ? "invalid" : items.length + (fault === "total" ? 1 : 0) };
}

function capture(seed: number, fault: Fault): Exchange[] {
  return Array.from({ length: 10 }, (_, i) => ({
    method: "GET", url: `${ORIGIN}/api/catalog?q=`, path: "/api/catalog", query: { q: "" },
    requestHeaders: {}, status: 200, responseHeaders: { "content-type": "application/json" },
    responseType: "application/json", capturedBy: "synthetic-catalog/1",
    responseBody: catalog(seed + i, 4, "", fault),
  }));
}

export async function runLab(value: unknown) {
  const input = labInput.parse(value);
  const root = mkdtempSync(join(tmpdir(), "bridgesmith-lab-"));
  const timeline: { stage: string; pass: boolean; detail: string }[] = [];
  let serviceCalls = 0;
  try {
    const registry = new Registry(root);
    // Pin separately before any certificate or lifecycle change is considered.
    const pinnedRoot = readFileSync(join(root, ".registry-key-root.pub"), "utf8");
    const spec = deriveSpec(capture(100, "none"), { app: "catalog", captureLabel: "synthetic derive A", host: "catalog.synthetic.invalid" });
    spec.semanticInvariants = [
      { id: "catalog.total", severity: "blocking", kind: "total-matches", op: OP, path: "items", totalPath: "total" },
      { id: "catalog.status", severity: "blocking", kind: "enum-consistency", field: "status", allowed: ["draft", "published"], sources: [{ op: OP, path: "items" }] },
    ];
    spec.specHash = specHashOf(spec);
    const holdout = capture(500, input.faultAt === "holdout" ? input.fault : "none");
    let outcome = await certify(spec, holdout, { maxRepairs: 0 });
    timeline.push({ stage: "certify", pass: outcome.report.verdict === "certified", detail: `Schema ${outcome.report.schemaVerdict}; semantics ${outcome.report.semanticVerdict}. Repairs disabled.` });
    if (outcome.report.verdict !== "certified") {
      return { input, timeline, report: outcome.report, mounted: false, serviceCalls, call: null, certificate: null, trust: null };
    }
    let promotion = registry.promote(outcome.effectiveSpec, outcome.report, { expiresAt: new Date(Date.now() + 60_000).toISOString() });
    if (!promotion.stored) throw new Error(promotion.reason);
    timeline.push({ stage: "sign", pass: true, detail: "Issued a 60-second certificate under this request's ephemeral registry key." });
    const initialKeyId = promotion.cert.keyId;
    if (input.trust === "retired" || input.trust === "recertified") {
      rotateRegistryKey(root, "visitor retirement scenario");
      const oldRejected = registry.latest("catalog") === null;
      timeline.push({ stage: "retire", pass: oldRejected, detail: "Old certificate rejected after rotation; no automatic re-signing." });
      if (!oldRejected) throw new Error("retired certificate unexpectedly mounted");
      if (input.trust === "recertified") {
        outcome = await certify(spec, holdout, { maxRepairs: 0 });
        promotion = registry.promote(outcome.effectiveSpec, outcome.report, { expiresAt: new Date(Date.now() + 60_000).toISOString() });
        if (!promotion.stored) throw new Error(promotion.reason);
        timeline.push({ stage: "recertify", pass: true, detail: "Ran certification again after key activation and issued a new certificate." });
      }
    } else if (input.trust === "revoked") {
      revokeRegistryKey(root, "visitor revocation scenario");
    } else if (input.trust === "tampered") {
      writeFileSync(join(promotion.dir, "certificate.json"), JSON.stringify({ ...promotion.cert, specHash: "0".repeat(64) }));
    }
    const certificate = JSON.parse(readFileSync(join(promotion.dir, "certificate.json"), "utf8")) as BirthCertificate;
    const anchor = loadTrustAnchor(root);
    const clockMs = input.trust === "expired" ? Date.parse(promotion.cert.expiresAt!) : Date.now();
    const pinned = input.trust === "wrong-root" ? "not the pinned registry key" : pinnedRoot;
    const chainValid = anchor !== null && verifyRegistryKeyring(root, pinned) === anchor;
    const signatureValidAtClock = anchor !== null && verifyCertificate(certificate, anchor, clockMs);
    const mounted = chainValid && signatureValidAtClock ? registry.latest("catalog") : null;
    timeline.push({ stage: "mount", pass: mounted !== null, detail: mounted ? "Pinned root, active key, signature, expiry and registry artifact bindings passed." : "Trust or certificate gate refused mounting. No catalog read was attempted." });
    const reached: string[] = [];
    const fetcher: Fetcher = async (url, init) => {
      const parsed = new URL(url);
      if (parsed.origin !== ORIGIN || parsed.pathname !== "/api/catalog" || init.method !== "GET") throw new Error("synthetic catalog refuses this destination or method");
      serviceCalls++;
      reached.push(`${init.method} ${parsed.pathname}${parsed.search}`);
      const body = catalog(input.seed, input.count, parsed.searchParams.get("q") ?? "", input.faultAt === "runtime" ? input.fault : "none");
      return { status: 200, json: async () => body, text: async () => JSON.stringify(body), headers: { get: (name) => name.toLowerCase() === "content-type" ? "application/json" : null } };
    };
    const call = mounted ? await new Adapter(mounted.spec, { fetcher }).call(OP, { q: input.query }) : null;
    if (call) timeline.push({ stage: "call", pass: call.ok, detail: call.error ?? "Catalog response passed the same schema and declared semantic checks used in certification." });
    return {
      input, timeline, report: outcome.report, mounted: mounted !== null, serviceCalls, reached, call,
      certificate,
      trust: { chainValid, signatureValidAtClock, pinnedRootKeyId: keyId(pinnedRoot), initialKeyId, activeKeyId: chainValid && anchor ? keyId(anchor) : null, evaluatedAt: new Date(clockMs).toISOString(), clockAdvanced: input.trust === "expired" },
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
