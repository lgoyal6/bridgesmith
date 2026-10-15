/**
 * Checks that Registry.store publishes a complete immutable connector version.
 * Builds a real certification from fixtures before exercising the registry.
 * A second writer must fail without leaving a partial staging directory.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadHar } from "../src/capture/har.js";
import { certify } from "../src/certify/certify.js";
import { deriveSpec } from "../src/spec/derive.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { Registry } from "../src/registry/registry.js";
import { captureA, captureB } from "./fixtures.js";

async function legitRegistry() {
  const dir = mkdtempSync(join(tmpdir(), "atomic-reg-"));
  const reg = new Registry(dir);
  const makeHar = (data: unknown) => {
    const path = join(mkdtempSync(join(tmpdir(), "atomic-har-")), "cap.har");
    writeFileSync(path, JSON.stringify(data));
    return path;
  };
  const a = loadHar(makeHar(captureA()));
  const derived = deriveSpec(a, { app: "events", captureLabel: "A", host: "example-events.com" });
  const b = loadHar(makeHar(captureB()));
  const { report, effectiveSpec } = await certify(derived, b, { deriveExchanges: a });
  const cert = issueCertificate(effectiveSpec, report, 1, dir);
  return { dir, reg, spec: effectiveSpec, report, cert };
}

describe("registry version publication", () => {
  it("publishes a complete immutable version and rejects a competing writer", async () => {
    const { dir, reg, spec, report, cert } = await legitRegistry();
    const versionDir = reg.store(spec, report, cert);
    expect(readdirSync(versionDir).sort()).toEqual(["certificate.json", "report.json", "spec.json"]);
    expect(JSON.parse(readFileSync(`${versionDir}/certificate.json`, "utf8")).signature).toBe(cert.signature);
    expect(() => reg.store(spec, report, cert)).toThrow();
    expect(readdirSync(`${dir}/events`).filter((name) => name.includes("staging"))).toEqual([]);
  });
});
