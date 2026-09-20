import { describe, expect, it } from "vitest";
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { BirthCertificate } from "../src/core/types.js";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { generateDotnetPackage, writeDotnetPackage } from "../src/codegen/dotnet.js";
import { captureA } from "./fixtures.js";

function harFile(obj: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "bridgesmith-dotnet-")), "cap.har");
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

function certificate(app: string, specHash: string, certifiedOps: string[]): BirthCertificate {
  return {
    app,
    version: 3,
    tier: "derived-api",
    specHash,
    certifiedOps,
    refusedOps: [],
    mutationStats: { generated: 1, caught: 1, missed: 0, missedKinds: [] },
    certifiedWorkflows: [],
    certifiedInvariants: [],
    permissionsHash: null,
    captureManifestHash: "capture",
    holdoutManifestHash: "holdout",
    issuedAt: "2026-09-19T00:00:00.000Z",
    predecessor: null,
    compat: "initial",
    adapterHash: "adapter",
    signature: "test-only",
    publicKey: "test-only",
  };
}

describe(".NET client generation", () => {
  it("emits only certified operations and binds every call to the certificate identity", () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), {
      app: "events",
      captureLabel: "A",
      host: "example-events.com",
    });
    const cert = certificate("events", spec.specHash, ["get_api_events_event_id"]);
    const generated = generateDotnetPackage(spec, cert);
    const source = generated.files["EventsClient.cs"]!;

    expect(source).toContain("GetApiEventsEventIdAsync");
    expect(source).not.toContain("GetApiEventsAsync");
    expect(source).toContain(`public const string CertifiedSpecHash = "${spec.specHash}"`);
    expect(source).toContain("manifest.Version != CertificateVersion");
    expect(source).toContain("!actualOps.SequenceEqual(CertifiedOperations");
  });

  it("is deterministic and writes a dependency-free net8.0 package", () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), {
      app: "events",
      captureLabel: "A",
      host: "example-events.com",
    });
    const cert = certificate("events", spec.specHash, ["get_api_events_event_id"]);
    const first = generateDotnetPackage(spec, cert, { namespace: "Acme.Events" });
    const second = generateDotnetPackage(spec, cert, { namespace: "Acme.Events" });
    expect(first).toEqual(second);

    const root = mkdtempSync(join(tmpdir(), "bridgesmith-dotnet-out-"));
    const dir = writeDotnetPackage(root, first);
    expect(readFileSync(join(dir, "Events.Bridgesmith.csproj"), "utf8")).toContain("<TargetFramework>net8.0</TargetFramework>");
    expect(readFileSync(join(dir, "EventsClient.cs"), "utf8")).toContain("namespace Acme.Events;");
  });

  it("refuses mismatched and unknown certificate identities", () => {
    const spec = deriveSpec(loadHar(harFile(captureA())), {
      app: "events",
      captureLabel: "A",
      host: "example-events.com",
    });
    expect(() => generateDotnetPackage(spec, certificate("other", spec.specHash, []))).toThrow(/identity/);
    expect(() => generateDotnetPackage(spec, certificate("events", spec.specHash, ["delete_everything"]))).toThrow(/unknown operation/);
  });
});
