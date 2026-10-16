import { describe, expect, it } from "vitest";
import { labInput, runLab, type LabInput } from "../src/demo/lab.js";

const base: LabInput = { count: 6, seed: 7, query: "", fault: "none", faultAt: "runtime", trust: "current" };

describe("bounded connector lab through the actual certifier and registry", () => {
  it("runs changed visitor inputs rather than returning stored results", async () => {
    const first = await runLab(base);
    const second = await runLab({ ...base, count: 12, seed: 81, query: "Cedar" });
    expect(first.mounted).toBe(true);
    expect(first.serviceCalls).toBe(1);
    expect(first.call?.ok).toBe(true);
    expect(first.call?.data).toMatchObject({ total: 6 });
    expect(second.call?.data).toMatchObject({ total: 3 });
    expect(second.call?.data).not.toEqual(first.call?.data);
    expect(first.certificate?.captureManifestHash).not.toBe(first.certificate?.holdoutManifestHash);
    expect(first.trust?.chainValid).toBe(true);
    expect(second.certificate?.keyId).not.toBe(first.certificate?.keyId);
  });

  it.each(["schema", "total", "vocabulary"] as const)("refuses %s in holdout without contacting the catalog", async (fault) => {
    const result = await runLab({ ...base, fault, faultAt: "holdout" });
    expect(result.mounted).toBe(false);
    expect(result.serviceCalls).toBe(0);
    expect(result.call).toBeNull();
    expect(result.certificate).toBeNull();
    expect(result.report.verdict).not.toBe("certified");
  });

  it.each([
    ["schema", "schema-violation"], ["total", "semantic-violation"], ["vocabulary", "schema-violation"],
  ] as const)("withholds %s runtime data", async (fault, outcome) => {
    const result = await runLab({ ...base, fault });
    expect(result.mounted).toBe(true);
    expect(result.serviceCalls).toBe(1);
    expect(result.call?.outcome).toBe(outcome);
    expect(result.call?.data).toBeUndefined();
  });

  it.each(["tampered", "wrong-root", "retired", "revoked", "expired"] as const)("refuses %s trust before a service call", async (trust) => {
    const result = await runLab({ ...base, trust });
    expect(result.mounted).toBe(false);
    expect(result.serviceCalls).toBe(0);
    expect(result.call).toBeNull();
    if (trust === "wrong-root" || trust === "revoked") expect(result.trust?.chainValid).toBe(false);
    else expect(result.trust?.signatureValidAtClock).toBe(false);
  });

  it("requires and runs fresh certification after retirement", async () => {
    const result = await runLab({ ...base, trust: "recertified" });
    expect(result.timeline.map((entry) => entry.stage)).toEqual(["certify", "sign", "retire", "recertify", "mount", "call"]);
    expect(result.timeline.every((entry) => entry.pass)).toBe(true);
    expect(result.certificate?.version).toBe(2);
    expect(result.certificate?.keyId).not.toBe(result.trust?.initialKeyId);
    expect(result.call?.ok).toBe(true);
  });

  it("accepts only bounded data, with no upstream destination or caller code", () => {
    for (const patch of [{ count: 13 }, { count: -1 }, { count: 2.5 }, { seed: 10000 }, { query: "x".repeat(49) }, { url: "http://127.0.0.1" }, { fault: "custom" }]) {
      expect(labInput.safeParse({ ...base, ...patch }).success).toBe(false);
    }
  });
});
