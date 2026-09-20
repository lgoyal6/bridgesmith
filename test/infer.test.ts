/**
 * Schema inference regressions found by running the live eval, not by reading
 * the code. Both defects manufactured their own failures: one produced schema
 * false greens out of thin evidence, the other made the repair loop structurally
 * incapable of succeeding.
 */
import { describe, it, expect } from "vitest";
import { inferSchema } from "../src/spec/infer.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { validateAgainst } from "../src/runtime/validate.js";
import type { Exchange, JsonSchema } from "../src/core/types.js";

function propOf(schema: JsonSchema, ...path: string[]): JsonSchema | undefined {
  let cur: JsonSchema | undefined = schema;
  for (const p of path) {
    cur = p === "[]" ? cur?.items : cur?.properties?.[p];
    if (!cur) return undefined;
  }
  return cur;
}

describe("a closed vocabulary needs evidence that it is closed", () => {
  it("I1 ten samples of one value do not make an enum, so an unseen value is not a false green", () => {
    // the live chess.com case: a capture of ten grandmasters all carry title "GM"
    const samples = Array.from({ length: 10 }, (_, i) => ({ username: `p${i}`, title: "GM" }));
    const schema = inferSchema(samples, { minSamplesForRequired: 8 });
    expect(propOf(schema, "title")?.enum).toBeUndefined();
    // the first International Master at runtime is accepted, not refused
    expect(validateAgainst(schema, { username: "im1", title: "IM" }).ok).toBe(true);
  });

  it("I2 two values that each recur DO make an enum, and a third value is rejected", () => {
    const samples = [
      ...Array.from({ length: 6 }, (_, i) => ({ id: `a${i}`, state: "open" })),
      ...Array.from({ length: 4 }, (_, i) => ({ id: `b${i}`, state: "ended" })),
    ];
    const schema = inferSchema(samples, { minSamplesForRequired: 8 });
    expect(propOf(schema, "state")?.enum).toEqual(["ended", "open"]);
    expect(validateAgainst(schema, { id: "x", state: "open" }).ok).toBe(true);
    expect(validateAgainst(schema, { id: "x", state: "archived" }).ok).toBe(false);
  });

  it("I3 a value seen once does not join the vocabulary: it is evidence the field is open", () => {
    const samples = [
      ...Array.from({ length: 9 }, (_, i) => ({ id: `a${i}`, state: "open" })),
      { id: "z", state: "ended" }, // seen once, below the support floor
    ];
    const schema = inferSchema(samples, { minSamplesForRequired: 8 });
    expect(propOf(schema, "state")?.enum).toBeUndefined();
    expect(validateAgainst(schema, { id: "x", state: "anything" }).ok).toBe(true);
  });
});

describe("the repair loop must be able to see the holdout", () => {
  const ORIGIN = "https://api.pages.test";

  function page(n: number, items: { id: string; state: string }[]): Exchange {
    return {
      method: "GET",
      url: `${ORIGIN}/api/items?page=${n}`,
      path: "/api/items",
      query: { page: String(n) },
      requestHeaders: { accept: "application/json" },
      status: 200,
      responseHeaders: { "content-type": "application/json" },
      responseBody: { items, total: items.length },
      responseType: "application/json",
      capturedBy: "test-fixture/1",
    };
  }
  /** Ten items per page, so six derive pages alone exceed the 50-element budget. */
  const items = (prefix: string, n: number, state: (i: number) => string) =>
    Array.from({ length: n }, (_, i) => ({ id: `${prefix}${i}`, state: state(i) }));

  const derive = [1, 2, 3, 4, 5, 6].map((p) => page(p, items(`d${p}_`, 10, (i) => (i % 2 ? "open" : "upcoming"))));
  // the holdout introduces a third state the derive capture never showed
  const holdout = [7, 8, 9, 10].map((p) => page(p, items(`h${p}_`, 10, (i) => (i % 3 === 0 ? "ended" : "open"))));

  it("I4 a derive capture that alone fills the element budget does not truncate the holdout away", async () => {
    const deriveElements = derive.reduce((n, e) => n + (e.responseBody as { items: unknown[] }).items.length, 0);
    expect(deriveElements).toBeGreaterThan(50); // the precondition for the bug

    const spec = deriveSpec(derive, { app: "pages", captureLabel: "A", host: "api.pages.test", minSamplesForRequired: 4 });
    // derived from A alone, the vocabulary is closed over what A showed
    expect(propOf(spec.operations[0]!.responseSchema, "items", "[]", "state")?.enum).toEqual(["open", "upcoming"]);

    // repair re-infers over A+B; with a flat prefix the holdout never reached
    // inference, so both iterations reproduced the same schema and the op was refused
    const { report, effectiveSpec } = await certify(spec, holdout, { deriveExchanges: derive, minSamplesForRequired: 4 });
    expect(report.refusedOps).toEqual([]);
    expect(report.certifiedOps).toEqual(["get_api_items"]);
    expect(report.schemaVerdict).toBe("certified");

    const repaired = propOf(effectiveSpec.operations[0]!.responseSchema, "items", "[]", "state");
    expect(repaired?.enum).toContain("ended"); // the holdout's evidence made it in
    expect(repaired?.enum).toContain("open");
  });

  it("I5 every response body contributes before any body contributes twice", () => {
    // 60 single-element bodies: a prefix would take the first 50 and drop ten
    // bodies entirely; round-robin takes one element from each of the first 50.
    const bodies = Array.from({ length: 60 }, (_, i) => [{ id: `x${i}`, marker: i }]);
    const schema = inferSchema(bodies, { minSamplesForRequired: 4 });
    expect(schema.type).toBe("array");
    expect(propOf(schema, "[]", "marker")?.type).toBe("integer");

    // determinism: the same inputs produce byte-identical schemas
    expect(JSON.stringify(inferSchema(bodies, { minSamplesForRequired: 4 }))).toBe(JSON.stringify(schema));
  });
});
