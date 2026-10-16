import { describe, expect, it } from "vitest";
import { generateMutants } from "../src/certify/mutate.js";
import { validateAgainst } from "../src/runtime/validate.js";
import type { JsonSchema } from "../src/core/types.js";

describe("nested mutation targets", () => {
  it("edits a list item inside the full response and preserves siblings", () => {
    const schema: JsonSchema = { type: "object", properties: {
      events: { type: "array", items: { type: "object", properties: {
        id: { type: "string" }, active: { type: "boolean" },
      }, required: ["id", "active"] } },
      total: { type: "integer" },
    } };
    const sample = { events: [{ id: "one", active: true }, { id: "two", active: false }], total: 2 };
    const before = structuredClone(sample);
    const mutants = generateMutants(schema, sample);
    const nested = mutants.filter((m) => m.path.startsWith("/events/0/"));
    expect(nested.length).toBeGreaterThan(0);
    for (const m of nested) {
      const body = m.value as typeof sample;
      expect(body.total).toBe(2);
      expect(body.events[1]).toEqual(sample.events[1]);
      expect(validateAgainst(schema, m.value).ok).toBe(false);
    }
    expect(sample).toEqual(before);
    expect(validateAgainst(schema, sample).ok).toBe(true);
  });

  it("keeps an array response rooted at the array", () => {
    const schema: JsonSchema = { type: "array", items: { type: "object", properties: {
      child: { type: "object", properties: { count: { type: "integer" } }, required: ["count"] },
    }, required: ["child"] } };
    const sample = [{ child: { count: 3 } }, { child: { count: 4 } }];
    for (const m of generateMutants(schema, sample)) {
      expect(Array.isArray(m.value)).toBe(true);
      expect((m.value as typeof sample)[1]).toEqual(sample[1]);
      expect(validateAgainst(schema, m.value).ok).toBe(false);
    }
  });

  it("addresses escaped and empty JSON property names without editing a sibling", () => {
    const schema: JsonSchema = { type: "object", properties: {
      "a/b": { type: "object", properties: {
        "~key": { type: "string" }, "": { type: "integer" },
      }, required: ["~key", ""] },
    }, required: ["a/b"] };
    const sample = { "a/b": { "~key": "value", "": 7 } };
    const mutants = generateMutants(schema, sample);
    const stringFlip = mutants.find((m) => m.kind === "type-flip" && m.path === "/a~1b/~0key");
    const emptyFlip = mutants.find((m) => m.kind === "type-flip" && m.path === "/a~1b/");
    expect(stringFlip?.value).toEqual({ "a/b": { "~key": 424242, "": 7 } });
    expect(emptyFlip?.value).toEqual({ "a/b": { "~key": "value", "": "BRIDGESMITH_MUTANT" } });
    for (const m of mutants) expect(validateAgainst(schema, m.value).ok).toBe(false);
    expect(generateMutants(schema, sample, 3)).toHaveLength(3);
  });
});
