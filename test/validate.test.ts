import { describe, expect, it } from "vitest";
import { validateAgainst } from "../src/runtime/validate.js";
import type { JsonSchema } from "../src/core/types.js";

describe("required empty property names", () => {
  const schema: JsonSchema = { type: "object", properties: { "": { type: "integer" } }, required: [""] };

  it("refuses an absent required empty-name property", () => {
    expect(validateAgainst(schema, {}).ok).toBe(false);
  });

  it("accepts a present zero and still rejects the wrong type", () => {
    expect(validateAgainst(schema, { "": 0 }).ok).toBe(true);
    expect(validateAgainst(schema, { "": "0" }).ok).toBe(false);
  });

  it("enforces the same requirement in nested array items", () => {
    const nested: JsonSchema = { type: "array", items: schema };
    expect(validateAgainst(nested, [{ "": 7 }, {}]).ok).toBe(false);
    expect(validateAgainst(nested, [{ "": 7 }, { "": 0 }]).ok).toBe(true);
  });
});
