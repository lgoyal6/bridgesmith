/**
 * JSON Schema inference from observed response samples.
 *
 * Bias: strict enough that mutations (dropped fields, type flips) are caught,
 * loose enough that a held-out capture of the same endpoint still validates.
 * The certify stage measures both directions (missed mutants / holdout failures)
 * and the repair loop re-runs inference with the union of evidence.
 */
import type { JsonSchema } from "../core/types.js";

const MAX_ARRAY_SAMPLES = 50;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DATETIME_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/;
const URI_RE = /^https?:\/\//;

export interface InferOptions {
  /**
   * A property is marked `required` only if it appears in every sample AND there
   * are at least this many samples. With thin evidence we cannot distinguish
   * "always present" from "happened to be present", so we do not over-constrain.
   * This is the primary control on false-green rate. Default 8.
   */
  minSamplesForRequired?: number;
}

export function inferSchema(samples: unknown[], opts: InferOptions = {}): JsonSchema {
  const present = samples.filter((s) => s !== undefined);
  if (present.length === 0) return {};

  const types = new Set(present.map(jsonType));
  const nullable = types.delete("null");

  // Every observed value was null. That is weak evidence the field is *always*
  // null (it is often an optional description that happens to be empty in the
  // sample), so we emit no type constraint rather than locking to type:null,
  // which would reject the first non-null value seen at runtime.
  if (types.size === 0) return {};
  if (types.size > 1) {
    // Mixed types: keep the union, no deeper inference. Rare in practice.
    const t = [...types];
    return nullable ? { type: [...t, "null"] } : { type: t };
  }

  const type = [...types][0]!;
  const nonNull = present.filter((s) => s !== null);
  let schema: JsonSchema;
  switch (type) {
    case "object":
      schema = inferObject(nonNull as Record<string, unknown>[], opts);
      break;
    case "array":
      schema = inferArray(nonNull as unknown[][], opts);
      break;
    case "string":
      schema = inferString(nonNull as string[]);
      break;
    default:
      schema = { type };
  }
  if (nullable) schema.type = Array.isArray(schema.type) ? [...schema.type, "null"] : [schema.type ?? type, "null"];
  return schema;
}

function jsonType(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  switch (typeof v) {
    case "number":
      return Number.isInteger(v) ? "integer" : "number";
    case "string":
      return "string";
    case "boolean":
      return "boolean";
    case "object":
      return "object";
    default:
      return "string";
  }
}

function inferObject(samples: Record<string, unknown>[], opts: InferOptions): JsonSchema {
  const minForRequired = opts.minSamplesForRequired ?? 8;
  const keyCounts = new Map<string, number>();
  const valuesByKey = new Map<string, unknown[]>();
  for (const s of samples) {
    for (const [k, v] of Object.entries(s)) {
      keyCounts.set(k, (keyCounts.get(k) ?? 0) + 1);
      const arr = valuesByKey.get(k) ?? [];
      arr.push(v);
      valuesByKey.set(k, arr);
    }
  }
  const properties: Record<string, JsonSchema> = {};
  const required: string[] = [];
  for (const [k, values] of valuesByKey) {
    properties[k] = inferSchema(values, opts);
    // Required only with enough evidence: present in every sample AND the sample
    // count clears the confidence floor. Otherwise "seen every time" may just be
    // small-sample luck (the classic over-constrained-optional-field failure).
    if (keyCounts.get(k) === samples.length && samples.length >= minForRequired) required.push(k);
  }
  const schema: JsonSchema = { type: "object", properties };
  if (required.length > 0) schema.required = required.sort();
  return schema;
}

function inferArray(samples: unknown[][], opts: InferOptions): JsonSchema {
  const elements = samples.flat().slice(0, MAX_ARRAY_SAMPLES);
  return { type: "array", items: elements.length ? inferSchema(elements, opts) : {} };
}

function inferString(samples: string[]): JsonSchema {
  const schema: JsonSchema = { type: "string" };
  if (samples.length > 0 && samples.every((s) => UUID_RE.test(s))) schema.format = "uuid";
  else if (samples.length > 0 && samples.every((s) => DATETIME_RE.test(s))) schema.format = "date-time";
  else if (samples.length > 0 && samples.every((s) => URI_RE.test(s))) schema.format = "uri";

  // Conservative enum detection: enough samples, low cardinality, short tokens.
  const distinct = new Set(samples);
  if (
    samples.length >= 8 &&
    distinct.size <= 5 &&
    distinct.size / samples.length <= 0.3 &&
    [...distinct].every((s) => s.length <= 32 && !DATETIME_RE.test(s))
  ) {
    schema.enum = [...distinct].sort();
  }
  return schema;
}
