/**
 * The single response validator used by BOTH certification and the live runtime.
 * One validator means the certificate's meaning and the runtime gate can't drift
 * apart.
 */
import { Ajv, type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import type { JsonSchema } from "../core/types.js";

const ajv = new Ajv({ allErrors: false, strict: false, validateFormats: true });
addFormats.default ? addFormats.default(ajv) : (addFormats as unknown as (a: Ajv) => void)(ajv);

const cache = new Map<string, ValidateFunction>();

export interface ValidationResult {
  ok: boolean;
  error?: string;
}

export function validateAgainst(schema: JsonSchema, value: unknown, cacheKey?: string): ValidationResult {
  let fn: ValidateFunction;
  if (cacheKey && cache.has(cacheKey)) {
    fn = cache.get(cacheKey)!;
  } else {
    fn = ajv.compile(schema as object);
    if (cacheKey) cache.set(cacheKey, fn);
  }
  const ok = fn(value) as boolean;
  if (ok) return { ok: true };
  const first = fn.errors?.[0];
  return {
    ok: false,
    error: first ? `${first.instancePath || "/"} ${first.message ?? "invalid"}` : "schema violation",
  };
}
