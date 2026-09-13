/**
 * Mutation suite: proves the gate can catch WRONG data, not just confirm what it
 * saw. We take real holdout responses, corrupt them in schema-relevant ways, and
 * assert the validator rejects each mutant. A mutant that survives = the schema
 * is too loose in that spot = "missed", reported in the certificate.
 */
import type { JsonSchema } from "../core/types.js";

export interface Mutant {
  kind: "drop-required" | "type-flip" | "null-inject" | "enum-violation" | "rename-required";
  path: string;
  value: unknown;
}

export function generateMutants(schema: JsonSchema, sample: unknown, cap = 40): Mutant[] {
  const out: Mutant[] = [];
  walk(schema, sample, "", out, cap);
  return out.slice(0, cap);
}

function walk(schema: JsonSchema, value: unknown, path: string, out: Mutant[], cap: number): void {
  if (out.length >= cap || value === null || value === undefined) return;

  if (schema.type === "array" || (Array.isArray(value) && schema.items)) {
    const arr = value as unknown[];
    if (arr.length > 0 && schema.items) walk(schema.items, arr[0], `${path}/0`, out, cap);
    return;
  }

  if (typeof value === "object" && !Array.isArray(value) && schema.properties) {
    const obj = value as Record<string, unknown>;
    for (const req of schema.required ?? []) {
      if (req in obj) {
        out.push({ kind: "drop-required", path: `${path}/${req}`, value: cloneWithout(value, path, req) });
        out.push({ kind: "rename-required", path: `${path}/${req}`, value: cloneWithRename(value, path, req) });
        if (out.length >= cap) return;
      }
    }
    for (const [k, propSchema] of Object.entries(schema.properties)) {
      if (!(k in obj) || out.length >= cap) continue;
      const t = primaryType(propSchema);
      if (t && t !== "null") {
        out.push({ kind: "type-flip", path: `${path}/${k}`, value: cloneWithSet(value, `${path}/${k}`, flipValue(t)) });
        if (!allowsNull(propSchema) && obj[k] !== null) {
          out.push({ kind: "null-inject", path: `${path}/${k}`, value: cloneWithSet(value, `${path}/${k}`, null) });
        }
      }
      if (propSchema.enum && typeof obj[k] === "string") {
        out.push({ kind: "enum-violation", path: `${path}/${k}`, value: cloneWithSet(value, `${path}/${k}`, "TOOLSMITH_MUTANT_ENUM") });
      }
      walk(propSchema, obj[k], `${path}/${k}`, out, cap);
    }
  }
}

function primaryType(s: JsonSchema): string | undefined {
  if (typeof s.type === "string") return s.type;
  if (Array.isArray(s.type)) return s.type.find((t) => t !== "null");
  return undefined;
}

function allowsNull(s: JsonSchema): boolean {
  return Array.isArray(s.type) ? s.type.includes("null") : s.type === "null";
}

function flipValue(t: string): unknown {
  switch (t) {
    case "string": return 424242;
    case "integer": return "TOOLSMITH_MUTANT";
    case "number": return "TOOLSMITH_MUTANT";
    case "boolean": return "TOOLSMITH_MUTANT";
    case "object": return "TOOLSMITH_MUTANT";
    case "array": return "TOOLSMITH_MUTANT";
    default: return 424242;
  }
}

/** Deep-clone the ROOT sample, applying one change at an internal path. */
function cloneWithSet(root: unknown, targetPath: string, newValue: unknown): unknown {
  return editAt(structuredClone(root), splitPath(targetPath), (parent, key) => {
    (parent as Record<string, unknown>)[key] = newValue;
  });
}

function cloneWithout(root: unknown, parentPath: string, key: string): unknown {
  return editAt(structuredClone(root), [...splitPath(parentPath), key], (parent, k) => {
    delete (parent as Record<string, unknown>)[k];
  });
}

function cloneWithRename(root: unknown, parentPath: string, key: string): unknown {
  return editAt(structuredClone(root), [...splitPath(parentPath), key], (parent, k) => {
    const p = parent as Record<string, unknown>;
    p[`${k}_mutated`] = p[k];
    delete p[k];
  });
}

function splitPath(path: string): string[] {
  return path.split("/").filter(Boolean);
}

function editAt(root: unknown, segments: string[], edit: (parent: unknown, key: string) => void): unknown {
  if (segments.length === 0) return root;
  let node: unknown = root;
  for (let i = 0; i < segments.length - 1; i++) {
    const seg = segments[i]!;
    if (node === null || typeof node !== "object") return root;
    node = Array.isArray(node) ? node[Number(seg)] : (node as Record<string, unknown>)[seg];
  }
  if (node !== null && typeof node === "object") edit(node, segments[segments.length - 1]!);
  return root;
}
