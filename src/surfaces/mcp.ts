/**
 * MCP surface: exposes a certified connector's operations as MCP tools. Only
 * ops named in the birth certificate are registered - refused/uncovered ops are
 * never reachable through the surface, so "uncertified tool cannot be mounted"
 * holds at the surface boundary too.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { BirthCertificate, ConnectorSpec, OperationSpec } from "../core/types.js";
import { Adapter, type AdapterOptions } from "../codegen/adapter.js";

export function buildMcpServer(
  spec: ConnectorSpec,
  cert: BirthCertificate,
  adapterOpts: AdapterOptions = {},
): { server: McpServer; adapter: Adapter; toolCount: number } {
  const adapter = new Adapter(spec, adapterOpts);
  const server = new McpServer({ name: `toolsmith-${spec.app}`, version: `${cert.version}.0.0` });
  const certified = new Set(cert.certifiedOps);

  let toolCount = 0;
  for (const op of spec.operations) {
    if (!certified.has(op.id)) continue; // surface exposes certified ops only
    server.registerTool(
      op.id,
      {
        description: describeOp(spec.app, op),
        inputSchema: inputShape(op),
      },
      async (args: Record<string, unknown>) => {
        const result = await adapter.call(op.id, args);
        if (!result.ok) {
          return {
            isError: true,
            content: [{ type: "text" as const, text: `toolsmith refused/failed: ${result.outcome} - ${result.error ?? ""}` }],
          };
        }
        return { content: [{ type: "text" as const, text: JSON.stringify(result.data) }] };
      },
    );
    toolCount++;
  }
  return { server, adapter, toolCount };
}

function inputShape(op: OperationSpec): Record<string, z.ZodTypeAny> {
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const p of op.pathParams) shape[p] = z.string().describe(`path parameter ${p}`);
  for (const q of op.queryParams) {
    const base = z.string().describe(`query parameter ${q.name}${q.example ? ` (e.g. ${q.example})` : ""}`);
    shape[q.name] = q.required ? base : base.optional();
  }
  if (op.mutating) shape["body"] = z.record(z.string(), z.unknown()).optional().describe("request body");
  return shape;
}

function describeOp(app: string, op: OperationSpec): string {
  return `${app}: ${op.method} ${op.pathTemplate} (certified, ${op.samples} evidence samples)`;
}
