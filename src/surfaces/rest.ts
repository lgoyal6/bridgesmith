/**
 * REST surface: the same certified adapter, exposed as a keyed HTTP API. This is
 * the "every workflow leaves behind a reusable connector" side product - the
 * connector is usable by anything that speaks HTTP, not just MCP clients.
 *
 * Auth on the FACADE (the scoped key a caller presents to us) is separate from
 * the connector's own upstream auth. Scope: intended for team use with a scoped
 * token, not a public proxy of a logged-in session (see README honesty section).
 */
import express, { type Express, type Request, type Response } from "express";
import type { BirthCertificate, ConnectorSpec } from "../core/types.js";
import { Adapter, type AdapterOptions } from "../codegen/adapter.js";

export function buildRestApp(
  spec: ConnectorSpec,
  cert: BirthCertificate,
  opts: AdapterOptions & { apiKey?: string } = {},
): Express {
  const adapter = new Adapter(spec, opts);
  const certified = new Set(cert.certifiedOps);
  const app = express();
  app.use(express.json());

  // Scoped-key gate on every data route.
  app.use("/op", (req: Request, res: Response, next) => {
    if (opts.apiKey && req.header("x-toolsmith-key") !== opts.apiKey) {
      res.status(401).json({ error: "invalid or missing x-toolsmith-key" });
      return;
    }
    next();
  });

  // Discovery: what this connector can do, and its certificate.
  app.get("/manifest", (_req, res) => {
    res.json({
      app: spec.app,
      tier: spec.tier,
      version: cert.version,
      specHash: spec.specHash,
      certifiedOps: cert.certifiedOps,
      operations: spec.operations
        .filter((o) => certified.has(o.id))
        .map((o) => ({ id: o.id, method: o.method, path: o.pathTemplate, params: o.pathParams, query: o.queryParams.map((q) => q.name) })),
    });
  });

  app.get("/certificate", (_req, res) => res.json(cert));

  app.post("/op/:opId", async (req: Request, res: Response) => {
    const opId = req.params.opId ?? "";
    if (!certified.has(opId)) {
      res.status(404).json({ error: `operation "${opId}" is not certified on this connector` });
      return;
    }
    const result = await adapter.call(opId, (req.body ?? {}) as Record<string, unknown>);
    if (!result.ok) {
      res.status(result.outcome === "schema-violation" ? 502 : 500).json({
        ok: false,
        outcome: result.outcome,
        error: result.error,
      });
      return;
    }
    res.json({ ok: true, data: result.data });
  });

  return app;
}
