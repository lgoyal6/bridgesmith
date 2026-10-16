/** Bounded stateless public entrypoint. No caller URLs, secrets or code. */
import type { IncomingMessage, ServerResponse } from "node:http";
import { labInput, runLab } from "../src/demo/lab.js";

export default async function handler(req: IncomingMessage & { body?: unknown }, res: ServerResponse) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.writeHead(405).end(JSON.stringify({ error: "Use POST." }));
    return;
  }
  // Vercel may already have parsed the body; the local HTTP server has not.
  let size = 0;
  const chunks: Buffer[] = [];
  if (req.body !== undefined) {
    chunks.push(Buffer.isBuffer(req.body) ? req.body : Buffer.from(typeof req.body === "string" ? req.body : JSON.stringify(req.body)));
    size = chunks[0]!.length;
  } else {
    for await (const chunk of req) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > 2048) break;
      chunks.push(bytes);
    }
  }
  if (size > 2048) {
    res.writeHead(413).end(JSON.stringify({ error: "Input exceeds 2048 bytes." }));
    return;
  }
  let input: unknown;
  try { input = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { res.writeHead(400).end(JSON.stringify({ error: "Expected JSON." })); return; }
  const parsed = labInput.safeParse(input);
  if (!parsed.success) {
    res.writeHead(400).end(JSON.stringify({ error: "Invalid bounded catalog inputs." }));
    return;
  }
  try { res.writeHead(200).end(JSON.stringify(await runLab(parsed.data))); }
  catch { res.writeHead(500).end(JSON.stringify({ error: "Connector run failed. No result is available." })); }
}
