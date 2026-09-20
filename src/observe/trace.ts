/**
 * Spans across the whole connector lifecycle, emitted in the OpenTelemetry data
 * model and serialized as OTLP/JSON.
 *
 * ON THE DEPENDENCY: this implements the OTel data model (trace/span ids,
 * parent links, attributes, status, OTLP resourceSpans envelope) without
 * importing @opentelemetry/*. Bridgesmith pins its lockfile and the plan forbids
 * dependency churn mid-build, and the surface actually needed here is small and
 * stable. The tradeoff is real and stated plainly: this emits OTLP that a
 * collector accepts, it is NOT the OTel SDK, so there is no context propagation
 * across process boundaries, no sampler, and no exporter retry. Swapping in the
 * SDK later means replacing this file, not the call sites.
 *
 * CORRELATION IDS carry no payload. A span links an incident to the spec and
 * certificate it came from by HASH, never by content, so a trace can be shipped
 * to a collector without shipping the app's data with it.
 */
import { randomBytes } from "node:crypto";

/** Lifecycle stages, in the order they occur. */
export type SpanName =
  | "capture"
  | "normalize"
  | "derive"
  | "certify"
  | "certify.operation"
  | "certify.workflow"
  | "certify.semantic"
  | "sign"
  | "registry.promote"
  | "runtime.invoke"
  | "runtime.breaker"
  | "replay";

export type SpanStatus = "unset" | "ok" | "error";

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: SpanName;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: Record<string, string | number | boolean>;
  status: { code: SpanStatus; message?: string };
}

const id = (bytes: number) => randomBytes(bytes).toString("hex");

export interface TracerOptions {
  /** Injected in tests so span ids and times are deterministic. */
  idFactory?: (bytes: number) => string;
  now?: () => number;
  onEnd?: (s: Span) => void;
}

export class Tracer {
  readonly traceId: string;
  private readonly spans: Span[] = [];
  private readonly mkId: (bytes: number) => string;
  private readonly now: () => number;

  constructor(private readonly opts: TracerOptions = {}) {
    this.mkId = opts.idFactory ?? id;
    this.now = opts.now ?? (() => Date.now());
    this.traceId = this.mkId(16);
  }

  /**
   * Run `fn` inside a span. An exception is recorded as an error status and
   * rethrown: a span that swallows the failure it was opened to describe is
   * worse than no span.
   */
  async span<T>(
    name: SpanName,
    attributes: Record<string, string | number | boolean>,
    fn: (ctx: { spanId: string; setAttribute: (k: string, v: string | number | boolean) => void }) => Promise<T> | T,
    parentSpanId?: string,
  ): Promise<T> {
    const spanId = this.mkId(8);
    const startTimeUnixNano = String(this.now() * 1_000_000);
    const attrs = { ...attributes };
    let status: Span["status"] = { code: "ok" };
    try {
      return await fn({ spanId, setAttribute: (k, v) => void (attrs[k] = v) });
    } catch (e) {
      status = { code: "error", message: (e as Error).message };
      throw e;
    } finally {
      const span: Span = {
        traceId: this.traceId,
        spanId,
        ...(parentSpanId ? { parentSpanId } : {}),
        name,
        startTimeUnixNano,
        endTimeUnixNano: String(this.now() * 1_000_000),
        attributes: attrs,
        status,
      };
      this.spans.push(span);
      this.opts.onEnd?.(span);
    }
  }

  /** Record a span that has already happened, for synchronous call sites. */
  record(name: SpanName, attributes: Record<string, string | number | boolean>, status: Span["status"] = { code: "ok" }, parentSpanId?: string): Span {
    const t = String(this.now() * 1_000_000);
    const span: Span = {
      traceId: this.traceId,
      spanId: this.mkId(8),
      ...(parentSpanId ? { parentSpanId } : {}),
      name,
      startTimeUnixNano: t,
      endTimeUnixNano: t,
      attributes,
      status,
    };
    this.spans.push(span);
    this.opts.onEnd?.(span);
    return span;
  }

  all(): Span[] {
    return [...this.spans];
  }

  /** OTLP/JSON envelope, the shape a collector's HTTP receiver accepts. */
  toOtlp(serviceName = "bridgesmith"): unknown {
    return {
      resourceSpans: [
        {
          resource: { attributes: [{ key: "service.name", value: { stringValue: serviceName } }] },
          scopeSpans: [
            {
              scope: { name: "bridgesmith" },
              spans: this.spans.map((s) => ({
                traceId: s.traceId,
                spanId: s.spanId,
                ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
                name: s.name,
                kind: 1,
                startTimeUnixNano: s.startTimeUnixNano,
                endTimeUnixNano: s.endTimeUnixNano,
                attributes: Object.entries(s.attributes).map(([key, v]) => ({
                  key,
                  value: typeof v === "number" ? { doubleValue: v } : typeof v === "boolean" ? { boolValue: v } : { stringValue: v },
                })),
                status: { code: s.status.code === "ok" ? 1 : s.status.code === "error" ? 2 : 0, ...(s.status.message ? { message: s.status.message } : {}) },
              })),
            },
          ],
        },
      ],
    };
  }
}

/**
 * Attribute keys shared across stages, so an incident can be joined to its spec
 * and certificate by hash. Nothing here is payload: hashes, ids, counts, verdicts.
 */
export const ATTR = {
  app: "bridgesmith.app",
  specHash: "bridgesmith.spec.hash",
  captureSetId: "bridgesmith.capture.set_id",
  certVersion: "bridgesmith.certificate.version",
  certKeyId: "bridgesmith.certificate.key_id",
  adapterHash: "bridgesmith.adapter.hash",
  op: "bridgesmith.op",
  outcome: "bridgesmith.outcome",
  schemaVerdict: "bridgesmith.verdict.schema",
  semanticVerdict: "bridgesmith.verdict.semantic",
  invariant: "bridgesmith.invariant.id",
  workflow: "bridgesmith.workflow.id",
  compat: "bridgesmith.compat",
  breakerState: "bridgesmith.breaker.state",
  driftKind: "bridgesmith.drift.kind",
  incidentId: "bridgesmith.incident.id",
  bundleDir: "bridgesmith.bundle.dir",
  reproduced: "bridgesmith.replay.reproduced",
} as const;

/** Reject any attribute that looks like response content rather than an identifier. */
export function assertNoPayload(span: Span): void {
  for (const [k, v] of Object.entries(span.attributes)) {
    if (typeof v !== "string") continue;
    if (v.length > 256) throw new Error(`span attribute "${k}" is too long to be an identifier (${v.length} chars)`);
  }
}
