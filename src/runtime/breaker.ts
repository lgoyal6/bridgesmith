/**
 * Circuit breaker + failure accounting per connector. This is where the
 * false-green rate comes from: certification says an op is green, the breaker
 * records what actually happened at runtime. Drift (a run of schema violations)
 * demotes the connector and signals the orchestrator to re-capture/re-certify.
 */
import type { CallResult } from "../codegen/adapter.js";
import type { TraceEvent as Trace } from "../core/types.js";

export interface OpStats {
  calls: number;
  ok: number;
  schemaViolations: number;
  /** Shape-valid responses that violated a declared semantic invariant. */
  semanticViolations: number;
  httpErrors: number;
  networkErrors: number;
  /** Consecutive non-ok results; resets on ok. Drives the breaker. */
  consecutiveFailures: number;
  /** Op certified green but produced a schema violation at runtime => schema false green. */
  falseGreen: boolean;
  /** Op certified green but broke a certified semantic invariant => semantic false green. */
  semanticFalseGreen: boolean;
}

export type BreakerState = "closed" | "open";

export class ConnectorMonitor {
  private readonly stats = new Map<string, OpStats>();
  private state: BreakerState = "closed";
  private readonly traces: Trace[] = [];

  constructor(
    private readonly certifiedOps: Set<string>,
    private readonly threshold = 3,
    private readonly onDemote?: (op: string) => void,
  ) {}

  get breakerState(): BreakerState {
    return this.state;
  }

  record(op: string, result: CallResult, trace?: Trace): OpStats {
    if (trace) this.traces.push(trace);
    const s =
      this.stats.get(op) ??
      { calls: 0, ok: 0, schemaViolations: 0, semanticViolations: 0, httpErrors: 0, networkErrors: 0, consecutiveFailures: 0, falseGreen: false, semanticFalseGreen: false };
    s.calls++;
    if (result.ok) {
      s.ok++;
      s.consecutiveFailures = 0;
    } else {
      s.consecutiveFailures++;
      if (result.outcome === "schema-violation") {
        s.schemaViolations++;
        if (this.certifiedOps.has(op)) s.falseGreen = true; // certified green, failed live
      } else if (result.outcome === "semantic-violation") {
        s.semanticViolations++;
        if (this.certifiedOps.has(op)) s.semanticFalseGreen = true;
      } else if (result.outcome === "http-error") s.httpErrors++;
      else if (result.outcome === "network-error") s.networkErrors++;

      if (s.consecutiveFailures >= this.threshold && this.state === "closed") {
        this.state = "open";
        this.onDemote?.(op);
      }
    }
    this.stats.set(op, s);
    return s;
  }

  /**
   * Two separate rates, never summed into one "false green" number:
   *   - schema: certified green, then returned data of the wrong SHAPE;
   *   - semantic: certified green and shape-valid, then broke a certified
   *     invariant (wrong total, disagreeing ids, a unit that changed).
   * A connector with a 0 schema rate and a nonzero semantic rate is exactly the
   * case a shape-only gate reports as perfect.
   */
  falseGreenRate(): {
    rate: number;
    falseGreen: number;
    certified: number;
    semanticRate: number;
    semanticFalseGreen: number;
  } {
    const certified = this.certifiedOps.size;
    let fg = 0;
    let sfg = 0;
    for (const op of this.certifiedOps) {
      const s = this.stats.get(op);
      if (s?.falseGreen) fg++;
      if (s?.semanticFalseGreen) sfg++;
    }
    return {
      rate: certified ? fg / certified : 0,
      falseGreen: fg,
      certified,
      semanticRate: certified ? sfg / certified : 0,
      semanticFalseGreen: sfg,
    };
  }

  snapshot(): { state: BreakerState; ops: Record<string, OpStats>; falseGreen: ReturnType<ConnectorMonitor["falseGreenRate"]> } {
    return { state: this.state, ops: Object.fromEntries(this.stats), falseGreen: this.falseGreenRate() };
  }

  allTraces(): Trace[] {
    return this.traces;
  }

  reset(): void {
    this.state = "closed";
    for (const s of this.stats.values()) s.consecutiveFailures = 0;
  }
}
