/**
 * Self-healing connector manager. This is the runtime complement to
 * certification: a connector that certified green can still drift when the
 * upstream app changes (a field disappears, a type changes, an endpoint moves).
 * The manager runs every call through the adapter + monitor; when the breaker
 * trips on a run of schema violations, it re-captures, re-derives, re-certifies
 * against a fresh holdout, and hot-swaps the adapter IN PLACE - or, if the new
 * capture cannot be certified, DEMOTES the connector and refuses rather than
 * serving drift. Every transition is emitted as a timeline event.
 */
import type { BirthCertificate, ConnectorSpec, Exchange } from "../core/types.js";
import { Adapter, type AdapterOptions, type CallResult } from "../codegen/adapter.js";
import { ConnectorMonitor } from "./breaker.js";
import { certify } from "../certify/certify.js";
import { deriveSpec } from "../spec/derive.js";
import { issueCertificate } from "../registry/certificate.js";

export interface HealHooks {
  /** Re-capture the derive slice from the live app. */
  recapture: () => Promise<Exchange[]>;
  /** Re-capture an INDEPENDENT holdout slice. */
  recaptureHoldout: () => Promise<Exchange[]>;
  /** Access-tier fetcher for the rebuilt adapter (e.g. local SQL fetcher). */
  fetcher?: AdapterOptions["fetcher"];
  deriveOpts: { app: string; tier: ConnectorSpec["tier"]; host?: string; minSamplesForRequired?: number };
  registryDir: string;
}

export type HealEvent =
  | { t: "mounted"; version: number; certifiedOps: number }
  | { t: "call"; op: string; ok: boolean; outcome: CallResult["outcome"] }
  | { t: "breaker-open"; op: string; consecutive: number }
  | { t: "recapture" }
  | { t: "recertify"; verdict: string; certifiedOps: number }
  | { t: "hot-swap"; fromVersion: number; toVersion: number }
  | { t: "demoted"; reason: string };

export class ConnectorManager {
  private adapter: Adapter;
  private monitor: ConnectorMonitor;
  private demoted = false;
  private healing = false;
  private healPromise?: Promise<void>;

  /** Resolves once any in-flight self-heal has settled. */
  async settle(): Promise<void> {
    await this.healPromise;
  }

  constructor(
    private spec: ConnectorSpec,
    private cert: BirthCertificate,
    private readonly hooks: HealHooks,
    private readonly emit: (e: HealEvent) => void,
    breakerThreshold = 3,
  ) {
    this.adapter = new Adapter(spec, hooks.fetcher ? { fetcher: hooks.fetcher } : {});
    this.monitor = this.freshMonitor(breakerThreshold);
    this.emit({ t: "mounted", version: cert.version, certifiedOps: cert.certifiedOps.length });
  }

  private freshMonitor(threshold = 3): ConnectorMonitor {
    return new ConnectorMonitor(new Set(this.cert.certifiedOps), threshold, () => {
      this.healPromise = this.onDrift();
    });
  }

  async call(opId: string, params: Record<string, unknown> = {}): Promise<CallResult> {
    if (this.demoted) return { ok: false, outcome: "refused", error: "connector demoted (uncertifiable drift)", ms: 0 };
    const result = await this.adapter.call(opId, params);
    this.monitor.record(opId, result, {
      ts: new Date(0).toISOString(),
      app: this.spec.app,
      op: opId,
      outcome: result.outcome,
      ms: Math.round(result.ms),
    });
    this.emit({ t: "call", op: opId, ok: result.ok, outcome: result.outcome });
    return result;
  }

  falseGreen() {
    return this.monitor.falseGreenRate();
  }

  private async onDrift(): Promise<void> {
    if (this.healing || this.demoted) return;
    this.healing = true;
    this.emit({ t: "breaker-open", op: "*", consecutive: 3 });
    try {
      this.emit({ t: "recapture" });
      const a = await this.hooks.recapture();
      const b = await this.hooks.recaptureHoldout();
      const opts = this.hooks.deriveOpts;
      const newSpec = deriveSpec(a, {
        app: opts.app,
        tier: opts.tier,
        captureLabel: "reheal",
        ...(opts.host ? { host: opts.host } : {}),
        ...(opts.minSamplesForRequired ? { minSamplesForRequired: opts.minSamplesForRequired } : {}),
      });
      const { report, effectiveSpec } = await certify(newSpec, b, {
        deriveExchanges: a,
        ...(opts.minSamplesForRequired ? { minSamplesForRequired: opts.minSamplesForRequired } : {}),
      });
      this.emit({ t: "recertify", verdict: report.verdict, certifiedOps: report.certifiedOps.length });

      if (report.verdict === "refused") {
        this.demoted = true;
        this.emit({ t: "demoted", reason: "re-certification produced no certified operations" });
        return;
      }

      const fromVersion = this.cert.version;
      const newCert = issueCertificate(effectiveSpec, report, fromVersion + 1, this.hooks.registryDir);
      this.spec = effectiveSpec;
      this.cert = newCert;
      this.adapter = new Adapter(effectiveSpec, this.hooks.fetcher ? { fetcher: this.hooks.fetcher } : {});
      this.monitor = this.freshMonitor();
      this.emit({ t: "hot-swap", fromVersion, toVersion: newCert.version });
    } catch (e) {
      this.demoted = true;
      this.emit({ t: "demoted", reason: (e as Error).message });
    } finally {
      this.healing = false;
    }
  }

  get isDemoted() {
    return this.demoted;
  }
  get version() {
    return this.cert.version;
  }
}
