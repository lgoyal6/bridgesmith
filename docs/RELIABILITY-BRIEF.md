# Bridgesmith - System & Reliability Brief

**One agent, multiple apps, connectors it builds and certifies itself.** This is
the required system-and-reliability brief. It states what the system guarantees,
what it does not, how each guarantee is instrumented, and the numbers behind the
claims.

## 1. Problem

Agents stall the moment they hit an app with no connector, and the connectors
that do exist for the long tail are unmaintained scrapers nobody trusts. The
expensive part is not writing the integration; it is *knowing it works and keeps
working*. Bridgesmith makes the integration disposable and the **certificate** the
durable artifact.

## 2. Architecture (what runs where)

- **LLM plans, deterministic code executes.** The orchestrator chooses an access
  tier and drives capture; derivation, certification, codegen, and the runtime
  gate are deterministic. A deterministic generator has no generated-code failure
  surface to certify - a reliability property in itself.
- **Access ladder** (`src/drivers/*`), uniform certification across rungs:
  official API → derived API (reverse-engineered from the app's own XHR) →
  browser bridge (not in v0) → local store (SQLite: iMessage/Notes/Safari).
- **One validator** (`src/runtime/validate.ts`) is shared by certification and
  the runtime, so the certificate's meaning and the runtime gate cannot drift
  apart.

Pipeline: `capture A` + `capture B (holdout)` → derive spec from **A only** →
certify against **B** → sign → register → mount → runtime gate → self-heal.

## 3. What we guarantee (and how it is instrumented)

| Guarantee | Mechanism | Where |
| --- | --- | --- |
| An uncertified tool cannot be mounted | surfaces expose only `cert.certifiedOps` | `src/surfaces/mcp.ts`, `rest.ts` |
| An unexercised operation cannot be mounted | no holdout coverage → refused | `src/certify/certify.ts` (uncoveredOps) |
| Schema-invalid data cannot be returned | every response validated on return | `src/codegen/adapter.ts` |
| The gate catches *wrong* data, not just *its own* data | holdout is an independent capture; mutation suite corrupts real responses and asserts rejection | `certify.ts`, `src/certify/mutate.ts` |
| Drift is not served silently | breaker trips on consecutive schema violations → re-certify + hot-swap, or demote | `src/runtime/selfheal.ts`, `breaker.ts` |
| Certificates are tamper-evident | ed25519 signature over canonical JSON | `src/registry/certificate.ts` |

**We do NOT claim "never fails."** We claim: cannot mount the uncertified,
cannot return schema-invalid data, and no failure is silent - every failure is a
typed, counted outcome (`schema-violation | http-error | network-error |
refused | anomaly`).

## 4. Failure taxonomy → detector

| Failure | Detector | Response |
| --- | --- | --- |
| Response shape wrong at runtime | runtime validator | typed `schema-violation`, counted, not returned |
| Upstream drift (field/type change) | breaker (N consecutive violations) | re-capture → re-certify → hot-swap |
| Upstream gone / uncertifiable | re-certification verdict = refused | **demote**, refuse all calls |
| Over-constrained schema from thin evidence | confidence floor on `required`; always-null → permissive | fewer false-greens; measured, see §6 |
| Certified-then-failed-live | monitor flags op false-green | contributes to the false-green rate |
| Semantic error (right type, wrong value) | **not detected by shape** | out of scope; stated plainly (§7) |

## 5. Refusal is a first-class outcome

Three demonstrated refusals:
1. **Certification refusal** - a poisoned/over-constrained capture fails holdout
   replay; the connector is not mounted and the failing ops are named. (test:
   `test/pipeline.test.ts`)
2. **Uncovered-op refusal** - an operation with no holdout evidence is never
   mounted, even if it looked fine in derivation.
3. **Runtime demotion** - a mounted connector whose upstream becomes
   uncertifiable is demoted and refuses, rather than serving drift. (test:
   `test/selfheal.test.ts`)

## 6. Measured reliability (reproducible: `pnpm tsx scripts/eval.ts`)

Live public APIs, no auth, no secrets. Derive and holdout are **independent**
captures; the probe uses **inputs never seen** during derive or certify.

| Connector | Certified | Holdout | Mutants caught | Unseen-input probe | Silent failures |
| --- | --- | --- | --- | --- | --- |
| chess.com | 1/1 | 8 | 40/40 | 3/4 | **0** |
| devpost | 1/1 | 4 | 40/40 | 5/5 | **0** |

Reading these honestly:
- **40/40 mutant catch** on both means the inferred schema is tight enough that
  dropped-required, type-flip, null-inject, and enum-violation corruptions are
  all rejected.
- **chess.com 3/4 unseen** is the instructive one. At 8 holdout samples, one
  field was over-constrained and an unseen player tripped it. The runtime gate
  caught it as a `schema-violation` - a **loud** miss, zero silent failures. This
  is the false-green rate doing its job: it surfaces the generalization gap
  instead of hiding it. Two real inference bugs were found this exact way and
  fixed (over-required fields; always-null fields locked to null-only).
- The lever is evidence volume: more holdout samples → fewer over-constraints →
  the probe trends to 4/4. We report the number rather than tuning the demo to
  hide it.

## 7. Honest boundaries

- **Legality.** Reverse-engineering a private API may violate an app's ToS.
  Bridgesmith runs only against public, no-auth data or the user's own session
  reading the user's own data. It never reuses an app-wide embedded secret and
  never bypasses a protection (two such "easy" targets were explicitly dropped
  during target selection).
- **Secrets.** Traffic is redacted at ingest (`src/capture/redact.ts`); fixtures
  never contain auth headers, cookies, or token-like params.
- **Shape, not meaning.** Certification proves structural conformance. A
  connector returning the right-typed *wrong value* passes every gate; detecting
  that needs an independent oracle and is out of scope for v0.
- **Writes.** Mutating operations are never live-canaried; treat as unverified
  until a reversible-write canary exists.
- **REST facade.** Scoped to team use with a token; not a public proxy of a
  logged-in session.

## 8. What's next (scale, not table stakes)

Multi-session holdout capture on a schedule; a semantic oracle (cross-source
agreement) for the shape-vs-meaning gap; the browser-bridge rung for pure-canvas
apps; reversible-write canaries. None of these are required for the guarantees
above; they widen coverage.
