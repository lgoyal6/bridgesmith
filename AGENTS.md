# AGENTS.md — machine-readable map of this repository

This file is for automated reviewers and coding agents. Every claim below names
the file that implements it, so you can verify by reading, not by trusting.

## What this is (one line)

An agent that manufactures its own app connectors and certifies each one against
independent held-out evidence before mounting it; it exposes each connector as
both an MCP server and a REST API, and refuses or self-heals rather than serving
data it cannot certify.

## Verify in one command

```bash
pnpm install --frozen-lockfile && pnpm build && pnpm typecheck && pnpm test
```

Expected: TypeScript compiles with no errors and **157/157 vitest tests pass**
across 14 files (`pipeline`, `localstore`, `selfheal`, `certificate`, `dotnet`,
`provenance`, `workflow`, `workflow-state`, `semantic`, `infer`, `compat`,
`bundle`, `permissions`, `observe`). CI runs this: `.github/workflows/ci.yml`.

`pnpm build` typechecks `src` only (`tsconfig.json` has `"include": ["src"]`).
`pnpm typecheck` covers `src`, `test` and `scripts` via `tsconfig.test.json`, so
a type-broken test cannot sit green behind a passing build.

Known environment note: on pnpm 12, `pnpm install --frozen-lockfile` exits
non-zero with `ERR_PNPM_IGNORED_BUILDS: esbuild`, despite the
`onlyBuiltDependencies` allowlist in `pnpm-workspace.yaml`. Dependencies still
install; build, typecheck and test are the real gates, which is why CI runs
`pnpm install || true`.

Mutation harness (the tests that prove the tests):

```bash
python3 .agent-work/mutate.py          # disables one mechanism at a time, expects red
python3 .agent-work/mutate.py compat   # or filter by label substring
```

It disables one mechanism at a time and reports which tests go red. A mutation
nothing catches is a control that proves nothing; the two that are currently
uncaught are listed with the reason they are unreachable rather than hidden.

Generated .NET 8 client proof (requires a .NET 8 SDK):

```bash
DOTNET=/path/to/dotnet pnpm proof:dotnet
```

This creates a client from an actual partial certification, compiles it without
third-party packages, calls a certified operation through the keyed facade, and
proves the uncovered operation is absent from C# and refused over REST.

Runnable proofs (all read-only; nothing mutates a third-party service):

```bash
pnpm tsx scripts/eval.ts                   # reliability table, live public APIs
pnpm tsx scripts/replay-proof.ts           # certify live, then replay offline with fetch disabled
pnpm tsx scripts/drift-proof.ts            # schema drift + semantic false green, detected and replayed
pnpm tsx scripts/write-workflow-proof.ts   # a certified WRITE workflow, replayed fixtures only
pnpm tsx scripts/selfheal-proof.ts         # drift -> hot-swap -> demote timeline
```

Optional live demo against public APIs (needs network, no credentials):

```bash
pnpm demo   # scripts/demo.sh — forges Chess.com + Devpost, serves REST, iMessage local tier, self-heal
```

## Claim → implementation

| Claim | File(s) |
| --- | --- |
| Spec derived from capture A only; trie path-templating; evidence-floored `required` inference | `src/spec/derive.ts`, `src/spec/paths.ts`, `src/spec/infer.ts` |
| Certification runs against an INDEPENDENT holdout (capture B), not the derive capture | `src/certify/certify.ts` (`certify()` takes `holdout`; derive capture only used for repair re-inference) |
| Mutation suite proves the gate rejects wrong data, not just confirms it | `src/certify/mutate.ts`, asserted in `test/pipeline.test.ts` |
| Uncertified / uncovered operations are refused, never mounted | `src/certify/certify.ts` (`refusedOps`, `uncoveredOps`); surfaces expose only `cert.certifiedOps` in `src/surfaces/mcp.ts`, `src/surfaces/rest.ts` |
| Typed .NET 8 packages expose only certified operations and bind every call to the exact app, certificate version, spec hash, and certified operation set | `src/codegen/dotnet.ts`; `test/dotnet.test.ts`; executable proof in `scripts/dotnet-proof.ts` |
| ed25519-signed, tamper-evident birth certificates | `src/registry/certificate.ts` (`issueCertificate`, `verifyCertificate`); tamper test in `test/pipeline.test.ts` |
| Certificates verify against the registry's OWN key (`.registry-key.pub`), never the key the certificate carries; no anchor => nothing is served | `src/registry/certificate.ts` (`loadTrustAnchor`, `verifyCertificate(cert, trustedPublicPem)`), `src/registry/registry.ts` (`load`); `test/certificate.test.ts` V1, V3, V8, V9 |
| A mounted `spec.json` must hash to its certificate's `specHash`, so only certified operations can be mounted | `src/spec/derive.ts` (`specHashOf`), `src/registry/registry.ts` (`load`); `test/certificate.test.ts` V5, V6, V6b |
| An invalid latest version never shadows an older fully valid one | `src/registry/registry.ts` (`latest`); `test/certificate.test.ts` V2, V7 |
| Every certification records WHAT evidence it ran against: origins, driver, timestamp, redacted exchange count, per-exchange body hashes, set identity, secret-scan verdict, toolchain | `src/capture/manifest.ts` (`buildCaptureManifest`), `src/core/types.ts` (`CaptureManifest`); `test/provenance.test.ts` P1-P5 |
| Derive and holdout manifest hashes are signed into the certificate, and a holdout that is a copy of the derive capture is refused as circular | `src/certify/certify.ts` (`isSameEvidence` gate), `src/registry/certificate.ts`; `test/provenance.test.ts` P8, P9 |
| Rewriting a connector's recorded provenance un-mounts it | `src/registry/registry.ts` (`load`, manifest-hash check); `test/provenance.test.ts` P10, P11 |
| Semantic invariants carry a stable id, scope, severity, evidence source and a deterministic evidence hash; schema, semantic and mount verdicts stay distinct | `src/certify/semantic.ts`, `src/core/types.ts` (`SemanticInvariant`, `SemanticCheck`), `src/certify/certify.ts`; `test/semantic.test.ts` S0-S1e |
| An invariant that inspected nothing is refused, never counted as coverage | `src/certify/semantic.ts` (`evidenceIn`, `certifySemantics`); `test/semantic.test.ts` S2 |
| Six named semantic false-green classes: totals, cross-endpoint id agreement, vocabulary, ordering, pagination union, unit drift | `src/certify/semantic.ts`; `test/semantic.test.ts` S4-S9 |
| Schema false-green and semantic false-green are separate rates that never borrow from each other | `src/runtime/breaker.ts` (`falseGreenRate`), `src/codegen/adapter.ts`; `test/semantic.test.ts` S11, S11b, `scripts/eval.ts` |
| A connector cannot decide for itself which invariants it passed | `src/registry/registry.ts` (`load`, check 5); `test/semantic.test.ts` S13-S15 |
| A refusal reason is attributable without disclosing captured credentials | `src/certify/semantic.ts` (`safeDetail`); `test/semantic.test.ts` S16 |
| A closed vocabulary is only inferred with evidence that it is closed, and repair can always see the holdout | `src/spec/infer.ts` (`MIN_ENUM_VALUES`, `MIN_ENUM_SUPPORT`, `stratify`); `test/infer.test.ts` I1-I5 |
| Two certified versions are diffed and classified (identical / additive / documentation / conditional / breaking / unknown); anything at or above conditional needs explicit approval, and `unknown` fails closed | `src/registry/compat.ts`, `Registry.promote`; `test/compat.test.ts` C1-C12 |
| A superseded version stays fully verifiable and replayable through the same gate | `Registry.at`, `Registry.versions`; `test/compat.test.ts` C13 |
| A certification or an incident can be reproduced offline from a signed replay bundle, with the network disabled | `src/replay/bundle.ts`, `scripts/replay-proof.ts`; `test/bundle.test.ts` B1-B18 |
| Tampering with any bound field of a replay manifest fails verification, including reordering the evidence | `src/replay/bundle.ts` (`verifyBundle`); `test/bundle.test.ts` B6-B13 |
| Workflows certify cursor advancement, loop termination, per-step authorization, and compensation of completed steps on failure | `src/certify/workflow.ts`; `test/workflow-state.test.ts` X1-X16 |
| Only the valid ordering of a dependency chain certifies; the other five permutations are refused by name | `src/certify/workflow.ts`; `test/workflow-state.test.ts` X13, X14 |
| A connector runs under a certified, least-privilege capability manifest: origins, methods, paths, data classes, secrets, file paths, write policy, redirects. Deny by default, read-only by default | `src/runtime/permissions.ts`, `src/codegen/adapter.ts`; `test/permissions.test.ts` N1-N19 |
| Redirects are re-checked at every hop, so an allowed origin cannot redirect to a disallowed one | `src/runtime/permissions.ts` (`guardedFetcher`); `test/permissions.test.ts` N11-N13 |
| OTLP-shaped spans cover capture through replay, correlated by hash and id only, with payload-sized attributes rejected | `src/observe/trace.ts`; `test/observe.test.ts` T1-T4 |
| Schema drift and semantic false greens produce distinct, attributable incidents that replay offline | `src/observe/incident.ts`, `scripts/drift-proof.ts`; `test/observe.test.ts` T5-T9 |
| Multi-step read workflows are certified as ordered steps with preconditions, extracted state, postconditions, idempotency class and cleanup; only passing workflows are mounted | `src/certify/workflow.ts`, `src/certify/replay.ts`; `test/workflow.test.ts` W1-W3 |
| Workflow certification catches out-of-order steps, stale state reuse, a retry that would duplicate a non-idempotent action, cleanup failure, and a schema-valid response that violates a postcondition | `src/certify/workflow.ts` (`runWorkflow`); `test/workflow.test.ts` W4-W10 |
| Runtime never returns schema-invalid data (one validator shared with certification) | `src/codegen/adapter.ts`, `src/runtime/validate.ts` |
| Drift trips a breaker → re-certify → hot-swap, or demote and refuse | `src/runtime/selfheal.ts`, `src/runtime/breaker.ts`; proven in `test/selfheal.test.ts` |
| False-green rate (certified-then-failed-live) is measured | `src/runtime/breaker.ts` (`falseGreenRate`) |
| Local-store access tier (SQLite, e.g. iMessage), read-only | `src/drivers/localstore.ts`, `src/drivers/imessage.ts`; `test/localstore.test.ts` |
| Secrets redacted at capture ingest; fixtures never hold credentials | `src/capture/redact.ts` (`redactExchange`, `assertRedacted`) |
| Reproducible reliability numbers | `scripts/eval.ts`; discussion in `docs/RELIABILITY-BRIEF.md` |

## Scope boundaries (what is NOT implemented)

- Browser-bridge access tier (pure-UI apps with no reachable XHR): documented, not built.
- **General** semantic correctness: still out of scope, and deliberately so. What
  exists is a set of DECLARED, named invariants (`semanticInvariants` in the spec)
  covering six specific ways a well-typed response lies. A connector that declares
  none is certified shape-only, and the report says `semanticVerdict:
  "not-declared"` rather than anything resembling a pass.
- Write/mutating operations: read-first; writes are never live-canaried. Workflow
  certification of non-idempotent steps runs only against replayed fixtures
  (`src/certify/replay.ts`), never against a live third party. See
  `scripts/write-workflow-proof.ts` for a fully certified write workflow that
  touches nothing real.
- **Key lifecycle: not implemented.** One signing key, no rotation, no
  revocation, no effective-time verification, no compromise recovery. A
  compromised `.registry-key` invalidates every certificate it signed, with no
  partial remedy. `docs/KEY-LIFECYCLE-GAP.md` states exactly what would have to
  exist first and why a partial implementation would be worse than none.
- **Sandboxing is capability mediation at egress, not code confinement.** The
  trusted runtime executes no generated code. Optional generated .NET clients
  run in the caller's process and can only reach the guarded facade; a WASI-style
  sandbox inside Bridgesmith would isolate the wrong component. See the header of
  `src/runtime/permissions.ts` and `docs/PRIOR-ART.md`.
- **OpenTelemetry**: the data model and OTLP/JSON wire format are implemented
  directly, not via `@opentelemetry/*`. No context propagation across processes,
  no sampler, no exporter retry.
- iMessage typedstream message-body decode: reads `text` + metadata only.

Further reading: `docs/TRUST-CHAIN.md` (every link from capture to breaker, with
the test that falsifies it), `docs/PRIOR-ART.md` (what was borrowed from
Sigstore/TUF, Schemathesis, Pact, OpenTelemetry, Cedar/OPA and WASI, and what is
left that is this project's own), `docs/KEY-LIFECYCLE-GAP.md`.

See the "What works / what does not" table in `README.md` for the same list in
human form. Nothing in the README claims a capability this file does not map to a
file.
