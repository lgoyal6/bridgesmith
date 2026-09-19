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
pnpm install --frozen-lockfile && pnpm build && pnpm test
```

Expected: TypeScript compiles with no errors, and **44/44 vitest tests pass**
across 6 files (`test/pipeline.test.ts`, `test/localstore.test.ts`,
`test/selfheal.test.ts`, `test/certificate.test.ts`, `test/provenance.test.ts`,
`test/workflow.test.ts`). CI runs exactly this: `.github/workflows/ci.yml`.

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
| ed25519-signed, tamper-evident birth certificates | `src/registry/certificate.ts` (`issueCertificate`, `verifyCertificate`); tamper test in `test/pipeline.test.ts` |
| Certificates verify against the registry's OWN key (`.registry-key.pub`), never the key the certificate carries; no anchor => nothing is served | `src/registry/certificate.ts` (`loadTrustAnchor`, `verifyCertificate(cert, trustedPublicPem)`), `src/registry/registry.ts` (`load`); `test/certificate.test.ts` V1, V3, V8, V9 |
| A mounted `spec.json` must hash to its certificate's `specHash`, so only certified operations can be mounted | `src/spec/derive.ts` (`specHashOf`), `src/registry/registry.ts` (`load`); `test/certificate.test.ts` V5, V6, V6b |
| An invalid latest version never shadows an older fully valid one | `src/registry/registry.ts` (`latest`); `test/certificate.test.ts` V2, V7 |
| Every certification records WHAT evidence it ran against: origins, driver, timestamp, redacted exchange count, per-exchange body hashes, set identity, secret-scan verdict, toolchain | `src/capture/manifest.ts` (`buildCaptureManifest`), `src/core/types.ts` (`CaptureManifest`); `test/provenance.test.ts` P1-P5 |
| Derive and holdout manifest hashes are signed into the certificate, and a holdout that is a copy of the derive capture is refused as circular | `src/certify/certify.ts` (`isSameEvidence` gate), `src/registry/certificate.ts`; `test/provenance.test.ts` P8, P9 |
| Rewriting a connector's recorded provenance un-mounts it | `src/registry/registry.ts` (`load`, manifest-hash check); `test/provenance.test.ts` P10, P11 |
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
- Semantic correctness (right type, wrong value): out of scope by design — the gate proves shape, not meaning.
- Write/mutating operations: read-first; writes are never live-canaried. Workflow
  certification of non-idempotent steps runs only against replayed fixtures
  (`src/certify/replay.ts`), never against a live third party.
- iMessage typedstream message-body decode: reads `text` + metadata only.

See the "What works / what does not" table in `README.md` for the same list in
human form. Nothing in the README claims a capability this file does not map to a
file.
