# The trust chain, end to end

Every link below names the file that implements it and the test that would fail
if it were removed. Nothing here asks you to take a claim on faith; the mutation
harness (`python3 .agent-work/mutate.py`) exists to prove each link is load
bearing rather than decorative.

```
  app traffic
      │  capture driver stamps `capturedBy` on every exchange
      ▼
┌─────────────────┐
│ 1. CAPTURE      │  secrets redacted at ingest, before anything is written
│                 │  redaction policy is DATA, versioned, and hashed
└────────┬────────┘
         │  CaptureManifest: origins, driver, time, per-body hashes,
         │  secret-scan verdict, toolchain, setId (identity of the EVIDENCE)
         ▼
┌─────────────────┐
│ 2. DERIVE       │  spec inferred from capture A only; the holdout never
│                 │  flows through here. Derive manifest embedded in the spec,
│                 │  so specHash covers provenance.
└────────┬────────┘
         │  a least-privilege PermissionManifest is derived with it:
         │  one origin, observed methods, observed paths, read-only, no secrets
         ▼
┌─────────────────┐
│ 3. CERTIFY      │  against capture B. Refuses outright if B's setId equals
│                 │  A's - certifying against your own derive capture is circular
│   schema        │  holdout replay + mutation suite, per operation
│   semantic      │  declared invariants, each with an evidence hash
│   workflow      │  ordering, state freshness, idempotency, auth, cleanup
└────────┬────────┘
         │  THREE distinct verdicts: schemaVerdict, semanticVerdict, verdict.
         │  "declared no invariants" is `not-declared`, never a semantic pass.
         ▼
┌─────────────────┐
│ 4. SIGN         │  ed25519 over canonical JSON, with the registry's own key
└────────┬────────┘
         │  the certificate binds: specHash, certifiedOps, certifiedInvariants
         │  (id + evidence hash), captureManifestHash, holdoutManifestHash,
         │  adapterHash, permissionsHash, predecessor, compat class
         ▼
┌─────────────────┐
│ 5. REGISTRY     │  six checks on EVERY read, all fail closed
└────────┬────────┘
         │  1 certificate verifies under .registry-key.pub (no anchor => nothing)
         │  2 the certificate names this app
         │  3 spec.json re-hashes to certificate.specHash
         │  4 the embedded capture manifest hashes to captureManifestHash
         │  5 declared invariants == certified invariants
         │  6 the adapter hash matches the executor configuration
         ▼
┌─────────────────┐
│ 6. PROMOTE      │  a new version is diffed against the current one and
│                 │  classified. Anything at or above `conditional` needs an
│                 │  explicit approval; `unknown` fails closed.
└────────┬────────┘
         ▼
┌─────────────────┐
│ 7. RUNTIME      │  permission gate -> request -> schema gate -> semantic gate
│                 │  a connector with no permission manifest gets no capability
└────────┬────────┘
         │  outcomes: ok | schema-violation | semantic-violation |
         │            http-error | network-error | refused | anomaly
         ▼
┌─────────────────┐
│ 8. BREAKER      │  two SEPARATE false-green rates: schema and semantic.
│                 │  They never borrow from each other.
└────────┬────────┘
         ▼
┌─────────────────┐
│ 9. INCIDENT     │  a signed replay bundle carrying the failing evidence,
│                 │  replayable offline with zero network calls
└─────────────────┘
```

## Link by link

| # | Claim | Implementation | Falsified by removing it |
| --- | --- | --- | --- |
| 1 | Secrets never reach a fixture, certificate, bundle, log or diff | `src/capture/redact.ts` (`redactExchange`, `scanForSecrets`, `REDACTION_POLICY`) | `P4`, `P5`, `B15`, `B16`, `S16`, `T8`, `T9` |
| 2 | Provenance is bound to the spec and signed into the certificate | `src/capture/manifest.ts`, `src/spec/derive.ts` | `P8`, `P10` |
| 2 | Every spec carries a least-privilege capability budget | `src/runtime/permissions.ts` (`derivePermissions`) | `N1`, `N3` |
| 3 | A holdout that is the derive capture is refused as circular | `src/certify/certify.ts` (`isSameEvidence`) | `P9` |
| 3 | A closed vocabulary needs evidence that it is closed | `src/spec/infer.ts` (`MIN_ENUM_VALUES`, `MIN_ENUM_SUPPORT`) | `I1`, `I3` |
| 3 | Repair can always see the holdout | `src/spec/infer.ts` (`stratify`) | `I4` |
| 3 | An invariant that inspected nothing is refused, not passed | `src/certify/semantic.ts` (`evidenceIn`) | `S2` |
| 3 | Schema, semantic and mount verdicts stay distinct | `src/certify/certify.ts` | `S1b`, `S1c`, `S1d` |
| 4 | Verification is anchored to the registry's own key | `src/registry/certificate.ts` | `V1`, `V9`, `V10` |
| 5 | Six fail-closed checks on every registry read | `src/registry/registry.ts` (`load`) | `V6`, `V6b`, `V8`, `P10`, `S15` |
| 6 | A breaking change cannot inherit the old certificate | `src/registry/compat.ts`, `Registry.promote` | `C12` |
| 6 | A superseded version stays verifiable and replayable | `Registry.at` | `C13` |
| 7 | No permission manifest means no capability | `src/codegen/adapter.ts` | `N14` |
| 7 | Redirects are re-checked at every hop | `src/runtime/permissions.ts` (`guardedFetcher`) | `N11`, `N12` |
| 8 | Schema and semantic false greens are separate rates | `src/runtime/breaker.ts` | `S11`, `S11b` |
| 9 | An incident replays offline and reproduces the failure | `src/replay/bundle.ts`, `src/observe/incident.ts` | `B2`, `T6`, `T7` |

## Where the chain stops

- **Key lifecycle.** One key, no rotation, no revocation, no effective-time
  verification. See `docs/KEY-LIFECYCLE-GAP.md` for exactly what would have to
  exist first. A compromised `.registry-key` today invalidates everything it
  signed, with no partial remedy.
- **General semantic correctness.** The semantic layer covers six named,
  declared invariants. A connector that declares none is certified shape-only,
  and the report says `semanticVerdict: "not-declared"` rather than anything that
  reads as a pass.
- **Live writes.** Write workflows are certified against replayed fixtures only.
  No third-party service is ever mutated to demonstrate correctness.
- **Code confinement.** The permission layer mediates egress; it does not
  sandbox executing code. The trusted runtime executes no generated code.
  Optional generated .NET clients run in the caller's process and can only call
  the guarded REST facade. See the header of `src/runtime/permissions.ts`.
