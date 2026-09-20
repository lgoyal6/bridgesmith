# Prior art: what was borrowed, and what is actually new here

Bridgesmith's ideas are not sui generis, and pretending otherwise would be the
fastest way to lose a reader who knows the field. This file names what each
established project does better, what pattern was taken from it, and what is left
over that is genuinely this project's own.

## Sigstore / TUF — signing, trust anchors, key lifecycle

**What they do.** TUF defines a role-and-threshold model for signing metadata
with explicit key rotation, expiry and revocation. Sigstore makes signing
identity-based and records signatures in Rekor, an append-only transparency log,
so "this was valid at time T" is checkable against something the signer does not
control.

**Borrowed.** The trust-anchor discipline: a signature is only meaningful
relative to a key you already trust, never the key the artifact carries about
itself. `verifyCertificate(cert, trustedPublicPem)` exists because the earlier
version verified against `cert.publicKey`, which is self-consistency, not proof.
Also the habit of signing *metadata about* an artifact rather than the artifact
itself, which is what lets a replay manifest bind ordering and provenance.

**Not borrowed, and it matters.** No keyring, no thresholds, no rotation, no
revocation, no transparency log, no notion of an effective time.
`docs/KEY-LIFECYCLE-GAP.md` states that gap in full. Anyone needing real key
lifecycle should use TUF rather than this.

## Schemathesis — property-based API testing

**What it does.** Generates requests from an OpenAPI/GraphQL schema and checks
responses against it, finding places where an implementation contradicts its own
spec.

**Borrowed.** The adversarial instinct: a schema that only ever sees valid data
is untested. Bridgesmith's mutation suite (`src/certify/mutate.ts`) corrupts
recorded responses and requires the validator to reject them, so a schema that is
too loose shows up as a missed mutant instead of a green tick.

**Different problem.** Schemathesis starts from a spec someone wrote and tests an
implementation. Bridgesmith has no spec — it infers one from traffic and has to
decide whether the inference is trustworthy. That inverts the direction of doubt:
the artifact under test is the schema, not the service. It is also why the enum
evidence floors in `src/spec/infer.ts` exist; nothing in a hand-written spec
needs to ask "is this vocabulary actually closed, or did I only see one value".

## Pact — consumer-driven contract testing

**What it does.** A consumer records the interactions it depends on; the provider
verifies against those recorded pacts in CI, so a provider change that breaks a
consumer fails before deploy.

**Borrowed.** Recorded interactions as the unit of verification, and the idea
that a contract should be replayable by someone who was not there. Replay bundles
(`src/replay/bundle.ts`) are the same instinct: evidence plus a statement about
it, checkable offline.

**Different problem.** Pact assumes cooperation — the provider runs the
verification. Bridgesmith's provider is a third party who has never heard of it
and will not run anything. So the verification has to be one-sided, which is why
everything hinges on holdout separation and on refusing to serve what cannot be
re-derived, rather than on a handshake.

## OpenTelemetry — traces

**What it does.** A vendor-neutral data model and wire format for spans, with
SDKs, context propagation, sampling and exporters.

**Borrowed.** The data model and OTLP/JSON wire format, implemented directly in
`src/observe/trace.ts` — trace/span ids, parent links, typed attributes, status
codes, the `resourceSpans` envelope.

**Honestly not the SDK.** This emits OTLP a collector accepts. It is not
`@opentelemetry/*`: no cross-process context propagation, no sampler, no exporter
retry. The reason is dependency discipline, not a claim of improvement, and the
call sites are shaped so swapping the SDK in means replacing one file. What is
Bridgesmith's own is the *attribute vocabulary* (`ATTR` in that file): every
correlation key is a hash or an id, never payload, so an incident can be joined
to its spec and certificate by a collector that must never see the app's data.
`assertNoPayload()` enforces that as a check rather than a convention.

## Cedar / OPA — policy engines

**What they do.** Expressive, auditable policy languages with formal semantics,
designed so authorization decisions are reviewable separately from application
code.

**Borrowed.** The separation itself: policy as data, one decision point, and a
denial that names the rule rather than the value. `check()` in
`src/runtime/permissions.ts` returns a reason that can be logged without becoming
a disclosure — a habit Cedar's and OPA's decision logs make obvious.

**Deliberately not used.** The policy here is a fixed, closed schema —
operations, origins, methods, path templates, data classes, secret names, file
paths, one write flag. There are no user-supplied rules to evaluate, so a policy
*language* would add an evaluator, a parser and a new attack surface to express
what a struct already expresses exactly. If connector permissions ever become
user-authored, Cedar is the right answer and this struct is the wrong one.

## WASI — sandboxing

**What it does.** A capability-based syscall interface for WebAssembly, so
untrusted code runs with only the host imports it was granted.

**Evaluated and not used, with a reason.** WASI isolates untrusted *code*.
Bridgesmith generates no code: the adapter is one hand-written, spec-driven
executor, and a connector is data. Wrapping that executor in WASI would confine
the one component nobody needs protecting from, while the real capability
question — which origins, paths, files and secrets a spec may reach — would still
be decided on the other side of the boundary. A WASI module needs its host
imports whitelisted, and that whitelist *is* the permission manifest. So the
isolation layer here is capability mediation at egress.

This flips the moment `emit.ts` writes a runnable connector package. That code
would be generated, would execute, and would need real confinement — with this
manifest as its import whitelist rather than a substitute for it.

## What is left that is Bridgesmith's own

Stated narrowly, because the interesting claim is the combination, not any single
piece:

1. **Holdout certification of an inferred spec.** Deriving a spec from capture A
   and certifying it against an independent capture B, with the circularity check
   that refuses when B turns out to be A. Pact replays recorded interactions;
   Schemathesis tests against a given spec. Neither has to ask whether the
   evidence used to judge the spec is independent of the evidence that produced
   it, because neither infers the spec.

2. **Two false-green rates that never merge.** Schema false green (certified,
   then returned the wrong shape) and semantic false green (certified, shape
   still perfect, a declared invariant stopped holding) are measured and reported
   separately end to end, from the breaker through the eval table. The whole
   point is that a shape-only gate reports the second as a clean bill of health.

3. **Provenance and capability bound into the signed artifact.** The certificate
   does not merely say "this passed". It binds which evidence it passed against
   (derive and holdout manifest hashes, distinct by construction), which
   invariants held and over what evidence, which capability budget was granted,
   which executor configuration will run it, and what it supersedes — so a
   connector cannot widen its own permissions, drop an invariant, or rewrite its
   own provenance without re-certification.

4. **Certification you can re-run without the service.** A replay bundle lets
   someone who was not there reproduce the certification, or the incident,
   offline and with the network disabled — including the refusal to bundle
   evidence that still holds a credential.
