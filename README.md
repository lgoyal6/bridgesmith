# Bridgesmith

**An agent that manufactures its own certified integrations.** Give it a task
involving an app it has no connector for, and it discovers an access path,
generates a connector exposing **both an MCP server and a keyed REST API** from
one adapter core, **certifies it against held-out evidence**, and only mounts
what passes. When it cannot certify, it refuses and says which operations failed.
When a mounted connector drifts, it re-certifies and hot-swaps, or demotes.

> Built for the Multi-App AI Agent Hackathon. The challenge: "Build one useful,
> multi-step AI agent. Connect it to at least three external apps. Show how you
> know it works." Bridgesmith's answer to *show how you know it works* is the
> architecture, not a slide: certification is the gate between generated and
> mounted.

## Project overview

Bridgesmith is a runtime that lets an agent extend itself: when it needs an app it
has no connector for, it captures that app's traffic, derives a spec, generates a
connector, and **certifies it against independent held-out evidence** before
mounting. Certified connectors are exposed simultaneously as an **MCP server**
(for any MCP client) and a **keyed REST API**. Refusal is first-class: what
cannot be certified is not mounted, and drift at runtime triggers re-certify +
hot-swap or demotion.

## External apps (minimum 3)

The demo agent spans four external apps, two via connectors Bridgesmith builds and
certifies itself, two established:

1. **Devpost** — connector *manufactured and certified live* from its public API
   (`connectors/devpost/`, forged via the CLI; no prior connector used).
2. **Chess.com** — second connector manufactured and certified live (Tier-1
   public API; see the eval table).
3. **Notion** — established app; the agent writes certified-connector results
   into it (via the connected Notion MCP).
4. **Slack** — established app; the agent posts a run notification (self-DM).

## Setup instructions

```bash
pnpm install
pnpm build
pnpm test                              # 10 tests, all green

# Forge + certify a connector from a public API (two independent capture slices):
node dist/cli/index.js forge devpost \
  --derive  "https://devpost.com/api/hackathons?page=1,https://devpost.com/api/hackathons?page=2,https://devpost.com/api/hackathons?page=3,https://devpost.com/api/hackathons?page=4,https://devpost.com/api/hackathons?page=5,https://devpost.com/api/hackathons?page=6" \
  --holdout "https://devpost.com/api/hackathons?page=7,https://devpost.com/api/hackathons?page=8,https://devpost.com/api/hackathons?page=9,https://devpost.com/api/hackathons?page=10" \
  --host devpost.com --min-required 4

node dist/cli/index.js list                                   # registry + certificate validity
node dist/cli/index.js call devpost get_api_hackathons --param page=12
node dist/cli/index.js serve devpost                          # REST facade on :8787
```

## Reliability testing

See [`docs/RELIABILITY-BRIEF.md`](docs/RELIABILITY-BRIEF.md) for the full brief.
Reproduce the numbers: `pnpm tsx scripts/eval.ts` (live public APIs, no
secrets) and `pnpm tsx scripts/selfheal-proof.ts` (drift → hot-swap → demote).

## Demo

Video (≤2 min): **[demo link — add before submitting]**

## What works / what does not

Written first, on purpose. Certification is only as honest as this section.

| Area | Status |
| --- | --- |
| Derive an OpenAPI-ish spec from captured JSON traffic | **Works.** `src/spec/derive.ts`, trie path-templating `src/spec/paths.ts`, schema inference `src/spec/infer.ts`. |
| Certify against an **independent** holdout capture (not the derive capture) | **Works.** `src/certify/certify.ts`; the derive capture is only reused for repair re-inference. |
| Mutation testing (prove the gate catches wrong data, not just confirms it) | **Works.** `src/certify/mutate.ts`, 40/40 mutants caught on both live targets. |
| Bounded generate-verify-repair loop | **Works.** capped, re-infers over A+B on holdout failure; refuses at the cap. |
| Signed, verifiable birth certificates + registry | **Works.** ed25519, `src/registry/certificate.ts`, `src/registry/registry.ts`. |
| MCP surface + keyed REST surface off one adapter | **Works.** `src/surfaces/mcp.ts`, `src/surfaces/rest.ts`. |
| Runtime schema gate (never return schema-invalid data) | **Works.** `src/codegen/adapter.ts`, one validator shared with certification `src/runtime/validate.ts`. |
| Self-heal: drift → re-certify → hot-swap, or demote | **Works.** `src/runtime/selfheal.ts`, `src/runtime/breaker.ts`. |
| Local-store tier (apps with no network API, e.g. iMessage) | **Works** on synthetic + real SQLite via the `sqlite3` CLI; `src/drivers/localstore.ts`, `src/drivers/imessage.ts`. |
| Browser-bridge tier (UI automation for apps with no reachable XHR) | **Not built.** Documented as the T3 rung; out of scope for v0. |
| Message-body typedstream decode for iMessage | **Not built.** We read `text` + metadata; full `attributedBody` decode is a not-now. |
| Semantic correctness (right *type*, wrong *value*) | **Not covered by design.** The gate proves shape, not meaning. See the brief. |
| Write/mutating operations | **Read-first.** Writes are never live-canaried; treat as unverified until a reversible-write canary lands. |

## How it works

```
capture A ─┐                              ┌─ MCP server ─┐
           ├─ derive spec (from A only) ──┤   adapter    ├─ certified ops only
capture B ─┘        │                     └─ REST API ───┘
 (holdout)          ▼
            CERTIFY: holdout replay + mutation suite + (optional) live canary
                    │  repair loop (bounded) ─ re-infer over A+B, re-check on B
                    ▼
            all green? ── yes → sign birth certificate → registry → mount
                       └─ no  → REFUSE (name the failing/uncovered ops)

runtime: every response schema-validated → drift trips breaker →
         re-capture → re-certify → hot-swap, or DEMOTE and refuse
```

The **access ladder** (pluggable drivers, uniform certification): official API →
derived API (reverse-engineer the app's own XHR) → browser bridge → local store.
Every rung produces `Exchange[]`; everything downstream is identical.

## Try it

```bash
pnpm install && pnpm build

# Forge a connector from a public API (two independent capture slices):
node dist/cli/index.js forge devpost \
  --derive  "https://devpost.com/api/hackathons?page=1,...,page=6" \
  --holdout "https://devpost.com/api/hackathons?page=7,...,page=10" \
  --host devpost.com --min-required 4

node dist/cli/index.js list            # registry + certificate validity
node dist/cli/index.js call devpost get_api_hackathons --param page=12
node dist/cli/index.js serve devpost   # REST facade: GET /manifest, POST /op/:opId
```

Reproduce the evidence:

```bash
pnpm test                              # 10 tests: derivation, holdout cert, refusal, self-heal, signing
pnpm tsx scripts/eval.ts           # the reliability table below, from live traffic
pnpm tsx scripts/selfheal-proof.ts # drift → hot-swap → demote timeline
```

## Reliability, measured

From `scripts/eval.ts` against live public APIs (no auth, no secrets):

| Connector | Tier | Certified | Holdout | Mutants caught | Unseen-input probe | Silent failures |
| --- | --- | --- | --- | --- | --- | --- |
| chess.com | derived-api | 1/1 | 8 | 40/40 | 3/4 | **0** (the 1 miss was caught as a schema violation) |
| devpost | derived-api | 1/1 | 4 | 40/40 | 5/5 | **0** |

The chess.com miss is the point: at 8 holdout samples a field can still be
over-constrained, and the runtime gate caught it **loudly** instead of returning
wrong data. Certification confidence scales with evidence; the false-green rate
is how we measure it (`src/runtime/breaker.ts`). Full discussion in
[`docs/RELIABILITY-BRIEF.md`](docs/RELIABILITY-BRIEF.md).

## Honest scope & boundaries

- Reverse-engineering a private API can violate an app's ToS. Bridgesmith is run
  only against **public, no-auth data** or **your own session reading your own
  data**. It never reuses an app-wide embedded secret and never bypasses a
  protection.
- Captured traffic is **redacted at ingest** (`src/capture/redact.ts`): auth
  headers, cookies, and token-like query params never reach fixtures.
- The REST facade is scoped to team use with a token, not a public proxy of a
  logged-in session.
- "Certified" means *consistent with independent held-out evidence and robust to
  schema mutation*, not *provably correct*. It proves shape, not meaning.
