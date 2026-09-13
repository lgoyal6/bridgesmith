<div align="center">

# Bridgesmith

**An agent that builds its own integrations and refuses to use the ones it can't prove work.** Point it at an app with no connector; it reverse-engineers the API, generates an MCP server + REST connector, and only mounts what passes certification against held-out evidence.

[![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-5FA04E?logo=nodedotjs&logoColor=white)](package.json)
[![TypeScript strict](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.json)
[![Tests](https://img.shields.io/badge/tests-10%2F10-35d07f)](test)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

### ▶ [Watch the 2-minute demo](https://www.youtube.com/watch?v=HA4aw3cb8B4)

[What it is](#what-it-is) · [How it works](#how-it-works) · [Why it matters](#why-it-matters) · [Alignment](#how-it-aligns-with-the-hosts) · [Try it](#try-it) · [Reliability](#reliability-measured)

</div>

> Most connector tools ask, "how do I call this API?" Bridgesmith asks, "how do I *know* this connector works, and how do I know the moment it stops?"

![Bridgesmith building and certifying a connector live: it captures an app's API, derives a spec, runs the certification gate, and mints a signed birth certificate](docs/assets/demo.gif)

<sub>Silent capture from real runs: the terminal forges a Chess.com connector, certifies it against an independent holdout (40/40 mutation tests caught), and mints a signed certificate. Every log line and number is from an actual run; the fixtures are public, no-auth data.</sub>

## What it is

Bridgesmith is a **connector foundry** — a runtime that lets an AI agent extend itself. When an agent needs an app it has no integration for, Bridgesmith captures that app's own traffic, derives a spec, generates a connector exposing **both an MCP server and a keyed REST API** from one adapter core, and **certifies it against independent held-out evidence** before it can be used. Certified connectors get a signed birth certificate and enter a registry; drift at runtime triggers automatic re-certification and hot-swap, or demotion.

**The problem it solves.** Agents stall the moment they hit an app with no connector, and the connectors that exist for the long tail are unmaintained scrapers nobody trusts. The expensive part was never *writing* the integration — it's **knowing it works, and knowing the instant it breaks.** Bridgesmith makes the integration disposable and the *certificate* the durable artifact: an agent can manufacture a tool mid-task and have machine-checkable proof it is safe to call.

**Why it's important.** Every autonomous agent is one unverified tool call away from a silent failure — a connector that returns a schema-valid empty list, a field that quietly changed type, an endpoint that moved. Bridgesmith turns those silent failures into loud, typed, attributed ones, and never serves data it cannot certify.

## How it works

The core idea: **certification is the gate between *generated* and *mounted*.** A connector is derived from one capture and graded against a *different, independent* capture — never its own homework — plus a mutation suite that proves the gate rejects wrong data, not just confirms what it already saw.

```
 capture A ─┐                                   ┌── MCP server ──┐
            ├─ derive spec (from A only) ───────┤    adapter     ├── certified ops only
 capture B ─┘         │                         └── REST API ────┘
 (holdout)            ▼
              ┌───────────────────────────────────────────────┐
              │  CERTIFY                                        │
              │   1. holdout replay   (validate B vs the spec)  │
              │   2. mutation suite   (corrupt B → must reject) │
              │   3. live canary      (read-only, optional)     │
              │   repair loop (bounded): re-infer over A∪B      │
              └───────────────────────────────────────────────┘
                     │ all green?
             ┌───────┴────────┐
        yes  ▼                ▼  no
   sign birth cert       REFUSE — name the
   → registry → mount    failing / uncovered ops

 runtime:  every response schema-validated → drift trips the breaker →
           re-capture → re-certify → hot-swap   ·OR·   DEMOTE and refuse
```

**Access ladder (pluggable drivers, uniform certification).** Every rung produces the same `Exchange[]`, so everything downstream is identical:

1. **official-api** — a documented public API.
2. **derived-api** — reverse-engineer the app's own XHR/JSON traffic into a spec (`mitmproxy`-style capture → inference).
3. **browser-bridge** — UI automation for apps with no reachable XHR *(documented; not in v0)*.
4. **local-store** — desktop apps whose data lives in a local SQLite file (iMessage, Notes, Safari), read-only via the `sqlite3` CLI.

**The technical spine** (file-level, so every claim is checkable):

| Stage | What it does | Where |
| --- | --- | --- |
| Capture | HAR + live fetch; **secrets redacted at ingest** so fixtures never hold credentials | `src/capture/` |
| Derive | trie path-templating (varying id vs distinct resource by cardinality); schema inference with an **evidence floor** (a field is `required` only with enough samples) | `src/spec/` |
| Certify | independent-holdout replay + mutation suite + bounded repair loop | `src/certify/` |
| Sign | ed25519 birth certificate over canonical JSON; on-disk registry | `src/registry/` |
| Serve | one spec-driven adapter → MCP + REST surfaces, exposing certified ops only | `src/codegen/`, `src/surfaces/` |
| Guard | runtime schema gate (shared validator), circuit breaker, **false-green rate**, self-heal | `src/runtime/` |

The LLM plans (which tier, when to re-capture, when to refuse); everything that produces a guarantee is deterministic code, so there is no generated-code failure surface to trust.

## Why it matters

A working connector is a snapshot; a *certified* one is a claim you can re-check. Bridgesmith is built so three things are structurally impossible: mounting an uncertified tool, mounting an operation with no held-out evidence, and returning schema-invalid data. It does **not** claim "never fails" — it claims **no failure is silent**. Every outcome is a typed, counted event (`ok | schema-violation | http-error | network-error | refused | anomaly`), and drift is met with re-certification or refusal, never a quiet wrong answer.

## How it aligns with the hosts

Bridgesmith uses **no sponsor SDK** — the hackathon named none, and its own thesis is the point. But it is aimed squarely at what the host and judges are building:

- **Lemma (host) — silent failures in production agents.** Bridgesmith's whole design is to convert silent tool failures into loud, attributed, traced ones, and its false-green rate measures exactly the "certified-but-actually-wrong" gap Lemma detects. It's the same worldview implemented at mount time and runtime. **It could feed Lemma** a certificate + drift signal per connector, so their traces start with a ground-truth spec to diff against.
- **Arga Labs (judge) — sandboxes that rehearse agents before they go live.** "Certify against held-out evidence before mounting" is rehearse-before-prod as a runtime primitive; the mutation suite is an adversarial test harness. **It could complement Arga** as the live-side counterpart to their pre-live twins: re-certify against reality when the app drifts.
- **Userlens (judge) — the integration long tail.** Manufacturing certified connectors for apps with no API *is* the long-tail problem Userlens fields weekly. **It could help Userlens** turn "can you integrate with X?" into a forge-and-certify step instead of a maintenance liability.

## External apps

The demo agent spans four external apps — two via connectors Bridgesmith builds and certifies itself, two established:

1. **Devpost** — connector manufactured + certified live from its public API (no prior connector used).
2. **Chess.com** — second connector manufactured + certified live (public API).
3. **Notion** — established; the agent writes certified-connector results into it.
4. **Slack** — established; the agent posts a run summary.

Plus **iMessage** as the local-store tier — an app with no network API at all, given one read-only.

## Try it

```bash
pnpm install && pnpm build
pnpm test                              # 10 tests, all green

# Forge + certify a connector from a public API (two independent capture slices):
node dist/cli/index.js forge devpost \
  --derive  "https://devpost.com/api/hackathons?page=1,https://devpost.com/api/hackathons?page=2,https://devpost.com/api/hackathons?page=3,https://devpost.com/api/hackathons?page=4,https://devpost.com/api/hackathons?page=5,https://devpost.com/api/hackathons?page=6" \
  --holdout "https://devpost.com/api/hackathons?page=7,https://devpost.com/api/hackathons?page=8,https://devpost.com/api/hackathons?page=9,https://devpost.com/api/hackathons?page=10" \
  --host devpost.com --min-required 4

node dist/cli/index.js list                                   # registry + certificate validity
node dist/cli/index.js call devpost get_api_hackathons --param page=12
node dist/cli/index.js serve devpost                          # REST facade: GET /manifest, POST /op/:opId
```

Reproduce the evidence:

```bash
pnpm tsx scripts/eval.ts            # the reliability table below, from live public APIs
pnpm tsx scripts/selfheal-proof.ts  # drift → hot-swap → demote timeline
```

## Reliability, measured

From `scripts/eval.ts` against live public APIs (no auth, no secrets). Derive and holdout are **independent** captures; the probe uses inputs never seen during either.

| Connector | Certified | Holdout | Mutants caught | Unseen-input probe | Silent failures |
| --- | --- | --- | --- | --- | --- |
| chess.com | 1/1 | 8 | 40/40 | 3/4 | **0** |
| devpost | 1/1 | 4 | 40/40 | 5/5 | **0** |

The chess.com miss is the point: at 8 holdout samples one field was over-constrained and an unseen player tripped it — and the runtime gate caught it **loudly** as a schema violation, never returning wrong data. Certification confidence scales with evidence; the false-green rate is how we measure it. Full discussion in [`docs/RELIABILITY-BRIEF.md`](docs/RELIABILITY-BRIEF.md).

## What works / what does not

| Area | Status |
| --- | --- |
| Derived-api + local-store tiers, end to end | **Works.** verified on live Chess.com/Devpost + SQLite. |
| Independent-holdout certification + mutation suite | **Works.** 40/40 mutants caught on both live targets. |
| Signed certificates, registry, MCP + REST surfaces | **Works.** |
| Self-heal (drift → re-certify → hot-swap, or demote) | **Works.** `scripts/selfheal-proof.ts`. |
| Browser-bridge tier (pure-UI apps) | **Not built.** documented T3 rung. |
| Semantic correctness (right type, wrong value) | **Not covered by design.** the gate proves shape, not meaning. |
| Write/mutating operations | **Read-first.** writes are never live-canaried yet. |

## Honest scope

Reverse-engineering a private API can violate an app's ToS; Bridgesmith is run only against **public, no-auth data** or **your own session reading your own data**, never a scraped app-wide secret or a bypassed protection. Captured traffic is redacted at ingest. "Certified" means *consistent with independent held-out evidence and robust to schema mutation* — not *provably correct*.

## Demo

Video (≤2 min): **https://www.youtube.com/watch?v=HA4aw3cb8B4**

MIT licensed.
