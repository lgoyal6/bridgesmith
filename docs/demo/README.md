# Bridgesmith connector lab and evidence explorer

The main page calls `api/run.ts`, which runs `src/demo/lab.ts` through the
existing derive, certify, registry and adapter implementations. Visitors can
change a bounded in-process synthetic catalog, inject a holdout or runtime
fault, or exercise certificate tampering, wrong-root validation, retirement,
revocation and fresh certification. No caller URL, code or credentials are
accepted. Each request creates and removes an isolated temporary registry.

Run locally from the repository root:

```sh
pnpm install --frozen-lockfile
pnpm exec tsx scripts/lab-server.ts
```

Open `http://127.0.0.1:4318`. Deploy the repository root with `vercel.json`;
deploying only this directory omits the engine endpoint. The API limits inputs
to 2048 bytes, 12 catalog entries and a 48-character search string. It has no
network fetcher or external side effects. The same-origin browser clears
results after edits, rejected requests and timeouts.

Trust is pinned before issuance within each ephemeral run. It is not an
independent production registry. The expiry scenario advances the evaluation
clock to the signed deadline; trusted historical time and broader semantic
coverage remain open. A retirement scenario refuses the old certificate;
recovery runs the certifier again before issuing under the active key.

## Saved evidence

The separate `saved.html` page reads the committed Devpost v1 connector spec, certification
report, and certificate. It checks the copied files against pinned SHA256
values and confirms that the three recorded spec hashes agree.

Regenerate the public bundle from the repository root:

```sh
python3 scripts/export_demo_evidence.py
```

The saved page does not contact Devpost, certify a new connector, mount a connector,
or validate an independent registry trust root. The saved certificate contains
a public key and signature, but the repository does not publish the external
root and expected keyring head needed for rollback-aware trust verification.
