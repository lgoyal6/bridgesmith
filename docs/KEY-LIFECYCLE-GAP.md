# Key lifecycle: what exists, what does not, and why nothing was added

**Status: not implemented, deliberately.** This document is the deliverable.

Bridgesmith's whole trust story rests on one signing key. That makes key
lifecycle the most obvious next feature and the easiest one to get wrong in a
way that is worse than absence: a rotation endpoint that leaves every previously
issued certificate trusted forever looks like a security feature and is a
liability. This file records exactly where the line is.

## What the registry persists today

| Thing | Where | Status |
| --- | --- | --- |
| One ed25519 key pair per registry | `connectors/.registry-key{,.pub}` (`src/registry/certificate.ts`) | present |
| Trust anchor = the registry's own public key | `loadTrustAnchor()`; absent anchor fails closed | present |
| Stable short key identity | `keyId()` = first 16 bytes of SHA-256 over SPKI DER | present |
| Key identity named by an artifact | replay manifests carry `keyId` and verify it (`src/replay/bundle.ts`) | present |
| Certificate lineage | signed `predecessor` + `compat` on every certificate | present |
| Issue time on a certificate | signed `issuedAt` | present |

## What is missing, and what each one actually requires

1. **A keyring.** There is one key pair at one path. Rotation needs a set of key
   identities with per-key metadata, and `ensureRegistryKey()` currently
   generates-or-reads a single pair. Rotating today means overwriting the file,
   which silently invalidates every certificate ever issued — with no way to tell
   that apart from a forgery.

2. **Validity windows.** No key carries `notBefore`/`notAfter`, so there is no
   notion of two keys being simultaneously valid during a handover. Without
   overlapping windows, rotation is a hard cutover with an outage in the middle.

3. **Revocation.** There is no revocation record and no place to put one. A
   revocation list is only meaningful if it is itself signed and monotonic;
   otherwise removing an entry is as easy as adding one.

4. **Verification at an effective time.** `verifyCertificate(cert, anchor)` asks
   "does this verify now". Rotation and revocation both require "did this verify
   at time T", which means `issuedAt` has to become trusted input rather than a
   signed-but-unused field — and `issuedAt` is chosen by the signer, so it needs
   an external time source or a transparency log to be worth anything.

5. **Reissue / invalidation policy.** Nothing decides what happens to live
   certificates when a key is retired: reissue under the new key, or invalidate
   and force re-certification. Both are defensible; neither is implemented, and
   picking one silently in code would be the wrong way to decide it.

6. **Compromise recovery.** A compromised-key drill needs 1–5 first. Simulating
   recovery without them would demonstrate a procedure the system cannot perform.

## Why this was not built

The build plan's rule is explicit: do not add key rotation or revocation until
the storage model and the tests can make the claim true end to end, and do not
add a rotation endpoint that leaves old certificates effectively trusted forever.
Every item above is a storage-model change, not a function. Implementing the
surface without the model would produce exactly the artifact the rule forbids.

## The honest claim, as it stands

Bridgesmith verifies certificates against a single registry-owned trust anchor
and fails closed without one. It does **not** support key rotation, revocation,
effective-time verification, or recovery from a compromised key. A compromised
`.registry-key` today means every certificate that key signed must be treated as
untrusted, and the only remedy is to re-certify every connector under a new key.

## What would have to land first

A signed keyring artifact (`keys.json`: key id, public key, `notBefore`,
`notAfter`, `revokedAt`, revocation reason), itself anchored — most likely by
requiring each entry to be signed by its predecessor so the chain is verifiable
from a single root. Certificates would name the `keyId` that signed them (they
carry the public key today, but verification is anchored to one file rather than
resolved through a keyring). `verifyCertificate` would take an effective time and
resolve the key through the ring. Only then do rotation, revocation and a
compromise drill have something true to assert.

Prior art worth reading before building it: **TUF** for the role/threshold and
key-rotation model, and **Sigstore/Rekor** for why an append-only transparency
log is what makes "valid at time T" mean something when the signer picks the
timestamp.
