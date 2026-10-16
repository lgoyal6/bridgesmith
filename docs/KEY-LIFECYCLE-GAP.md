# Key lifecycle: signed key history and recovery limits

**Status: local lifecycle implemented, external rollback protection pending.**

Previously, Bridgesmith's trust story rested on one signing key. The local
rotation and revocation behavior is now implemented; this file records its
guarantees and the limits that remain.

## What the registry persists today

| Thing | Where | Status |
| --- | --- | --- |
| Atomic current private/public key and keyring snapshot | `.registry-state.json` (mode 0600) | authoritative |
| Compatibility mirrors | `.registry-key{,.pub}`, `.registry-keyring.json` | non-authoritative |
| Initial root | `.registry-key-root.pub` | pinned by offline verifier |
| Stable short key identity | `keyId()` = first 16 bytes of SHA-256 over SPKI DER | present |
| Key identity named by an artifact | replay manifests carry `keyId` and verify it (`src/replay/bundle.ts`) | present |
| Certificate lineage | signed `predecessor` + `compat` on every certificate | present |
| Issue time on a certificate | signed `issuedAt` | present |
| Optional certificate expiry | signed `expiresAt`, enforced by the verifier clock | present; legacy certificates remain non-expiring |

## Original gaps and dispositions

1. **A keyring.** Implemented as a predecessor-signed sequence with stable key
   identities and status metadata.

2. **Key validity windows.** Keys have no `notBefore`/`notAfter`; rotation is a
   hard cutover, with no overlap period. Certificates may carry an optional signed `expiresAt` through
   `Registry.promote(..., { expiresAt })`. No expiry is added by default, and the
   CLI does not currently expose an expiry flag. Verifiers reject a certificate
   at or after that deadline using their local clock. Existing certificates
   without the field remain valid under the prior rules. A local clock does not
   provide trusted historical time.

3. **Revocation.** Implemented as a signed state transition. The active key can
   be revoked, which makes the registry fail closed until a replacement is
   rotated in.

4. **Verification at an effective time.** Signature checks establish current
   key trust. They do not prove historical validity because the signer chooses
   `issuedAt`. Historical decisions require an external time source or a
   transparency log; current rotation uses a hard cutover instead.

5. **Reissue / invalidation policy.** The approved policy is to invalidate old
   certificates and require fresh certification after rotation or revocation.

6. **Compromise recovery.** Replacement-key recovery exists, but no independent
   protected recovery authority or operational drill is evidenced.

## Implemented behavior

`.registry-state.json` atomically stores the current key pair with a signed
sequence anchored by the initial registry key in `.registry-key-root.pub`.
`.registry-key{,.pub}` and `.registry-keyring.json` are non-authoritative
compatibility mirrors; readers do not fall back to them when existing state is
corrupt. Each signed entry binds a key id, public key, active or revoked status,
time, reason, signer identity, and signature. Certificates name
their signing key id. Registry reads verify the chain and only accept a
certificate under the currently active key. Rotation retires the former key;
revocation leaves no active key until recovery rotates in a replacement. Both
operations make old-key certificates unmountable, and recovery requires fresh
certification.

Offline verifiers can call `verifyRegistryKeyring` with a root pinned outside the
registry and an optional expected head. A pinned root authenticates the history,
but detecting restoration of an older valid history also requires the verifier
to retain the latest expected head outside registry-controlled storage. The
registry does not claim rollback protection when that external state is absent.

The signed `changedAt` and certificate `issuedAt` values are signer-controlled.
They do not prove that a certificate was valid at a historical instant. Optional
certificate expiry is checked against the verifier local clock, which can be
wrong or manipulated. Trusted effective-time and transparency-log verification
remain unsupported, as does a protected recovery authority independent of the
current signing key.

## Concurrency and crash recovery

Initialization, certificate issuance, rotation and revocation share one directory
lock. This prevents two initializers from replacing each other's trust root and
keeps freshness validation and signing on the same key generation. Contention
fails with `EEXIST`; callers must retry only after the other writer finishes.
Readers still use the atomic state snapshot without taking the mutation lock.

A hard process kill may leave `.registry-keyring.lock`. Before removing it, stop
all registry writers, confirm the prior process is gone, and verify the saved
root, state and expected head. Removing an active writer's lock can break the
serialization guarantee. The local process tests do not establish power-loss
durability or an automatic recovery policy.

## Remaining limits

The current implementation does not provide trusted historical-time decisions,
automatic out-of-band head persistence, a separate recovery authority, or a
compromise-recovery drill. Operators must retain a pinned root and current head
outside the registry for rollback detection.

Prior art worth reading before building it: **TUF** for the role/threshold and
key-rotation model, and **Sigstore/Rekor** for why an append-only transparency
log is what makes "valid at time T" mean something when the signer picks the
timestamp.

The exported key initializer also takes the lifecycle lock. Payload signing uses
that initializer, so a direct caller cannot create a second key pair during first
initialization. Lifecycle writers use a private lock-assuming helper to avoid
nested acquisition. A competing call refuses with EEXIST and may retry later.
