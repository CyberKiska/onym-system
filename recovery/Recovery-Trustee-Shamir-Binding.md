---
status: draft
proposed: <author>
date: 23.09.2026
---

# Onym Recovery Trustee: Shamir Wire Binding

**Binding draft 1 — September 2026**

> Two correct implementations of the Shamir profile should produce the same
> bytes for the same envelope, session and contribution, and accept each
> other's signatures. This binding fixes those bytes and nothing else.

This document binds [Recovery-Trustee-Shamir.md](Recovery-Trustee-Shamir.md)
to concrete encodings. [Recovery-Trustee.md](Recovery-Trustee.md) and the
Shamir profile stay authoritative for meaning, roles and authority. The
binding fixes bytes for the objects they already define. It adds only the
values a trustee cannot operate without: an enrollment context, a first
factor and notification profile, and per-trustee session evidence.

The document distinguishes:

- **binding requirements**, which a conforming trustee and client follow;
- **rationale**, which explains a choice that is not forced; and
- **gaps**, where the binding knowingly stops short.

**Status.** A reference trustee core implements §§2–7 and produced the
vectors of §8. Its source will be linked here when published. A conforming
client, the trustee's storage and transport, and a deployment do not exist
yet. The binding identifier is `draft-1` until maintainers adopt it or assign
another (§12).

## 1. Problem

Shamir §4.1 says the profile pins canonical encodings, byte order, HPKE
`info`, AEAD associated data, SLIP-0039 parameters and fixtures. Today it pins
the suites and the SLIP-0039 parameters. It does not define:

- what `canonical(a, b, …)` means (§4.2, §6.2);
- the enrollment HPKE `info`: §5.2 step 5 lists its contents without order,
  encoding or domain tag;
- how a sealed value, its `enc` and its context travel;
- how identifiers, keys, digests, signatures, timestamps and durations are
  written;
- what a trustee policy contains: `candidateFactors`, `notifications`,
  `holderVeto` and `lapsePolicy` are placeholders;
- how factor evidence is bound to one session and one trustee.

Two implementations that differ on any of these reject each other's
signatures, even when both follow the profile.

## 2. Canonical encoding

**Binding requirement.** Objects use the canonical JSON of
[Discovery-Static-Ed25519.md](../discovery/Discovery-Static-Ed25519.md) §3:

- UTF-8, with a top-level object;
- no duplicate key at any depth;
- keys sorted by UTF-8 bytes at every level, arrays in order;
- no insignificant whitespace, and that section's pinned string escaping;
- only non-negative integers up to 2^53 − 1, never floats.

A signature covers the canonical object with only its own top-level field
removed, structurally: `holderAuthorization`, `candidateProof` or
`signature`. A reader verifies over re-canonicalized bytes; a writer emits
canonical bytes. Every object in §6 refuses unknown fields.

`canonical(a, b, …)` is the canonical JSON array of its elements, in order:
strings as strings, integers as numbers, objects as canonical objects. Every
tuple this binding introduces opens with a domain-tag string.

*Rationale.* Discovery's fixtures already agree across Rust, Swift and Kotlin.
Python's standard library reproduces them unchanged
(`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`),
so a client needs no custom serializer.

## 3. Field encodings

| Kind | Encoding | Fields |
|---|---|---|
| 256-bit identifiers | 64 lowercase hex digits | `enrollmentId`, `artifactId`, `sessionId`, `slot`, `trusteeChallenge` |
| Public keys | 64 lowercase hex digits of the raw 32 bytes | `authorizationPublicKey`, `encryptionPublicKey`, `proofPublicKey`, factor keys |
| Digests | `sha256:` followed by 64 lowercase hex digits | `policyDigest`, `identityBindingCommitment`, `artifactDigest`, `destinationKeysDigest`, `authorizationKeyDigest`, `trusteeKeyId` |
| Signatures and ciphertexts | Standard padded base64 (RFC 4648 §4), strict: missing padding and non-zero trailing bits are refused | `holderAuthorization`, `candidateProof`, `signature`, `sealedEnvelope`, `sealedContribution`, `ciphertext` |
| Timestamps | Exactly `YYYY-MM-DDTHH:MM:SSZ` | `createdAt`, `expiresAt`, `requestedAt`, `decidedAt` |
| Durations | `P[nD][T[nH][nM][nS]]`, at most six digits per component; no years, months or weeks | `cooldown`, `sessionLifetime` |
| Integers | JSON integers | `enrollmentSequence` (1 to 2^53 − 1), `memberIndex` (0–15), `memberThreshold`, `memberCount`, `maximumAttempts` |
| Component IDs | `onym:component:` followed by 1–64 of `[a-z0-9-]` | `trusteeComponentId`, `componentId` |

`recoveryMode` is `secret-restoration` until the identity profile supports
authority migration.

## 4. Digests and tuples

| Value | Definition |
|---|---|
| `artifactDigest` | SHA-256 of the canonical `ProtectedRecoveryArtifact` without `artifactDigest` |
| `authorizationKeyDigest` | SHA-256 of the raw 32-byte Ed25519 trustee-scoped authorization key |
| `trusteeKeyId` | SHA-256 of the raw 32-byte X25519 enrollment key the trustee publishes |
| `destinationKeysDigest` | SHA-256 of `canonical("onym-recovery-destination-keys-v1", destination)`, with the complete destination object |
| `sessionCommitment` | SHA-256 of the canonical session without `candidateEvidence` and `candidateProof` |
| Enrollment `info` | `canonical("onym-shamir-enrollment-v1", implementationProfileId, enrollmentId, enrollmentSequence, policyDigest, artifactId, artifactDigest, trusteeComponentId, slot, trusteeChallenge, authorizationKeyDigest)` |
| Recovery `info` | The Shamir §6.2 tuple, in order, as a canonical array, opening with its tag `onym-shamir-recovery-contribution-v1` |
| Factor message | `canonical("onym-recovery-factor-ed25519-session-v1", sessionCommitment, componentId, slot)` |
| `sealedContributionDigest` | SHA-256 of the raw sealed bytes |

The profile's `identityBindingCommitment` and artifact AAD (Shamir §4.2)
use the same array encoding. Their vectors are pending a conforming client.

## 5. HPKE framing

**Binding requirement:**

- RFC 9180 Base mode with KEM 0x0020, KDF 0x0001 and AEAD 0x0002, single-shot,
  one message per encapsulation.
- AAD is empty and all context goes in `info`, as RFC 9180 §8.1 asks of
  single-shot use.
- A sealed value is `enc (32 bytes) ‖ ciphertext ‖ tag`, written as base64.
- The fields that rebuild `info` travel in the enclosing object. The recipient
  rebuilds `info`, opens, and requires the plaintext to repeat each of those
  fields.
- **Enrollment:** the holder seals the signed share envelope to the trustee's
  published X25519 key, named by `trusteeKeyId`.
- **Recovery:** the trustee re-seals the exact decrypted envelope bytes to
  `destination.encryptionPublicKey`. The holder's signature therefore still
  verifies on the recovering device.

*Rationale.* The layout is exactly pyca/cryptography's single-shot output
(version 47 and later), so a Python client needs no framing code.

The trustee keeps the original sealed bytes and opens them at release with
the stored `info`. A ciphertext swapped in from another enrollment then fails
to open, even though anyone can seal to the published key.

## 6. Objects

### 6.1 Share envelope

The Shamir §4.4 envelope, with the encodings of §3 and this trustee policy:

```json
{
  "candidateFactors": ["onym:recovery-factor:ed25519-session-v1:<factor key hex>"],
  "cooldown": "P2D",
  "sessionLifetime": "P7D",
  "maximumAttempts": 3,
  "notifications": ["onym:recovery-notice:holder-poll-v1"],
  "holderVeto": "onym:recovery-veto:authorization-key-v1",
  "lapsePolicy": "onym:recovery-lapse:none-v1"
}
```

These are the proposed first factor and notification profile:

- **Factor.** Exactly one pre-enrolled Ed25519 key. The candidate proves it by
  signing the factor message of §4 for this trustee's slot.
- **Notice.** The holder's healthy device reads open sessions from the
  trustee, authenticated with the enrollment's trustee-scoped key. A notice
  exists from the moment a session is created.
- **Veto.** A cancellation signed by that same key, effective until release.
- **Lapse.** None: the offer is free.
- **Timing.** The cooldown is shorter than the session lifetime, and both sit
  inside the trustee's published limits.

A trustee refuses any other value with `invalid_policy` until a later
binding defines it.

### 6.2 Enrollment context

These are sent in clear next to a sealed envelope, so the trustee can rebuild
`info` before opening:

```json
{
  "implementationProfileId": "onym:recovery-implementation:shamir-trustees-slip39-v1",
  "enrollmentId": "<64 hex>",
  "enrollmentSequence": 1,
  "policyDigest": "sha256:<64 hex>",
  "artifactId": "<64 hex>",
  "artifactDigest": "sha256:<64 hex>",
  "trusteeComponentId": "onym:component:<id>",
  "slot": "<64 hex>",
  "trusteeChallenge": "<64 hex>",
  "authorizationKeyDigest": "sha256:<64 hex>"
}
```

### 6.3 Protected artifact

`protectionParameters` is `{"aead": "aes-256-gcm", "nonce": "<24 hex>"}`, and
`ciphertext` is base64. A trustee checks the digest and every header field
against the envelope. It cannot check the AEAD tag.

### 6.4 Recovery session

The abstract §5.7 session, with `candidateEvidence` holding exactly one entry
per trustee:

```json
{"factor": "onym:recovery-factor:ed25519-session-v1:<factor key hex>", "signature": "<base64>"}
```

The destination suites are `hpke-base-x25519-hkdf-sha256-aes-256-gcm` and
`ed25519`.

The candidate sends each trustee its own variant, carrying only that
trustee's evidence. `sessionId`, the destination and every binding stay
identical, because the evidence signs the commitment to the rest of the
session. `candidateProof` covers the variant, evidence included.

### 6.5 Trustee contribution

The abstract §5.8 object for an approval:

- `contributionVersion`, `sessionId`, `enrollmentId`, `enrollmentSequence`,
  `policyDigest`, `artifactId`, `artifactDigest`, `componentId`, `slot`;
- `decision` set to `approved`;
- `destinationKeysDigest`, `sealedContribution`, `decidedAt`, `expiresAt`;
- `signature` by the trustee's operator key.

`expiresAt` is the session's.

## 7. Trustee verification order

**Binding requirement.** Anything a caller can learn before authorization
must not depend on whether an enrollment exists.

**Enrollment:**

1. Profile identifier (`unsupported_profile`), formats, and
   `trusteeComponentId` equal to this trustee.
2. Open with the rebuilt `info`, then parse with duplicate keys refused.
3. Verify `holderAuthorization` with `authorizationPublicKey`. Require the
   envelope to repeat every context binding, the key's digest included
   (`invalid_enrollment`).
4. Envelope version and recovery mode (`unsupported_profile`).
5. Member parameters `2 ≤ t ≤ n ≤ 16` and index below n.
6. The share:
   - malformed: `invalid_enrollment`;
   - outside the profile: `unsupported_profile`;
   - index or threshold differing from the envelope: `invalid_enrollment`.
7. Timestamps, then the policy (`invalid_policy`).
8. The artifact digest and header (`artifact_mismatch`).

**Recovery:**

1. Parse, verify `candidateProof`, then check the destination suites and key
   (`invalid_request`, `invalid_destination`). All of this happens before any
   enrollment lookup.
2. Bindings to the current sequence. On a mismatch, give the uniform refusal
   `invalid_request`.
3. The attempt budget (`recovery_rate_limited`).
4. The factor (`invalid_candidate_factor`), which counts as an attempt.
5. The session must outlive the cooldown, which starts at trustee time. It
   must also stay inside the policy lifetime and the enrollment term.
6. At release, the release predicate.

The reference core implements every step whose data it has. The attempt
budget and challenge freshness need storage and are pending.

## 8. Test vectors

The reference core's fixtures use fixed test seeds: `0x11…` for the holder
authorization key, `0x22…` factor, `0x33…` operator, `0x44…` trustee X25519,
`0x55…` destination X25519, `0x66…` session proof. The share is member 1 of a
generated 2-of-3 set, and the artifact ciphertext is synthetic.
Representative values:

```text
authorizationKeyDigest  sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d
trusteeKeyId            sha256:34a31a0d016fad9b86b70ba95f4b21b7f4ea40104410836f77d7eb8b05d7859f
artifactDigest          sha256:5c5de4fcce3d63f1a23dbf13de998c40f24891b9c8deeab70160d16c7e7636a1
sessionCommitment       sha256:c31f68e9b87cc2a4ceee7ad331d17ba7290f90783869dd3ad81a09768caeef10
destinationKeysDigest   sha256:021239b8e724062f15c2459bb87b814d53c6a221e79576d62e0085a74df41285
```

The enrollment `info` for that envelope is:

```text
["onym-shamir-enrollment-v1","onym:recovery-implementation:shamir-trustees-slip39-v1","e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",1,"sha256:87f87bbed1f1873c2a951c9624a5919d8b0fdad9a53f7f630a35150ffe942128","a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","sha256:5c5de4fcce3d63f1a23dbf13de998c40f24891b9c8deeab70160d16c7e7636a1","onym:component:reference-trustee","5151515151515151515151515151515151515151515151515151515151515151","c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1","sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d"]
```

The complete fixtures are published with the reference implementation:
envelope, artifact, enrollment context with sealed envelope, session, signed
contribution, and every expected digest and tuple. An independent check with
pyca/cryptography and Trezor's `shamir-mnemonic` confirmed all of them:

- the sealed envelope and the contribution open under the documented `info`;
- every signature and digest recomputes;
- the released share recombines with its sibling to the set's master secret.

Two sources need care:

- **SLIP-0039.** None of the 45 official vectors fits this profile: the
  256-bit ones use exponent 2, the extendable flag, a threshold of 1 or
  several groups. The profile's accept path therefore needs generated shares.
  `shamir-mnemonic` defaults to `extendable=True, iteration_exponent=1`, so a
  generator must pass `False` and `0`.
- **HPKE.** RFC 9180's printed Appendix A pairs X25519 only with AES-128-GCM,
  ChaCha20-Poly1305 and export-only. The CFRG vector file behind the RFC
  ([`5f503c5`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json))
  has the Base-mode entry for this exact suite.

## 9. Corrections and clarifications

1. **Member count (Shamir §5.3 step 5).** A SLIP-0039 share encodes group
   count, member threshold and member index, but not member count. A trustee
   can only check the signed count for consistency. Corrected in the profile
   by this change.
2. **Receipts (Shamir §5.3).** The enrollment receipt example lacks the
   request ID and the old and new states that abstract §5.9 requires. Receipt
   shapes remain a gap (§11).
3. **`canonical(…)`.** Undefined in §4.2 and §6.2 of the profile; defined in
   §2 here.
4. **Enrollment `info`.** Contents listed without order or tag; fixed in §4.
5. **Artifact.** A trustee checks `artifactDigest` and the header, never the
   AEAD tag. Substitution resistance at recovery rests on the recovering
   vault's AEAD check (abstract §11).
6. **Factor privacy.** Abstract §4 draws one `RecoverySession` forwarded to
   every trustee, while Shamir §6.1 says a trustee does not learn factors
   enrolled with another. The per-trustee variants of §6.4 satisfy both.
7. **Aggregate states.** Activation (`pending_receipts → active`) and rotation
   (`rotating → superseded`) in abstract §7.1 are aggregate states one
   trustee cannot observe. How a trustee learns them is a gap (§11).

## 10. Security and privacy effects

- **Recovery authority is unchanged.** Any t trustees plus a client can still
  recover; fewer cannot.
- **Parsing and verification are stricter.** Duplicate keys and unknown
  fields are refused. Ed25519 is verified strictly (small-order keys and
  non-canonical signatures refused). Every encoding has one spelling.
- **Bindings are harder to misuse.** Context binds through HPKE `info`.
  Evidence names its session, trustee and slot. Stored ciphertexts open only
  under their own bindings.
- **Errors do not enumerate.** Refusals before authorization are uniform.
  Stale, revoked or expired state is disclosed only to a caller that presents
  the complete private bindings of an existing sequence.
- **Known limits:**
  - holder-poll notices reach the holder only while an enrolled device polls;
  - whoever holds the healthy device's scoped key can veto, which denies
    recovery but fails closed;
  - a party holding the private bindings can spend the attempt budget;
  - nothing here detects a trustee restored from an old snapshot;
  - compromise of a trustee's long-lived X25519 key exposes the envelopes it
    retains.

## 11. Compatibility, migration and gaps

No conforming implementation exists yet, so nothing migrates. Objects keep
the contract's version fields and gain no new ones. A trustee declares
`bindingVersion: "draft-1"` in its manifest.

Gaps this draft knowingly leaves open:

- the HTTP mapping and request authentication;
- receipt shapes;
- the manifest schema for the X25519 key, `trusteeKeyId` and limits;
- activation and rotation signaling;
- management authority after recovery;
- whether a terminal session state blocks re-serving a contribution already
  delivered;
- vectors for the artifact AAD and the recovery map;
- notification channels beyond holder poll;
- freshness assurance for restored trustees.

## 12. Authority, revenue, IP and licensing

**Authority and revenue.** No seat gains or loses either. The binding fixes
bytes for authority the contracts already assign, and adds no party.

**Decisions requested:**

- adopt this binding under the Shamir profile identifier, or assign a binding
  identifier;
- approve or replace the first factor and notification profile of §6.1.

**IP and licensing.** This text is contributed under the terms the repository
adopts; it has no licence file yet, so please state one. The reference
implementation is MIT. Its vendored test data keeps its own terms:

- Trezor's SLIP-0039 vectors and word list (MIT);
- Onym Discovery's canonical-JSON fixtures (MIT);
- one CFRG HPKE vector.

## References

1. [Recovery-Trustee.md](Recovery-Trustee.md) and
   [Recovery-Trustee-Shamir.md](Recovery-Trustee-Shamir.md)
2. [Discovery-Static-Ed25519.md](../discovery/Discovery-Static-Ed25519.md) §3,
   canonical encoding
3. IETF RFC 9180, “Hybrid Public Key Encryption”:
   <https://www.rfc-editor.org/rfc/rfc9180>
4. SatoshiLabs, “SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes”:
   <https://github.com/satoshilabs/slips/blob/master/slip-0039.md>
5. CFRG HPKE test vectors, commit `5f503c5`:
   <https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json>
