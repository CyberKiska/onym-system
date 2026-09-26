---
status: draft
proposed: "@CyberKiska"
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

**Status.** A [partial reference trustee](https://github.com/CyberKiska/onym-recovery-trustee) implements the covered path in §§2–7
with durable storage and the transport of §6.8, and produced the vectors of
§8. A demo client exercises it end to end: 2-of-3 enrollment, veto, release
after the cooldown and reconstruction, against three local trustees and
again over TLS against a container deployment.A native Onym client and a
public deployment do not exist yet. The binding identifier is `draft-1`
until maintainers adopt it or assign another (§12). §13 proposes, without
implementing, what a draft-2 would add: activation and rotation,
finalization, drills and export, late admission, inbox notices and
freshness anchoring.

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
| Timestamps | Exactly `YYYY-MM-DDTHH:MM:SSZ`: no fraction, offset or leap second. A reader requires the text to equal the formatting of the whole seconds it denotes | `createdAt`, `expiresAt`, `requestedAt`, `decidedAt` |
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
use the same array encoding. The demo client computes both; fixed vectors
are pending.

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

### 6.6 Requests

Every request is one canonical object with `requestVersion: 1` and an
`operation`:

| Operation | Authorized by | Request ID |
|---|---|---|
| `issue-challenge` | An operator-issued invitation code (64 hex), redeemed for a single-use challenge valid for 15 minutes | — |
| `enroll` | The consumed challenge and the envelope's `holderAuthorization`. Carries `context` (§6.2), `trusteeKeyId`, `sealedEnvelope` and `protectedArtifact` | The challenge |
| `begin-recovery` | `candidateProof`. Carries this trustee's `session` variant (§6.4) | `sessionId` |
| `read-enrollment`, `revoke-enrollment`, `close-enrollment` | A signed request by the enrollment's trustee-scoped key | `requestId` |
| `read-recovery` | A signed request by the session proof key | `requestId` |
| `cancel-recovery` | A signed request by the proof key (`"by": "candidate"`) or the trustee-scoped key (`"by": "holder"`, a veto) | `requestId` |

A signed request carries `requestVersion`, `operation`, `requestId` (64 hex),
`componentId`, `issuedAt`, exactly one of `enrollmentId` or `sessionId`,
`by` for cancellation only, and `signature` over everything else.

**Binding requirement, retries and replay:**

- A first acceptance needs `issuedAt` within the trustee's clock skew.
- An identical retry of a state change returns the identical receipt at any
  age. The one exception is `enroll`: its receipt is repeated only while the
  custody it created is live. A retry after revocation or closure gets
  `enrollment_revoked`, after supersession `stale_enrollment_sequence`, and
  after the term ends `enrollment_expired`, never a receipt that reads as
  live custody. A different body under the same request ID is
  `request_conflict`.
- Reads are single use. A replay is refused while its nonce is kept (at
  least twice the skew) and by `issuedAt` afterwards.
- `componentId` stops a request signed with the session proof key, which
  every trustee sees, from being replayed at another trustee.

### 6.7 Receipts

One signed shape: abstract §5.9, with the Shamir §5.3 fields for `enroll`.

- **Every receipt:** `receiptVersion`, `operation`, `requestId`,
  `componentId`, `implementationProfileId`, `enrollmentId`,
  `enrollmentSequence`, `policyDigest`, `oldState`, `newState`, `recordedAt`,
  `expiresAt`, and `signature` by the operator key.
- **`enroll`:** `artifactId`, `artifactDigest`, `slot`,
  `sealedContributionDigest` and `storageClass`.
- **Session operations:** `sessionId`, `cooldownEndsAt`,
  `destinationKeysDigest`, `remainingAttempts` and `evidenceDigest` (begin:
  the digest of the canonical session variant evaluated), `reason` (a §15
  code for a veto or refusal), and `contribution`, the signed §6.5 object
  once released.
- **`read-enrollment`:** `sessions`, the holder-poll notices: `sessionId`,
  `state`, `reason`, `released` (this trustee's contribution has left and
  a veto can no longer recall it), `cooldownEndsAt` and `expiresAt`.

A `begin-recovery` that reached factor evaluation spent an attempt, so a
failed factor is a signed receipt with `newState: refused` and `reason:
invalid_candidate_factor`, not an unsigned error. Unbound or malformed
requests stay uniform unsigned errors.

States use the contract's names: `active`, `revoked`, `closed`, `expired`
for an enrollment; `cooling_down`, `collecting`, `cancelled`, `refused`,
`expired`, `finalized` for a session. A trustee signs a receipt only after
the state it reports is committed and read back.

A receipt records a decision at its `recordedAt`. A retried one is
therefore historical: a client learns current state only from a fresh
`read-enrollment` or `read-recovery`.

`issue-challenge` answers with `challenge`, `componentId`, `expiresAt` and
`trusteeKeyId`, unsigned: the challenge is only as good as the `enroll`
receipt that consumes it.

### 6.8 Transport and manifest

**Proposed.** Each trustee serves one HTTPS origin:

| Route | Purpose |
|---|---|
| `GET /manifest.json` | The signed manifest |
| `GET /health` | Liveness only; nothing per enrollment |
| `GET /ready` | Optional: `{"status": "ready"}`, or 503 with a reason and nothing per enrollment |
| `POST /v1/trustee` | One §6.6 request; the body is its receipt or challenge, or `{"error": "<code>"}` |

Private identifiers travel only in request bodies, never in paths or query
strings. The `error` code is normative; the HTTP status is a class: 400
invalid, 409 state conflict, 429 attempts spent, 501 declared unsupported,
503 unable to decide safely. A response without an `error` code, such as a
proxy's 502, 504 or 429, is a transport failure, not the trustee's
answer: a client retries it within the session and never counts it as a
refusal.

The manifest is the abstract §5.3 object, with `operator` set to
`onym:key:<hex>` of the Ed25519 key that signs the manifest, receipts and
contributions. It adds:

- `bindingVersion`;
- `enrollmentKey`: `suite`, `publicKey` (64 hex) and `trusteeKeyId`;
- `storageClass`, as enrollment receipts declare it;
- `limits`: clock skew, cooldown bounds, session lifetime and enrollment
  term in seconds, maximum attempts, and artifact and request sizes in bytes;
- `operations` served, and `unsupportedOperations` mapping each refused
  contract operation to the code it returns;
- `offers`, inline as in whitepaper §16, each with `offerId`, `model` and a
  `service` object, the spine Onym clients decode. A free offer still
  declares the abstract §12 terms: service, fees, lapse, export, retention,
  jurisdiction and complaint path.

A client refuses a manifest whose signature, profile, binding version or
`trusteeKeyId` does not check, or whose `validUntil` has passed. Trustees
that declare the same `trustDomain` are not independent, and the client
says so.

The manifest a client enrolled with stays in its recovery map as evidence
of the enrolled keys, and may expire there. Before using a trustee again,
the client fetches its current manifest and requires the same
`componentId`, `operator` and `trusteeKeyId`. This draft defines no key
rotation, so a change is refused, never trusted. Responses to `POST
/v1/trustee` carry `Cache-Control: no-store`.

*Recommendation.* A trustee bounds how many requests it admits at once and
refuses the rest at once with `temporarily_unavailable`. It keeps capacity
for `read-enrollment`, `cancel-recovery`, `revoke-enrollment` and
`close-enrollment`, so a flood of other requests cannot keep a holder from
seeing or stopping a recovery. Per-client limits belong in front of it.

### 6.9 Time

**Binding requirement.** A trustee's decisions use its own time, never a
caller's:

- **It never runs backwards.** The trustee records the highest time any
  committed change used. While its clock reads earlier, it refuses what
  grants or uses authority (`issue-challenge`, `enroll`, `begin-recovery`,
  and release through `read-recovery`) with `temporarily_unavailable`.
- **Protection still works.** Operations that only report or remove
  authority (`read-enrollment`, `cancel-recovery`, `revoke-enrollment`,
  `close-enrollment`) run at the recorded time instead, and §6.6 freshness
  is checked against it. A clock set back must not delay a veto.
- **It never runs faster than elapsed time.** While it runs, a trustee's time
  advances no faster than a monotonic clock started with it, plus a few
  seconds of slack, so a clock stepped forward cannot shorten a cooldown.

*Gap.* A clock set forward before the trustee starts, or a trustee restored
from an old snapshot, cannot be detected from local state alone (§10, §11).
§13.6 proposes the rules an external freshness anchor must follow.

## 7. Trustee verification order

**Binding requirement.** Anything a caller can learn before authorization
must not depend on whether an enrollment exists.

**Enrollment:**

1. The challenge: issued by this trustee, unused, unexpired, for an open
   invitation (`invalid_enrollment`). Then the profile identifier
   (`unsupported_profile`), formats, and `trusteeComponentId` equal to this
   trustee.
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
9. Only now, a known enrollment ID. If the envelope's
   `authorizationPublicKey` is not the key that holds it, the answer is
   `invalid_enrollment` and the challenge and invitation are spent, as an
   enrollment would spend them. Otherwise: `enrollment_revoked` for a
   tombstone, `stale_enrollment_sequence` for an equal or lower sequence.

**Recovery:**

1. Parse, verify `candidateProof`, then check the destination suites and key
   (`invalid_request`, `invalid_destination`). All of this happens before any
   enrollment lookup.
2. Bindings to the current sequence. On a mismatch, give the uniform refusal
   `invalid_request`.
3. The attempt budget (`recovery_rate_limited`).
4. Timing: the session must outlive the cooldown, which starts at trustee
   time, and stay inside the policy lifetime and the enrollment term.
5. The factor (`invalid_candidate_factor`). Only from this step does the
   request count as an attempt, whether the factor holds or not.
6. At release, the release predicate, inside the transaction that persists
   the contribution. Later reads resend the same bytes until a terminal
   state or expiry.

The reference implementation follows this order.

**Client.** A conforming client, beyond abstract §8:

1. Parses every response with §2's rules and verifies every manifest,
   receipt and contribution signature with the operator key it pinned. It
   requires the fields a response must repeat: `componentId`, `operation`,
   `requestId` and the bindings.
2. Accepts only the codes of abstract §15, `invalid_request` and
   `request_conflict`, and only §6.7's state names; anything else is
   malformed. It shows no trustee text that has not passed these checks,
   and shows printable text only.
3. Declares an enrollment only once all n receipts verify and the encrypted
   recovery map is saved and reads back. If anything fails, or is
   interrupted, before that, it closes every slot it opened.
4. At recovery:
   - requires distinct slots and member indices;
   - verifies the holder's signature on every returned envelope, so a
     trustee can withhold a share but not substitute one;
   - combines exactly t shares;
   - imports only after the artifact's AEAD and identity binding check.
5. Treats a response without an `error` code as a transport failure (§6.8),
   and a receipt as historical (§6.7).

The reference client follows these rules and tests them against trustees
that return hostile codes, states, times and names.

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

The [complete fixtures](https://github.com/CyberKiska/onym-recovery-trustee/tree/main/tests/fixtures) are prepared with the reference implementation:
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
  An enrollment's stale, revoked or expired state is disclosed only to a
  caller holding its trustee-scoped key. A caller with an unused invitation
  and a well-formed envelope still learns that an enrollment ID is taken,
  at the cost of that invitation; IDs are random 256-bit values.
- **Known limits:**
  - holder-poll notices reach the holder only while an enrolled device polls;
  - whoever holds the healthy device's scoped key can veto, which denies
    recovery but fails closed;
  - a party holding the private bindings can spend the attempt budget;
  - nothing here detects a trustee restored from an old snapshot;
  - compromise of a trustee's long-lived X25519 key exposes the envelopes it
    retains.

## 11. Compatibility, migration and gaps

Nothing is deployed yet, so nothing migrates. Objects keep the contract's
version fields and gain no new ones. A trustee declares
`bindingVersion: "draft-1"` in its manifest.

Gaps this draft knowingly leaves open:

- adoption of the transport and manifest additions of §6.8, or a common
  HTTP binding shared across seats;
- activation and rotation signaling (proposed in §13.1);
- management authority after recovery (§13.1 proposes the new sequence's
  key);
- finalization, drills and export (§13.2, §13.3);
- a first admission later than the clock skew allows (§13.4);
- whether a terminal session state blocks re-serving a contribution already
  delivered (this draft: it does);
- vectors for the artifact AAD and the recovery map; the demo client binds
  the map to `canonical(implementationProfileId, mapId)`;
- notification channels beyond holder poll (§13.5);
- receipts name `implementationProfileId` where abstract §5.9 asks for
  policy and implementation-profile digests, and an enroll receipt's
  `active` means local custody accepted, not the aggregate activation that
  needs all n receipts (§13.1 proposes `pending_receipts`);
- freshness assurance for restored trustees (§13.6 states the rules an
  anchor must follow).

## 12. Authority, revenue, IP and licensing

**Authority and revenue.** No seat gains or loses either. The binding fixes
bytes for authority the contracts already assign, and adds no party.

**Decisions requested:**

- adopt this binding under the Shamir profile identifier, or assign a binding
  identifier;
- approve or replace the first factor and notification profile of §6.1;
- adopt, amend or refuse each draft-2 proposal of §13.

**IP and licensing.** This text is contributed under the terms the repository
adopts; it has no licence file yet, so please state one. The reference
implementation is MIT. Its vendored test data keeps its own terms:

- Trezor's SLIP-0039 vectors and word list (MIT);
- Onym Discovery's canonical-JSON fixtures (MIT);
- one CFRG HPKE vector.

## 13. Proposed for draft-2

**Status.** Proposals: not implemented, and not part of draft-1
conformance. They answer the gaps of §11. Each lands with vectors and a
reference implementation before it is recommended. A trustee that adopts
them declares `bindingVersion: "draft-2"`, which a draft-1 client refuses
(§6.8).

### 13.1 Activation and rotation

Abstract §7.1 separates holding custody (`pending_receipts`) from recovery
authority (`active`), and replaces a sequence only once its successor is
active. One trustee sees neither aggregate.

*Rationale: superseding per trustee strands recovery.* Suppose a of n
trustees have switched to the new sequence:
- the old sequence has n − a releasable shares, and the new one a;
- both are below t exactly when n − t < a < t;
- that can happen whenever 2t − n ≥ 2: for 3-of-3, 3-of-4 and 4-of-5, never
  for 2-of-3 or 3-of-5.

**Proposal.** Each sequence passes three steps at each trustee, every one
signed as a §6.6 request.

1. **Prepare.**
   - `rotate-enrollment` is signed with the current sequence's
     authorization key. Its receipt has `newState: "rotating"` and carries a
     `challenge`: single use, bound to `(enrollmentId, enrollmentSequence)`,
     valid for 15 minutes.
   - `enroll` for sequence k + 1 presents that challenge where a first
     enrollment presents an invitation's.
   - Every accepted sequence, a first one included, starts in
     `pending_receipts`: the trustee holds it, but it cannot be released.
2. **Activate.**
   - `activate-enrollment` is signed with the new sequence's key. It names
     `enrollmentSequence` and carries `receiptsDigest`: SHA-256 of
     `canonical("onym-shamir-activation-v1", r1, …, rn)`, the n enroll
     receipts as objects in policy order.
   - The trustee cannot verify the digest and records it as the holder's
     assertion. The sequence becomes `active`.
   - An older sequence at this trustee stays releasable, and reads as
     `rotating`.
3. **Retire.**
   - `retire-enrollment` is signed with the new sequence's key and names the
     old `enrollmentSequence`. Until the new sequence is active here it is
     refused with `enrollment_pending`.
   - The old sequence becomes `superseded`: its envelope and artifact are
     deleted, and its open sessions end with `stale_enrollment_sequence`.

**Client rule.** The client:
- persists each receipt before the next step;
- retires only once it holds activation receipts from all n trustees of the
  new set;
- closes every trustee that left the set.

**Invariant.** At every step, some sequence has at least t releasable
shares:
- before the first retirement, the old sequence has all n;
- retiring starts only once the new sequence has all n, and each retirement
  lowers the old one only;
- a crash, a lost acknowledgement or a partition leaves the set in step 2
  or 3, where both hold.

The holder abandons a rotation by closing sequence k + 1. The cost is that
the old sequence's factor and kit stay valid until they are retired.
Authority after recovery passes to the new sequence's key.

### 13.2 Finalize

- `finalize-recovery` is signed with the session proof key. It is allowed
  only once this trustee has released its contribution; before that it is
  refused with `recovery_cooling_down`.
- The session becomes `finalized`. Every other open session of the same
  sequence at this trustee ends as `cancelled` with `recovery_refused`, and
  each gets a notice.
- It does not consume the factor: retirement (§13.1) ends the sequence's
  authority. A client sends it only after durable import. It is an
  assertion, never proof of reconstruction.

### 13.3 Drill and export sessions

The session gains `purpose`: `recovery`, `drill` or `export`. Because it is
part of the session, `sessionCommitment` covers it.

- **Holder approval.** For any purpose but `recovery`, the trustee's session
  variant also carries `holderApproval`: an Ed25519 signature by the
  enrollment's authorization key over
  `canonical("onym-recovery-holder-approval-v1", sessionCommitment, componentId, slot, purpose)`.
  Without it, a stolen kit could label an attack a drill.
- **No shortcuts.** Every purpose gets the same factor check, cooldown,
  notices and veto; notices name the purpose. A holder key alone never
  releases anything.
- **Budget.** Holder-approved sessions spend no attempt. At most one may be
  open per sequence; another is refused with `recovery_rate_limited`.
- **Bootstrap is separate.** A drill never finalizes or retires a sequence,
  and it is not the bootstrap test that activation needs (abstract §7.1).
  That test is importing the map.

### 13.4 Late admission

Draft-1 requires `requestedAt` within the clock skew, so a trustee first
reached later in a longer session refuses it. The client cannot fix that
without changing the session.

- `begin-recovery` becomes a signed request (§6.6) carrying `session`,
  signed with the session's proof key.
- §6.6 freshness applies to its `issuedAt`. Its `requestId` is a nonce; the
  `sessionId` stays the idempotency key.
- The session's `requestedAt` need only lie no later than the trustee's
  time plus the skew, and within the policy's `sessionLifetime` of
  `expiresAt`.
- The cooldown still starts at this trustee's admission. When less of the
  session remains than the cooldown, admission is refused with
  `recovery_expired`.

### 13.5 Inbox notices

The notification profile `onym:recovery-notice:onym-inbox-v1` reuses Onym's
message carriage and push path, and adds no service. In the trustee policy
of §6.1 it is an object entry:

```json
{"profile": "onym:recovery-notice:onym-inbox-v1", "noticeKey": "<64 hex X25519>", "relays": ["wss://relay.example"], "interventionWindow": "PT12H", "required": true}
```

- **Relays** must be among the `noticeRelays` the trustee's manifest
  declares, so a trustee never dials an address a holder chose.
- **The inbox** is the first 8 bytes of
  `SHA-256("sep-inbox-v1" ‖ noticeKey)`, in hex, as in
  [UI-Message-Nostr.md](../message/UI-Message-Nostr.md) §7. The notice key
  should be seat-scoped, never the identity's own inbox key.
- **The event** has kind 34113, the four inbox tags and `ms`, and a fresh
  secp256k1 signer. Its content is the base64 of an HPKE seal (§5 suite) to
  `noticeKey`.
  - The sealed plaintext is a signed notice: `noticeVersion`, `noticeId`,
    `componentId`, `enrollmentId`, `enrollmentSequence`, `sessionId`,
    `event`, `purpose`, `cooldownEndsAt`, `releaseNotBefore`, `recordedAt`
    and `signature`.
  - The seal's `info` is
    `canonical("onym-recovery-notice-v1", componentId, enrollmentId, noticeId)`.
- **Events:** begin, release, cancellation or veto, refusal, finalization,
  supersession, revocation and closure.
- **A real veto window.** When `required` is set, release waits until
  `releaseNotBefore = max(cooldownEndsAt, acceptedAt + interventionWindow)`,
  where `acceptedAt` is the first relay's `OK true` for the begin notice.
  If no relay accepts before `expiresAt − interventionWindow`, the session
  cannot release. Relay acceptance is not delivery to a device or a person.
- **Polling stays.** `read-enrollment` remains the source of truth. A push
  only wakes the holder's device, whose app must subscribe to the notice
  inbox and register it for push; it does not today.

*Gap.* Once relays enforce NIP-42 (UI-Message-Nostr §11), a trustee needs a
relay-scoped key of its own to publish.

### 13.6 Freshness anchoring

§6.9 cannot see a trustee restored from an old snapshot. Consistency
proofs alone do not help either. Suppose a veto is acknowledged while the
anchor is unreachable, and the trustee is then restored to a snapshot taken
at the anchor's last checkpoint: a fresh cosignature of that checkpoint
cannot reveal the lost veto. Before a trustee holds real secrets, its anchor
must satisfy these rules.

1. **Commit before acknowledging.** Receipts for `cancel-recovery`,
   `revoke-enrollment` and `close-enrollment` carry
   `commitment: "pending"`. They become `"committed"` once a checkpoint
   containing them is cosigned outside the trustee. A client retries until
   it holds a committed receipt.
2. **Admission in anchored time.** The cooldown runs from the anchor's
   timestamp for the first checkpoint that contains the admission, not from
   local time.
3. **A fresh anchor at release.** A release needs a new cosignature over a
   checkpoint that includes the trustee's current state.
4. **Restore quarantine.** At boot, and after any disagreement with the
   anchor, releases wait for reconciliation. Protective operations continue,
   marked pending.

The preferred mechanism is [C2SP tlog-witness](https://c2sp.org/tlog-witness@v1.0.0):
checkpoints of an append-only log of security transitions, cosigned by at
least one witness in another trust domain. For a single witness, a
separately administered compare-and-set checkpoint is equivalent. Witnesses
learn only the log's size, root and timing, and nothing is published to a
ledger (abstract §10).

A veto still pending when a trustee is restored, from a holder whose device
is then lost, remains lost; the rules make that visible, not impossible.

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
