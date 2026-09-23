---
status: draft
proposed: Claude, Codex & @rinat-enikeev
date: 01.08.2026
---

# Onym Recovery Trustee: Shamir Threshold Implementation

**Implementation profile draft 0.1 — August 2026**

> No one trustee holds the recovery secret. A declared threshold can recover;
> fewer shares cannot. Availability and collusion move from one provider to a
> set the holder chooses.

This document maps the abstract
[Recovery Trustee seat](Recovery-Trustee.md) to independently selected
trustees holding shares created with Shamir's Secret Sharing. The v1 wire
profile uses the final SLIP-0039 share format for interoperability and wraps
each share in session-bound public-key encryption for enrollment and recovery.

The client splits a random recovery-unlock key, not the BIP-39 mnemonic text.
That unlock key protects the vault's canonical `RecoveryArtifact`. This keeps
the trustee profile independent of the identity's seed, curve, or migration
format and lets authenticated decryption reject an incorrect reconstruction.

The profile does not make trustees trustless. Any threshold of them can
recover. Too few available trustees permanently block recovery. Human
recognition, service authentication, coercion resistance, payment, and
operational storage remain separate risks.

## 1. Conformance declaration

| Abstract concept | Shamir trustee mapping |
|---|---|
| Implementation profile | `onym:recovery-implementation:shamir-trustees-slip39-v1` |
| Custody class | Holder-selected `t`-of-`n` threshold |
| Protected secret | Random 256-bit recovery-unlock key (`RUK`) |
| Share format | SLIP-0039, one group with `t`-of-`n` member shares |
| Trustee | One independently enrolled member-share slot |
| Protected object | AEAD-encrypted canonical `RecoveryArtifact` |
| Enrollment transfer | One share HPKE-sealed to one trustee key |
| Recovery transfer | Same share HPKE-sealed to one fresh destination key/session |
| Integrity | Share checksums/reconstruction digest plus final artifact AEAD |
| Individual malicious-share proof | Not provided; this is not verifiable secret sharing |
| Recovery modes | Secret restoration; authority migration when the identity profile supports it |

The profile maps:

```text
onym:recovery-profile:trustee-v1
    -> onym:recovery-implementation:shamir-trustees-slip39-v1
```

An implementation must claim this complete identifier. An arbitrary Shamir
library, proprietary mnemonic share, or set of encrypted file fragments is not
wire-compatible.

## 2. Threshold meaning

For `t`-of-`n` trustees:

- any `t` valid shares can reconstruct `RUK`;
- fewer than `t` shares reveal no information about `RUK` under the secret-
  sharing construction;
- the system tolerates at most `n - t` unavailable trustees; and
- any `t` colluding, compromised, coerced, or deceived trustees can recover.

Examples:

| Policy | Availability | Collusion boundary |
|---|---|---|
| 2-of-3 | One trustee may be unavailable | Any two can recover |
| 3-of-5 | Two trustees may be unavailable | Any three can recover |
| 5-of-7 | Two trustees may be unavailable | Any five can recover |

There is no universally best threshold. A higher `t` resists collusion but
increases loss risk. A larger `n` adds operational and metadata surface. The
UI shows both sentences—“these many can steal” and “these many may disappear”
—before confirmation.

SLIP-0039 supports at most 16 members in one group. This profile therefore
requires `2 <= t <= n <= 16`. A 1-of-1 arrangement uses the cloud or another
single-custodian profile, not a misleading threshold label.

## 3. Trustee selection and independence

A trustee can be:

- a human using a dedicated trustee application;
- an organization with a reviewed recovery process;
- a hardware device kept in another location;
- a paid online trustee service; or
- another automated agent that can protect and release one share.

The holder should select different administrative, credential, device, cloud,
geographic, and legal failure domains. Three services owned by one parent,
three accounts recovered through one email address, or three virtual machines
under one administrator are not meaningfully independent.

Each signed trustee manifest declares an operator and `trustDomain`. A UI may
warn about known overlap, but cannot prove social or corporate independence
from self-asserted metadata. Investigation by Discovery providers and holder
judgment remain part of the trust decision.

## 4. Cryptographic construction

### 4.1 Required suites

The v1 profile uses:

- a 256-bit `RUK` from a cryptographically secure random source;
- AES-256-GCM with a fresh 96-bit nonce for the recovery artifact;
- SHA-256 for protocol object and ciphertext digests;
- SLIP-0039 for one-group `t`-of-`n` member sharing of `RUK`;
- RFC 9180 HPKE Base mode using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and
  AES-256-GCM for transfers to trustees and recovery destinations; and
- Ed25519 for fresh session proofs and signed outer enrollment/trustee
  objects.

The profile pins canonical encodings, byte order, HPKE `info`, AEAD associated
data, SLIP-0039 parameters, and fixtures. Implementations use reviewed
libraries with cross-platform vectors; they do not implement polynomial
arithmetic in UI code. The byte-level binding is proposed in
[Recovery-Trustee-Shamir-Binding.md](Recovery-Trustee-Shamir-Binding.md).

### 4.2 Artifact encryption

The healthy vault serializes the abstract `RecoveryArtifact` and computes:

```text
identityBindingCommitment = SHA-256(canonical(
  "onym-recovery-identity-binding-v1",
  identityBindingSalt,
  identitySubject,
  descriptorDigest
))

AAD = canonical(
  implementationProfileId,
  enrollmentId,
  enrollmentSequence,
  policyDigest,
  identityBindingCommitment,
  recoveryMode,
  artifactId
)

artifactCiphertext = AES-256-GCM-Seal(
  key = RUK,
  nonce = fresh 96-bit nonce,
  plaintext = canonical RecoveryArtifact,
  associatedData = AAD
)
```

The client places the ciphertext, nonce, every AAD field, and a digest over the
canonical header and ciphertext into the abstract `ProtectedRecoveryArtifact`.
That object may be replicated with every trustee or stored through one or more
opaque blob locations. It is not a secret key, but its header, location, and
enrollment binding are private metadata. A recovery policy declares the
artifact availability rule separately from its share threshold.

### 4.3 SLIP-0039 parameters

This profile encodes the 32-byte `RUK` as the SLIP-0039 master secret with:

```json
{
  "masterSecretBits": 256,
  "groupCount": 1,
  "groupThreshold": 1,
  "memberCount": "n",
  "memberThreshold": "t",
  "extendableBackup": false,
  "passphrase": "",
  "iterationExponent": 0
}
```

The empty SLIP-0039 passphrase is intentional: the declared trustee threshold
is the complete cryptographic recovery authority. A forgotten extra
passphrase would defeat recovery, while a weak remembered passphrase would add
little protection against colluding trustees. A future profile may define a
holder-retained factor, but must present the resulting permanent-loss risk and
use a new implementation identifier.

SLIP-0039's 15-bit identifier and share metadata help reject mixed share sets,
but they are not the Onym enrollment ID. Every share is also carried inside an
outer, cryptographically bound 256-bit enrollment and session context.

SLIP-0039 is mostly incompatible with BIP-39. The client must not present a
SLIP-0039 trustee share as a BIP-39 recovery phrase or instruct the user to
import it into the ordinary Onym seed screen.

### 4.4 Share envelope

Before delivery, each mnemonic share is represented canonically as lowercase
SLIP-0039 words separated by one ASCII space and placed in a private envelope:

```json
{
  "shareEnvelopeVersion": 1,
  "implementationProfileId": "onym:recovery-implementation:shamir-trustees-slip39-v1",
  "enrollmentId": "<random-256-bit-id>",
  "enrollmentSequence": 1,
  "policyDigest": "<sha256>",
  "identityBindingCommitment": "<opaque-commitment-from-policy>",
  "artifactDigest": "<sha256>",
  "artifactId": "<same-random-256-bit-id-as-protected-artifact>",
  "recoveryMode": "secret-restoration",
  "trusteeComponentId": "onym:component:<trustee-id>",
  "slot": "<random-opaque-slot-id>",
  "trusteeChallenge": "<fresh-single-use-challenge-issued-for-this-slot>",
  "memberIndex": "<0-through-n-minus-1>",
  "memberThreshold": "t",
  "memberCount": "n",
  "trusteePolicy": {
    "candidateFactors": ["<this-trustee-factor-bindings>"],
    "cooldown": "P2D",
    "sessionLifetime": "P7D",
    "maximumAttempts": 3,
    "notifications": ["<this-trustee-destination-references>"],
    "holderVeto": "<this-trustee-veto-method-and-deadline>",
    "lapsePolicy": "<this-trustee-grace-export-destruction-rule>"
  },
  "slip39Share": "<canonical-share-words>",
  "createdAt": "2026-08-01T00:00:00Z",
  "expiresAt": "2027-08-01T00:00:00Z",
  "authorizationPublicKey": "<recovery-and-trustee-scoped-ed25519-public-key>",
  "holderAuthorization": "<ed25519-signature-over-canonical-envelope-with-this-field-omitted>"
}
```

This signed envelope is the Shamir mapping of the abstract
`TrusteeEnrollmentAuthorization`: it contains the full-policy digest and only
this trustee's identity, slot, share parameters, and enforcement policy. The
holder authorization authenticates every envelope field, including the share,
before the entire envelope is HPKE-sealed to that trustee. HPKE Base mode
provides confidentiality to the trustee; the Ed25519 authorization provides
sender authentication. Only the intended trustee learns its member index,
policy, or words. The coordinator receives a ciphertext and digest, not the
share or the full trustee roster.

The authorization proves control of the recovery-scoped enrollment key, not a
claimed human relationship. A human trustee independently confirms the
invitation and displayed key fingerprint with the holder before accepting; a
name, avatar, message, or valid self-created key alone cannot establish who
asked them to become a trustee.

Trustees never send share words through email, SMS, ordinary messenger chat,
support tickets, a public notary, clipboard telemetry, or QR codes rendered by
an untrusted web page. A human trustee uses a conforming app that decrypts,
stores, and later re-encrypts the envelope without displaying words by
default.

## 5. Enrollment ceremony

### 5.1 Preconditions

While the identity is healthy, the holder selects:

- recovery mode and identity/descriptor binding;
- `t` and `n`;
- exactly `n` current trustee manifests and enrollment public keys;
- each trustee's candidate-recognition/factor policy;
- cooldown, notifications, veto, session lifetime, and attempt limits;
- protected-artifact locations and replication rule; and
- each trustee offer, term, lapse, export, and deletion behavior.

Each trustee then issues a fresh, expiring, single-use enrollment challenge
after accepting the human invitation or authenticating the service enrollment
and entitlement. A published HPKE key without this challenge is insufficient
to create stored trustee state.

The UI highlights shared failure domains and refuses duplicate component IDs,
duplicate member indices, duplicate slots, expired manifests, or incompatible
implementation profiles.

### 5.2 Generate and distribute

The healthy vault:

1. creates a random enrollment ID, `RUK`, artifact ID, and artifact nonce;
2. encrypts the canonical artifact with `RUK` and the exact enrollment AAD;
3. invokes a conforming SLIP-0039 implementation to create `n` shares at
   threshold `t`;
4. creates one outer share envelope per trustee containing only that
   trustee's policy and slot, then signs it with the distinct recovery-and-
   trustee-scoped Ed25519 authorization key recorded for that slot;
5. HPKE-seals each signed envelope to that trustee's current enrollment public
   key, binding the profile, policy, enrollment, artifact, trustee, slot,
   trustee-issued challenge, and authorization-key digest in `info`;
6. sends the protected artifact and only the intended sealed share to each
   selected trustee;
7. collects and verifies all `n` signed enrollment receipts;
8. creates and verifies the encrypted recovery map defined below; and
9. destroys plaintext shares and `RUK` from process memory on a best-effort
   basis after activation.

The enrollment is not active if fewer than `n` selected trustees acknowledge.
The holder may deliberately create a revised policy with a lower `n`; the UI
must not silently activate a partially enrolled set under the old policy.
It is also not active until the holder confirms a usable recovery-map copy and
its separate map key.

### 5.3 Trustee receipt

Each trustee:

1. decrypts the envelope and verifies its recovery-and-trustee-scoped Ed25519
   holder authorization over every field;
2. verifies the exact abstract and implementation profiles, its own component
   and slot, the artifact digest, the opaque full-policy digest binding, and
   its local trustee policy;
3. consumes the matching unexpired, single-use challenge and refuses an
   unsolicited or replayed enrollment;
4. accepts only the current enrollment sequence for that enrollment and
   authorization key, refusing replay or rollback;
5. validates the SLIP-0039 checksum, member threshold, and member index
   against the signed envelope, and checks both against the signed member
   count, which a share does not encode;
6. confirms any invitation or human relationship through the prearranged
   independent path rather than trusting display text; and
7. stores the share under its local protection and verifies durable read-back
   before returning:

```json
{
  "receiptVersion": 1,
  "operation": "enroll",
  "componentId": "onym:component:<trustee-id>",
  "enrollmentId": "<same-id>",
  "enrollmentSequence": 1,
  "policyDigest": "<same-sha256>",
  "artifactDigest": "<same-sha256>",
  "artifactId": "<same-artifact-id>",
  "slot": "<same-slot>",
  "sealedContributionDigest": "<digest-of-enrollment-ciphertext>",
  "storageClass": "<manifest-declared-class>",
  "status": "active",
  "storedAt": "2026-08-01T00:00:00Z",
  "expiresAt": "2027-08-01T00:00:00Z",
  "signature": "<trustee-signature>"
}
```

The receipt proves the trustee's assertion, not continued possession. The
client should request signed, non-secret readiness attestations periodically
and prompt replacement before the active set falls below policy.

### 5.4 Offline verification drill

The holder may perform a recovery drill to a temporary local destination. The
client gathers `t` destination-encrypted shares, reconstructs `RUK`, verifies
the artifact, and then destroys the temporary plaintext without changing the
identity. Trustees and the client label the session `drill` in its private
policy context.

A drill exercises real recovery authority and leaks recovery timing to the
selected trustees. It is rate-limited, notified, and never run silently by
telemetry or a background health check.

### 5.5 Recovery map and fresh-device bootstrap

The complete trustee roster cannot be public or sent to every trustee, but a
fresh device still needs it. After enrollment, the healthy vault creates this
private `ShamirRecoveryMap`:

```json
{
  "recoveryMapVersion": 1,
  "recoveryProfileId": "onym:recovery-profile:trustee-v1",
  "implementationProfileId": "onym:recovery-implementation:shamir-trustees-slip39-v1",
  "enrollmentId": "<current-enrollment-id>",
  "enrollmentSequence": 1,
  "policy": "<canonical-holder-private-RecoveryPolicy>",
  "protectedArtifact": "<ProtectedRecoveryArtifact-or-private-locators>",
  "trusteeManifests": ["<current-signed-manifest-for-each-trustee>"],
  "trusteeReceipts": ["<signed-current-enrollment-receipts>"]
}
```

The map contains no `RUK`, root secret, mnemonic, or trustee share. It does
contain a sensitive social graph and recovery-routing metadata. The vault
encrypts it with AES-256-GCM under a separate random 256-bit recovery-map key
and fresh nonce, binding the implementation profile and a random map ID as
associated data. The ciphertext may be replicated; the holder stores the map
key offline as a recovery card, QR, hardware record, or another independently
chosen private channel.

On a fresh device, the candidate imports the map ciphertext and key. The vault
authenticates and decrypts it, verifies policy and receipt signatures, rejects
rollback, retrieves the current protected artifact, and constructs the
abstract `RecoveryBootstrap`. The candidate can then address the current
trustees and build `RecoverySession` without the old identity key.

A trustee or paid provider may additionally offer authenticated lookup of its
own slot, but the base profile has no public roster discovery. If the holder
loses every recovery-map key and cannot rediscover enough trustees through
prearranged relationships or provider accounts, recovery may fail even though
the shares still exist. The enrollment UI tests recovery-map import and states
this limitation explicitly.

## 6. Recovery session

### 6.1 Candidate request

Using the verified recovery map or a profile-compatible private lookup, the
recovering vault obtains the enrollment ID, current sequence, policy digest,
artifact ID, protected artifact and digest, and trustee routes. It then
generates a fresh HPKE destination key, a fresh Ed25519 session-proof key, and
a random session ID, and builds and signs the abstract `RecoverySession`. The
proof shows control of the request and binds the HPKE key; it does not
authenticate the old identity. The request includes the bootstrap bindings,
both destination keys, expiry, and factor evidence permitted for each trustee.

The old identity cannot be required to sign the request. Authentication comes
from the pre-enrolled trustee policy: human recognition, an offline recovery
code, a surviving independent authenticator, institutional proof, or another
declared mechanism. A trustee does not learn or demand factors enrolled only
with another trustee.

### 6.2 Trustee decision

Each trustee independently:

1. resolves the exact current enrollment and rejects stale sequences;
2. verifies the session signature made by the fresh proof key and its binding
   to the HPKE destination key;
3. checks its local candidate policy and allowed factor evidence;
4. applies attempt limits, cooldown, independent notification, and veto;
5. confirms that the requested artifact digest and recovery mode match;
6. decrypts its stored share envelope only inside its protected trustee
   application or service;
7. seals the share envelope to the session destination with HPKE; and
8. signs an abstract `TrusteeContribution` or bounded refusal.

HPKE `info` includes:

```text
"onym-shamir-recovery-contribution-v1",
sessionId,
enrollmentId,
enrollmentSequence,
policyDigest,
artifactId,
artifactDigest,
trusteeComponentId,
slot,
destinationKeysDigest,
expiresAt
```

A signature or share response from another session, destination, enrollment,
or sequence is invalid even if the underlying SLIP-0039 words are genuine.

### 6.3 Coordination

Any party can coordinate the session. The new client may contact trustees
directly, use one trustee as coordinator, or use a separately operated relay.
The coordinator may count signed approvals and relay ciphertext, but cannot
decrypt contributions or lower the threshold.

The candidate can collect contributions asynchronously until the session
expires. Only one contribution per distinct current slot counts. Duplicate
component IDs, member indices, or signatures do not create extra threshold
weight.

### 6.4 Local reconstruction

After receiving at least `t` valid contributions, the recovering vault:

1. verifies every trustee manifest, signature, slot, sequence, policy,
   artifact, session, destination, and expiry binding;
2. HPKE-opens contributions with the session destination private key;
3. validates outer envelopes and SLIP-0039 checksums;
4. rejects mixed identifiers, thresholds, groups, member indices, or duplicate
   shares;
5. combines exactly the profile-compatible shares locally to reconstruct
   `RUK`;
6. reconstructs the enrolled associated data from the verified protected-
   artifact header and opens the artifact using AES-256-GCM;
7. verifies the identity subject, descriptor digest, artifact schema, and
   recovery mode;
8. imports or migrates inside the vault's holder-facing recovery ceremony;
9. binds fresh device authentication and executes downstream compromise
   review; and
10. destroys plaintext shares, `RUK`, artifact plaintext, and both session
    private keys from memory on a best-effort basis.

The client never uploads the reconstructed `RUK` or plaintext artifact to the
coordinator, trustees, crash service, or notary.

### 6.5 Integrity without verifiable secret sharing

SLIP-0039 checksums help detect damaged encodings and its recovered-secret
digest helps reject an incorrect combination. The final AES-GCM tag and
identity binding provide another mandatory integrity check.

This profile does not implement Feldman, Pedersen, or another verifiable secret
sharing scheme. A trustee can submit a well-formed but wrong share and cause
recovery failure; the basic profile may not identify which trustee cheated.
The UI says “invalid contribution set,” not “artifact lost,” and preserves
signed evidence for a private dispute.

Clients do not auto-correct mnemonic words or silently search broad share
subsets. Automated correction can transform invalid input into different valid
input. Any diagnostic retry is explicit, bounded, local, and never reveals
share contents.

## 7. Operation mapping

| Abstract operation | Shamir behavior |
|---|---|
| `enroll` | Deliver one HPKE-sealed SLIP-0039 share per trustee and replicate artifact |
| `read-enrollment` | Return signed per-trustee sequence, expiry, and non-secret readiness |
| `bootstrap-recovery` | Decrypt and verify the holder's recovery map or use declared private trustee/provider lookup |
| `begin-recovery` | Create one destination-bound request for the current trustee set |
| `contribute-recovery` | Each approving trustee HPKE-seals its stored share to the destination |
| `read-recovery` | Aggregate signed non-secret session and contribution status |
| `cancel-recovery` | Candidate or enrolled veto cancels collection; trustees refuse later release |
| `finalize-recovery` | Client records successful local combine/import and may notify trustees |
| `rotate-enrollment` | Create a fresh `RUK`, artifact, SLIP-0039 set, and enrollment sequence |
| `revoke-enrollment` | Every reachable trustee destroys/revokes its old slot; client treats sequence as invalid |
| `export-enrollment` | Obtain threshold contributions to a fresh holder-controlled destination |
| `close-enrollment` | Revoke policy and request share/artifact deletion from all trustees |

No single trustee can complete `export-enrollment` or recovery. A trustee's
valid contribution is necessary evidence but not a successful recovery.

## 8. Rotation and trustee replacement

This profile does not support in-place addition, removal, or renumbering of one
ordinary share. Every policy or trustee-set change creates:

- a new random `RUK`;
- a newly encrypted artifact;
- a fresh SLIP-0039 identifier and complete share set;
- a higher enrollment sequence; and
- new receipts from all newly selected trustees.

A healthy vault can create this new enrollment directly from the identity
material it already controls. A recovering vault first obtains `t` old shares,
restores locally, and then performs the new enrollment. Only after the new set
is verified active does it revoke and request deletion of every old share.

Deletion receipts cannot prove a trustee made no copy. Fresh `RUK` and
ciphertext prevent old shares from opening the new enrollment, but old shares
can still open an old artifact copy. In secret-restoration mode, that old
artifact may contain the same root secret. Strong revocation therefore
requires authority migration and downstream support, not merely re-sharing.

Proactive share refresh without reconstructing the secret and verifiable
distributed key generation are possible research directions, but are outside
this v1 profile.

## 9. Lapse and availability

Each trustee defines its own offer and lapse policy. The holder's local
recovery dashboard computes current readiness from fresh signed status:

```text
active compatible trustees >= t  -> threshold presently reachable
active compatible trustees <  t  -> recovery endangered
```

This is not a guarantee of future cooperation. A synchronized outage,
jurisdictional order, disaster, account compromise, or human refusal can still
remove several trustees together.

A paid trustee must declare grace, export, deletion, and whether an unpaid
record can still approve recovery. A lapsed trustee cannot charge an
undisclosed emergency fee. The UI prompts a healthy holder to re-share before
the remaining active set approaches `t`.

The policy may mix free human trustees and paid providers. Payment failure at
one provider does not change the cryptographic threshold or appoint a
replacement.

## 10. Human trustee experience

A conforming human-trustee application:

1. explains that accepting a share creates a security and availability duty;
2. verifies the holder's invitation and profile before accepting;
3. stores the share under local device authentication and encrypted backup
   rules declared to the holder;
4. displays an opaque holder-chosen label locally without publishing the
   social relationship;
5. reminds the trustee to review readiness periodically without exposing
   share words;
6. shows recovery destination fingerprint, request age, declared reason,
   cooldown, and independent contact instructions;
7. requires deliberate approval and never approves from a notification tap;
8. supports refusal, suspected-fraud reporting, device migration, and
   holder-requested deletion; and
9. does not treat possession of the holder's public profile or a convincing
   story as protocol proof.

Human recognition is subjective. The holder should prearrange how a trustee
will recognize a legitimate candidate under device loss and what independent
contact path to use. The app must not upload address books or infer trustees
without consent.

## 11. Trustee storage obligations

Each trustee protects its share at rest using its declared storage class. A
service trustee may use an HSM/KMS; a human trustee app may use platform secure
storage and an encrypted, separately controlled device backup. The manifest
states whether the share survives device loss and who can restore it.

A trustee must:

- keep enrollment and recovery private;
- prevent share export through routine logs, UI, support, clipboard, or
  analytics;
- reject stale or malformed outer envelopes;
- authenticate local operators and protect release keys;
- issue readiness, approval, refusal, rotation, and deletion receipts;
- notify under the enrolled policy;
- disclose loss or suspected copy of a share promptly; and
- never transfer the slot to another operator without a full holder-authorized
  re-enrollment.

Replicating one trustee's share improves that trustee's availability but does
not add a trustee. If another party can restore the replica independently, the
operator must disclose that party inside its trust domain.

## 12. Privacy boundary

Each trustee can learn that it serves one opaque enrollment, the locally
chosen holder label if any, its own candidate factors, recovery attempts sent
to it, payment state, and its own decision. It need not learn the other
trustees or the holder's messages, names, groups, addresses, balances, or
applications.

The client retains the canonical `RecoveryPolicy` and full trustee array. It
sends a trustee only the signed share envelope that maps the abstract per-
trustee authorization: the common policy digest plus that trustee's component,
slot, share parameters, and enforcement terms. The trustee cannot recompute
the private full-policy digest, but can verify the holder signature over its
own complete duties and require all later requests to bind that digest.

The coordinator can observe which endpoints participate, timing, payload
sizes, and completion status unless a stronger routing profile hides them. The
encrypted artifact and shares must not be posted to a public ledger merely to
coordinate availability.

The client should contact trustees independently or through privacy-preserving
transport, pad contribution envelopes where a profile specifies it, and use
scoped trustee/account keys. These measures reduce linkability; they do not
hide trustee relationships from a global network observer.

Recovery receipts remain private. A dispute may disclose the minimum receipt
necessary to the selected adjudicator. Publicly naming a human trustee can
create coercion and targeting risk.

## 13. Payment and incentives

Every trustee defines its own payment model. An offer may be:

- voluntary and free;
- reciprocal between identities;
- one-time per enrollment or re-sharing ceremony;
- periodic for protected storage and readiness;
- per reviewed recovery request; or
- institution-funded.

A threshold enrollment may contain different offers and rails. The client
shows the total expected cost and the consequences of each independent lapse.
Payment is made to each selected trustee under its offer, after disclosed
channel fees, taxes, refunds, UI/broker splits, and contributor shares.

A trustee earns only for its declared service. It gains no ownership of the
identity, no right to see other trustees, no vote in unrelated seats, and no
royalty on the holder's later messages, assets, banking, charity, or recovery.
Approval cannot be sold to an attacker: a recovery fee buys policy evaluation
or completed service, not a guaranteed `approved` decision.

## 14. Threat summary

| Failure | Consequence | Mitigation or honest limit |
|---|---|---|
| Fewer than `t` trustees available | Permanent or delayed recovery failure | Choose `n - t` tolerance, independent domains, readiness checks, timely re-sharing |
| Any `t` trustees collude | They reconstruct `RUK` and artifact | Choose trusted independent parties; threshold defines, not removes, this risk |
| Candidate deceives `t` trustees | Unauthorized recovery | Prearranged factors, session-bound destination, cooldown, notification, independent verification |
| Coordinator compromised | Metadata exposure, delay, censorship | Direct/multiple routes; HPKE prevents share plaintext disclosure |
| One share stolen | No recovery below threshold, but loss of safety margin | Prompt disclosure and complete re-sharing |
| Malicious wrong share | Recovery fails and culprit may be unclear | Outer signatures, SLIP-0039 checks, final AEAD; VSS is out of scope |
| Mixed old/new shares | Invalid reconstruction or rollback attempt | Enrollment sequence, artifact digest, fresh identifier, strict set validation |
| Trustee copied an old share | Old artifact may remain recoverable | Fresh enrollment protects new artifact; migrate root authority for strong revocation |
| Recovering device compromised | Plaintext is stolen after combination | Trusted endpoint ceremony, minimal memory lifetime, immediate rotation |
| Public trustee graph | Coercion and correlation | Private enrollment/receipts, scoped IDs, no public ledger by default |

## 15. Conformance fixtures

In addition to the abstract suite, the profile publishes and tests:

1. generation and combination vectors for 2-of-3, 3-of-5, and boundary
   `n = 16` SLIP-0039 sets;
2. holder-authorized enrollment envelopes and refusal of missing, invalid,
   wrong-key, wrong-trustee, or stale-sequence authorizations, plus a fixture
   proving that one envelope contains no other trustee entry and that an
   unsolicited or reused trustee challenge is refused;
3. canonical share words and strict rejection of mixed identifiers, groups,
   thresholds, duplicate indices, invalid checksums, and unsupported
   parameters;
4. AES-256-GCM artifact vectors with every associated-data binding changed in
   negative cases;
5. enrollment HPKE vectors for each trustee and recovery HPKE vectors for a
   fresh destination;
6. recovery-map encryption, authenticated import, current-sequence bootstrap,
   rollback refusal, and failure after all bootstrap paths are lost;
7. rejection of a valid share response replayed into another session,
   destination, enrollment, or sequence;
8. threshold completion with `t` contributions and non-completion with
   `t - 1`;
9. malicious well-formed share and final artifact-integrity failure;
10. cooldown, veto, refusal, timeout, duplicate trustee, and late contribution;
11. full re-sharing on threshold or trustee-set change and refusal of every old
   contribution against the new artifact; and
12. log, crash, UI snapshot, clipboard, notification, and analytics scans for
    share words, `RUK`, artifact plaintext, candidate factors, and destination
    private keys.

Cross-platform fixtures must run in every supported vault and trustee app.
Round-tripping through one library alone does not prove interoperability.

## 16. Status

This is a proposed implementation profile, not a deployed Onym recovery
network. Production use requires canonical fixtures, reviewed libraries,
independent cryptographic and UX assessment, trustee applications, incident
procedures, full recovery and re-sharing drills, and clear provider/human
trustee terms.

## References

1. Adi Shamir, “How to Share a Secret,” *Communications of the ACM* 22(11),
   1979: <https://doi.org/10.1145/359168.359176>
2. SatoshiLabs, “SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes”:
   <https://github.com/satoshilabs/slips/blob/master/slip-0039.md>
3. IETF RFC 9180, “Hybrid Public Key Encryption”:
   <https://www.rfc-editor.org/rfc/rfc9180>
4. NIST SP 800-38D, “Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM) and GMAC”:
   <https://csrc.nist.gov/pubs/sp/800/38/d/final>
