# **Epoch Clock**
An Open Standard for Verifiable, Decentralized Time

**Specification Version:** v2.0.0
**Status:** Implementation Ready. Mechanically Proven.
**Author:** rosiea
**Contact:** [PQRosie@proton.me](mailto:PQRosie@proton.me)
**Date:** November 2025
**Licence:** Apache License 2.0 — Copyright 2025 rosiea


# **ABSTRACT**

The Epoch Clock defines a deterministic, decentralised, cryptographically signed time authority designed for systems that require verifiable, replay-resistant, and sovereignty-preserving temporal semantics. It provides ML-DSA-65–signed EpochTicks anchored to a canonical Bitcoin inscription, allowing clients to validate time without relying on system clocks, NTP, DNS, cloud services, or centralised providers. All profile and tick objects use canonical JSON or deterministic CBOR to ensure cross-implementation consistency.

EpochTicks integrate with PQSF and dependent specifications by supplying a verifiable temporal reference for consent windows, policy enforcement, transport binding, replay prevention, and session boundaries. The Epoch Clock also defines deterministic profile-lineage rules, mirror-reconciliation behaviour, offline constraints, and Stealth Mode operation. Runtime-integrity systems such as PQVL may contribute additional validity signals, but the Epoch Clock remains independently verifiable using only on-chain profile data and deterministic mirror rules.

---

# **PROBLEM STATEMENT**

Distributed systems commonly assume that local clocks, NTP infrastructure, DNS-based services, or cloud time providers can be trusted to provide accurate temporal information. These assumptions introduce failure modes: clocks drift or can be altered, NTP and DNS are susceptible to spoofing or poisoning, cloud services introduce centralisation and monitoring risks, and application-layer timestamps lack verifiable provenance. Replay, rollback, stale timestamps, and cross-session inconsistencies become feasible in these models.

Applications that require deterministic authorisation—such as replay protection, policy enforcement, consent-expiry windows, multi-device coordination, recovery delays, or AI-alignment freshness—cannot rely on ambient or centralised time sources. Time must be independently verifiable, tamper-evident, privacy-preserving, and reproducible across devices, including offline or partitioned environments.

The Epoch Clock addresses these issues by anchoring a canonical profile to Bitcoin, signing all ticks with post-quantum signatures, enforcing canonical encoding, and defining deterministic validation, lineage, and reconciliation rules. This enables systems to rely on verifiable time without trusting any single mirror, local clock, or external infrastructure. Attestation layers such as PQVL may supply runtime-validity data, but time itself remains independently verifiable.

---

# **1. PURPOSE AND SCOPE (NORMATIVE)**

## **1.1 Purpose**

The Epoch Clock provides a decentralised, post-quantum-secured temporal authority suitable for systems that depend on verifiable time for security decisions. It defines:

* a canonical Bitcoin-inscribed profile;
* a deterministic ML-DSA-65–signed tick structure;
* validation rules for freshness, monotonicity, encoding, and profile lineage;
* decentralised mirror behaviour and reconciliation;
* privacy-preserving, metadata-minimal time distribution;
* fully offline and sovereign operation.

This allows systems to enforce replay boundaries, expiry windows, policy timing rules, and multi-device consistency using verifiable, cryptographically authenticated time.

## **1.2 Scope**

This specification defines:

* the Epoch Clock Profile structure and inscription model
* the EpochTick structure and validation rules
* signature, hashing, and canonical-encoding requirements
* mirror operation, consensus, and reconciliation
* profile lineage, rotation, and emergency governance
* offline, Stealth Mode, and air-gapped operation
* integration boundaries with PQSF, PQHD, PQVL, and PQAI
* security, privacy, and sovereignty requirements
* deterministic client-side enforcement rules

This specification does **not** define:

* Bitcoin consensus or transaction formats
* application-level timing semantics or business logic
* wallet custody rules (PQHD)
* runtime-integrity measurement (PQVL)
* AI alignment or drift analysis (PQAI)

External attestation systems such as PQVL may satisfy runtime-validity predicates, but Epoch Clock validation does not depend on them.

## 1.2A Canonical Profile Reference (NORMATIVE)

The canonical Epoch Clock v2.0 profile used by all PQSF, PQHD, PQVL, and PQAI systems is:

profile_ref = "ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0"

All compliant implementations MUST validate this inscription directly and MUST reject any EpochTick whose `profile_ref` does not match this value. Profile lineage, mirror reconciliation, rotation behaviour, and freshness rules MUST all be evaluated using this canonical profile as the authoritative parent.

---

# **WHAT THIS SPECIFICATION COVERS**

This specification normatively defines:

1. **Temporal Authority**
   The canonical profile, Bitcoin anchoring model, lineage rules, and emergency-rotation semantics.

2. **EpochTick Semantics**
   ML-DSA-65 signatures, SHAKE256 hashing, canonical encoding, freshness, monotonicity, and profile_ref binding.

3. **Mirror and Reconciliation Model**
   Deterministic validation rules, cross-mirror consistency, divergence handling, and fail-closed behaviour.

4. **Canonical Encoding**
   JCS JSON and deterministic CBOR formats required for all signed or hashed objects.

5. **Offline, Stealth, and Sovereign Operation**
   Strict tick-reuse windows, freeze rules, reconciliation requirements, and partition-tolerant behaviour.

6. **Integration Semantics**
   How dependent systems interpret EpochTicks for consent windows, policy timing, runtime-integrity timestamping, AI-alignment freshness, and session boundaries.

7. **Security, Privacy, and Sovereignty Guarantees**
   Metadata minimisation, centralisation-avoidance, and full local verifiability using only deterministic validation rules.

Optional annexes provide examples and extended workflows without modifying the normative core.

---

1.1A Trustless Temporal Authority (INFORMATIVE)

The Epoch Clock is designed so that time validation never depends on central servers, cloud infrastructure, DNS, or NTP. All security properties derive from Bitcoin-inscribed profiles, ML-DSA-65 signatures, canonical encoding, and mirror consensus. Users may verify, fork, or self-host mirror infrastructure without coordination or permission from any operator.

The canonical Epoch Clock v2.0 profile is inscribed at:

profile_ref = "ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0"

(Informative) Public explorers for convenience only:

https://ordinals.com/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
https://bestinslot.xyz/ordinals/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
https://www.ord.io/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0

Explorer URLs are non-authoritative. Clients MUST validate the canonical profile using the on-chain inscription referenced by profile_ref.

---

## **1.3 Relationship to PQSF**

PQSF depends on the Epoch Clock for deterministic, post-quantum-signed time. Specifically, PQSF MUST consume:

* **EpochTick** — the authoritative source of freshness, monotonicity, and temporal ordering for all consent, policy, ledger, and runtime predicates (see PQSF 4).
* **Profile lineage rules** — PQSF MUST validate profile_ref against the active Epoch Clock v2 profile and child-profile lineage (see PQSF 4.2).
* **Tick freshness** — PQSF MUST enforce tick age and monotonicity exactly as defined in this specification (see PQSF 4.3–4.4).
* **Canonical encoding** — PQSF MUST use the canonical JSON/CBOR tick format defined by the Epoch Clock (see PQSF 3.5).
* **Replay and rollback detection** — PQSF MUST treat invalid, stale, or rollback ticks as fail-closed conditions for all dependent operations (see PQSF 4.5).

The Epoch Clock does not depend on PQSF. PQSF depends on the Epoch Clock to provide deterministic, sovereign, verifiable time for all temporal predicates.

## **1.5 Non-Goals**

The Epoch Clock does **not** aim to:

* replace Bitcoin consensus or timestamps
* serve as an oracle or data feed
* provide subjective time or timezone information
* manage private keys or custody models
* define wallet-level policy
* define application-level semantics

## **1.6 Deployment Environments**

The Epoch Clock supports:

* web browsers
* hardware devices
* air-gapped systems
* offline-first clients
* PQHD signers
* PQVL agents
* PQAI runtimes
* enterprise deployments
* sovereign, no-DNS networks
* WASM and mobile applications

## **1.7 Terminology and Definitions**

* **EpochTick**: A signed timestamp object.
* **Profile**: The long-lived parameter set for tick validation.
* **Mirror**: A node that fetches, validates, and republishes ticks.
* **Profile lineage**: Parent–child profile structure across Bitcoin inscriptions.
* **EmergencyTick**: A tick issued under emergency-governance conditions to support urgent profile rotation or cutover.
* **Canonical encoding**: JSON (JCS) or deterministic CBOR.

## **1.8 Compatibility With Existing Standards**

Epoch Clock integrates with:

* Bitcoin Ordinals
* JCS JSON (RFC 8785)
* Deterministic CBOR (RFC 8949 §4.2)
* PQSF transport (hybrid TLS, STP, TLSE-EMP)
* ML-DSA-65 and ML-KEM-1024 (NIST draft PQC)

## 1.9 Backwards Compatibility

Epoch Clock v2.0.0 supersedes all v1.x profiles and becomes the new canonical parent profile for all future rotations. Clients that previously validated v1.x ticks may continue to do so for historical data, but v1 profiles are not required to remain valid or lineage-compatible under v2.

Epoch Clock v2.0.0 maintains compatibility with:

* all existing PQSF v1.0.0 structures
* PQHD v1.0.0 tick rules
* Offline and Stealth Mode client behaviour
* Bitcoin mainnet and testnet deployments

No v1.x behaviour is required to persist as an active profile; v2.0 establishes stronger, fully normative semantics and becomes the authoritative lineage root.


## **1.10 Threat Model (High-Level)**

The Epoch Clock defends against:
forged time
replayed time
NTP poisoning
system-clock rollback
cross-domain replay
stale-tick attacks
consensus downgrade attacks
mirror manipulation
profile lineage forgery
partial compromise of mirrors
classical cryptographic break
quantum adversaries

Attackers are assumed capable of:
network interception
TLS tampering
state rollback
classical key theft
forging classical time sources
replaying valid ticks
partially compromising mirror infrastructure

(Informative)
This section describes only the temporal-authority threat surface. The complete, cross-module attack analysis — including transport, runtime, custody, identity, cloud, AI, supply-chain, and physical-world threats — is defined in PQ Annex A (See PQ Annex A — Security & Attack Surface Analysis).

---

# **2. ARCHITECTURE OVERVIEW (NORMATIVE)**

## **2.1 Architecture Layers**

The Epoch Clock comprises:

* **Bitcoin inscription layer**
* **Profile layer** (long-lived parameters)
* **Tick issuance layer** (ML-DSA-65 signatures)
* **Mirror layer** (distributed validation and reconciliation)
* **Client validation layer** (PQSF/PQHD/PQVL/PQAI)
* **Governance and emergency layer**

## **2.2 Components**

* **Profile**: JSON/CBOR object defining duration, public keys, emergency quorum, etc.
* **Tick issuer**: Entity producing signed ticks.
* **Mirrors**: Independent nodes verifying and serving ticks.
* **Clients**: PQSF-compliant applications using ticks for temporal enforcement.

## **2.3 Data Flow Overview**

1. Profile inscribed on Bitcoin
2. Mirrors retrieve inscription
3. Mirrors canonicalise and hash profile
4. Mirrors fetch ticks
5. Clients fetch ticks from mirrors
6. Clients validate ticks under profile
7. Ticks enforce security in PQSF/PQHD/etc.

## **2.4 Actor Roles**

* **Issuer**: Produces ticks using ML-DSA-65
* **Mirror**: Publishes validated ticks
* **Client**: Validates ticks before operation
* **Emergency quorum**: Signs profile rotations

## **2.5 Security Model Overview**

The Epoch Clock ensures:

* authenticated time
* deterministic replay boundaries
* tamper-evident chain of ticks
* decentralised validation via mirrors
* fail-closed behaviour under divergence

## **2.6 Trust Model**

Clients trust:

* profile public keys
* Bitcoin inscription as immutable anchor
* majority mirror agreement
* ML-DSA-65 signature validity
* deterministic canonical encoding

Clients do **not** trust:

* system clocks
* NTP
* DNS
* cloud servers
* single mirrors
* unauthenticated intermediaries

## **2.7 Protocol Overview**

The protocol defines:

* profile structure and lineage
* tick structure and signature validation
* tick freshness and monotonicity rules
* profile pinning and rotation (including emergency rotation)
* mirror discovery, API, and reconciliation behaviour
* bootstrap, error handling, and fail-closed recovery flows
* offline, Stealth Mode, and partition-tolerant operation


## **2.8 Dependencies**

Epoch Clock depends on:

* ML-DSA-65 (signatures)
* SHAKE256-256 (hashing)
* JCS canonical JSON / deterministic CBOR
* Bitcoin ordinal inscriptions
* PQSF transport and encoding rules

## 2.9 Sovereign Deployment

Epoch Clock deployments MUST support sovereign, offline, and partitioned
operation. Clients MUST be able to validate profiles and ticks using only the
Bitcoin inscription and deterministic validation rules. This requirement
ensures that time remains a user-verifiable primitive even when network
conditions are hostile, censored, or intentionally degraded.

---

# **3. CRYPTOGRAPHIC PRIMITIVES (NORMATIVE)**

## **3.1 Signature Algorithms**

The Epoch Clock uses **ML-DSA-65** for all profile and tick signatures.
Classical ECDSA-P256 may be included for dual-signature backwards compatibility.

## **3.2 KEM Algorithms**

ML-KEM-1024 may be used for encrypted mirror communication or profile transport but is optional.

## **3.3 Hash Functions**

SHAKE-256/256 is used for:

* profile hashing
* tick hashing
* profile lineage verification
* mirror reconciliation
* downstream PQSF binding

## **3.3.1 Hash Output Length (NORMATIVE)**

All SHAKE256 invocations defined in this specification MUST use an output length of exactly 256 bits (32 bytes). This requirement applies to:

profile hashing (hash_pq),

tick hashing,

profile-lineage verification,

mirror-consensus validation,

PQSF and downstream transport bindings that depend on Epoch Clock hashing.

Implementations MUST NOT vary the digest length.
All compliant systems MUST produce bit-identical 32-byte digests for the same canonical input.

## **3.4 Randomness Requirements**

Tick issuers must use CSPRNG entropy meeting NIST SP 800-90B requirements.

## **3.5 Domain Separation**

Domain strings MUST be used for hash and signature context:

* `"EpochClock-Profile-v2"`
* `"EpochClock-Tick-v2"`

## **3.6 Canonical Encoding Requirements**

Profiles and ticks MUST use:

* JCS JSON (RFC 8785), **or**
* Deterministic CBOR (RFC 8949 §4.2)

Encoding MUST be byte-identical across implementations.

---

## **3.6.1 Bitcoin Inscription Format (NORMATIVE)**

The Epoch Clock Profile MUST be inscribed on Bitcoin using the Ordinals protocol.

### **3.6.1.1 Content Requirements**

* The inscription MUST contain the exact JCS-canonical JSON profile object.
* Content-Type MUST be:

```
application/json
```

* The inscribed data MUST be UTF-8 encoded.
* No additional whitespace, comments, or metadata outside canonical JCS rules is permitted.

### **3.6.1.2 Provenance**

`profile_ref` MUST equal:

```
"ordinal:<txid:iN>"
```

Where `<txid:iN>` identifies the exact Ordinal inscription transaction.

A client MUST fetch this inscription and validate:

1. Canonical decoding
2. Recomputed `hash_pq`
3. `sig_pq` verification
4. `p == "epoch-clock"`
5. `origin == "ordinal"`

### **3.6.1.3 Child Profile Inscriptions**

Child profiles MUST:

* include `parent_profile_ref`
* follow identical canonical encoding rules
* be inscribed as independent ordinal inscriptions
* be validated according to PQSF §5.2.4 lineage rules

Clients MUST discover lineage by following parent_profile_ref → child_profile_ref → newest valid profile.

---

## **3.7 Cryptographic Failure Modes**

Clients MUST fail closed on:

* signature mismatch
* hash_pq mismatch
* profile invalidation
* tick expiry
* canonical encoding mismatch
* divergence between mirrors
* parent/child lineage mismatch

---

# **4. CORE PROTOCOL MECHANICS (NORMATIVE)**

## **4.1 Data Structures (CDDL / CBOR / JSON)**

### **4.1.1 EpochTick (Authoritative)**

Ticks MUST be encoded in deterministic CBOR or JCS-compliant canonical JSON:

```
EpochTick = {
  t:              uint,        ; unix seconds
  profile_ref:    tstr,        ; "ordinal:<txid:iN>"
  alg:            tstr,        ; "ML-DSA-65"
  sig:            bstr         ; ML-DSA-65 signature
}
```

### **4.1.2 Epoch Clock Profile (Authoritative)**

This structure corresponds exactly to the object found in `epoch-clock-v2.json`.

```
EpochClockProfile = {
  alg_alt:                       tstr,     ; optional classical signature algorithm
  alg_pq:                        tstr,     ; mandatory PQ algorithm ("ML-DSA-65")
  duration_seconds:              uint,
  emergency_quorum:              [* tstr],
  format:                        tstr,     ; "unix_seconds" or "ordinal"
  hash_pq:                       tstr,     ; shake-256/256 prefixed digest
  origin:                        tstr,     ; "ordinal"
  p:                             tstr,     ; MUST be "epoch-clock"
  profile_ref:                   tstr,
  pubkey_alt_spki_der_b64u:      tstr / null,
  pubkey_pq:                     tstr,
  rotation_schedule_seconds:     uint,
  sig_pq:                        bstr,
  start_unix:                    uint,
  v:                             tstr
}
```

### **4.1.3 Parent–Child Profile Lineage (PQSF-Aligned)**

Child profile:

```
ChildProfile = {
  ... EpochClockProfile fields ...,
  parent_profile_ref: tstr
}
```

### **4.1.4 MirrorConsensusPacket**

```
MirrorConsensusPacket = {
  tick:      EpochTick,
  profile:   EpochClockProfile,
  mirror_id: tstr,
  sig_mirror: bstr
}
```

## **4.1.5 Tick Time Base (NORMATIVE)**

The EpochTick time field t MUST represent Strict Unix Time, defined as the number of elapsed seconds since 1970-01-01T00:00:00Z ignoring leap seconds. Strict Unix Time provides deterministic, 86,400-second days and guarantees monotonic progression even during UTC leap-second events.

Implementations MUST NOT:

interpret t using UTC rules that include leap-second insertions or repeats,

smooth, adjust, or correct t based on local system clock behaviour,

derive t from RTC or NTP time sources.

Ticks MUST be treated as strictly monotonic and MUST NOT be corrected using local or system time. The tick value t derives exclusively from the Epoch Clock issuer’s monotonic counter and MUST be interpreted identically across all compliant implementations.

---

## **4.2 State Machines / Enforcement Pipelines**

### **4.2.1 Client Tick Validation Pipeline**

A PQSF/PQHD/PQVL/PQAI client MUST validate ticks via:

1. **Fetch** tick from ≥2 mirrors
2. **Canonicalise**
3. **Validate profile_ref**
4. **Verify ML-DSA-65 signature**
5. **Recompute SHAKE256 hash**
6. **Verify tick freshness** ≤ 900 seconds
7. **Check monotonicity**
8. **Mirror consensus check**
9. **Pass to consuming subsystem (PQSF/PQHD/etc.)**

### **4.2.2 Mirror Behaviour State Machine**

1. Startup
2. Fetch profile
3. Validate structure + sig_pq + hash_pq
4. Fetch ticks
5. Verify tick signatures
6. Publish only valid ticks
7. Enter steady state
8. Detect lineage extension (child profile)
9. Promote child → new active profile
10. Rehash / reconcile
11. Broadcast rotation event

---

## **4.3 Validation Rules (Authoritative)**

### **4.3.1 Profile Validation**

A client MUST reject a profile if ANY of the following fail:

* invalid canonical encoding
* invalid ML-DSA-65 signature
* invalid hash_pq
* missing mandatory fields
* p ≠ "epoch-clock"
* profile_ref mismatch
* unsupported format
* empty or invalid emergency_quorum
* parent chain incomplete (if child profile)

### **4.3.2 Tick Validation**

A tick MUST be rejected if:

* signature invalid
* profile_ref does not match pinned profile
* t is older than freshness window
* t < last_valid_tick
* encoding not canonical
* mirrors disagree
* tick references unknown or invalid profile

### **4.3.3 Mirror Consensus**

A client MUST obtain:

* at least 2 matching ticks
* matching profile_ref
* matching hash_pq
* matching t
* matching signature validity

If mirrors diverge → FAIL_CLOSED.

---

## **4.4 Operational Workflows**

### **4.4.1 Fetching a Tick (PQSF Client)**

```
tick = get_tick()
if validate(tick):
    return tick
else:
    error("E_TICK_INVALID")
```

### **4.4.2 PQHD Signing Workflow (Tick Integration)**

1. tick ← epoch_clock.get_current_tick()
2. validate tick freshness
3. validate Policy Enforcer policy
4. validate ConsentProof tick window
5. validate device attestation freshness
6. sign bundle if all predicates satisfied

### **4.4.3 PQVL Probe Workflow**

PQVL integrates ticks for drift timestamps:

1. Agent performs system/process/policy/integrity probes
2. Each probe records tick
3. Drift flagged if tick stale or missing

### **4.4.4 PQAI Alignment Freshness**

PQAI uses ticks for:

* alignment_tick boundaries
* behavioural drift evaluation windows
* provenance chains
* novelty detection timing

### **4.4.5 Stealth Mode Tick Workflow**

In Stealth Mode:

* mirrors unavailable
* tick reuse limited strictly to ≤ 900 seconds
* no fallback to local clock
* exit requires ≥2 matching mirror ticks

---

## **4.4.5 Mirror Discovery (NORMATIVE)**

Clients MUST implement at least one supported method for discovering Epoch Clock mirrors.
Implementations MAY support multiple mechanisms simultaneously to increase resilience.

### **4.4.5.1 Static Mirror List (Required for MVP)**

A client MAY embed a list of mirrors, for example:

```
[
  "https://mirror1.epochclock.net",
  "https://mirror2.epochclock.net",
  "https://mirror3.epochclock.net"
]
```

Requirements:

* Mirrors MUST use HTTPS or TLSE-EMP.
* Client MUST query ≥2 mirrors for every tick request.
* Responses MUST be validated under §4.3 and §5.

### **4.4.5.2 Profile-Embedded Mirror List (Recommended)**

Future profile versions MAY include:

```
"mirrors": ["https://...", "stp://..."]
```

If present:

* Clients MUST validate mirror URLs.
* Clients MAY use embedded mirrors but MUST NOT trust them exclusively.

### **4.4.5.3 DNS-Based Discovery (Optional)**

Clients MAY use DNS records such as:

```
_epochtick._tcp.example.com
```

DNS results MUST be ignored if:

* DNSSEC validation fails
* domain does not match `profile_ref`
* mirror list diverges from majority consensus

### **4.4.5.4 Local / Enterprise Discovery (Optional)**

STP broadcast or enterprise configuration MAY be used.
All discovered mirrors MUST adhere to the same validation rules as publicly listed mirrors.

---

## **4.4.6 Mirror API (NORMATIVE)**

Mirrors MUST expose at least one deterministic, canonical API for profile and tick retrieval.

### **4.4.6.1 HTTPS GET Endpoint (Required)**

**Endpoint:**

```
GET /tick
```

**Response** (JCS JSON or deterministic CBOR):

```json
{
  "tick": {
    "t": 1730000000,
    "profile_ref": "ordinal:<txid:iN>",
    "alg": "ML-DSA-65",
    "sig": "<b64>"
  },
  "mirror_id": "mirror-001",
  "sig_mirror": "<b64>"
}
```

Clients MUST validate:

* canonical encoding
* tick signature per §4.3
* `sig_mirror` against known mirror identity
* timestamp freshness

### **4.4.6.2 Profile Fetch**

```
GET /profile
```

Returns the canonical Epoch Clock Profile JSON (JCS).

### **4.4.6.3 STP Endpoint (Optional, INFORMATIVE)**

Mirrors MAY implement an STP (“Sovereign Transport Protocol”) endpoint for environments where DNS, public CA infrastructure, or traditional HTTPS are not available or not desired.

- The detailed STP handshake, framing, and security properties are specified in the PQSF transport layer (see PQSF STP Annex).
- When used, STP MUST carry the same canonical `tick` and `profile` objects as defined in §4.1, encoded using deterministic CBOR or JCS JSON.
- All validation rules in §3, §4, and §5 apply identically to ticks and profiles received over STP.

This specification does not redefine STP itself; it only states how EpochTicks and profiles are transported over an STP channel.

### **4.4.6.4 Mirror Error Codes**

* `E_MIRROR_UNAVAILABLE`
* `E_MIRROR_DIVERGENCE`
* `E_PROFILE_MISMATCH`
* `E_TICK_INVALID`

### **4.4.6.5 Rate-Limiting (Informative)**

Mirrors SHOULD implement basic rate-limiting but MUST NOT introduce non-determinism or personalized responses.

Numeric rate limits (e.g., requests-per-second thresholds) are deployment-specific and intentionally not specified by this document. Implementers MUST ensure that any rate-limiting strategies do not alter the semantic content of responses or introduce per-client variation that could affect determinism or privacy.

---

4.4.6.6 Example Mirror Implementation Snippets (INFORMATIVE)
The following examples provide non-normative reference patterns for implementing Epoch Clock mirror endpoints. Mirrors MAY use any framework or language, provided all responses remain deterministic and comply with canonical encoding rules.

4.4.6.6.1 Minimal /tick Endpoint (Illustrative)
def get_tick():
    tick = fetch_latest_verified_tick()
    canonical_tick = canonical_encode({
        "t": tick["t"],
        "profile_ref": tick["profile_ref"],
        "alg": tick["alg"],
        "sig": tick["sig"]
    })
    response = {
        "tick": canonical_tick,
        "mirror_id": MIRROR_ID,
        "sig_mirror": sign_with_mirror_key(canonical_tick)
    }
    return canonical_encode(response)

4.4.6.6.2 Minimal /profile Endpoint (Illustrative)
def get_profile():
    profile_bytes = load_canonical_profile()
    response = {
        "profile": profile_bytes,
        "mirror_id": MIRROR_ID,
        "sig_mirror": sign_with_mirror_key(profile_bytes)
    }
    return canonical_encode(response)

4.4.6.6.3 Illustrative Tick Reconciliation Logic
def reconcile_tick_sources():
    local_tick = fetch_local_tick()
    peer_ticks = fetch_peer_mirror_ticks()
    candidates = [local_tick] + peer_ticks
    valid = [t for t in candidates if verify_tick_signature(t)]
    selected = max(valid, key=lambda x: x["t"])
    return selected

4.4.6.6.4 Example Canonical Encoder Wrapper
def canonical_encode(obj):
    return jcs_canonical_json_dumps(obj)

## **4.4.7 Mirror Identity and Trust Model (NORMATIVE)**

Mirrors MUST authenticate their responses using a long-term public key, and clients MUST verify `sig_mirror` before trusting any tick or profile data.

### **4.4.7.1 Mirror Public Keys**

Each mirror MUST have a stable public key (`mirror_pubkey`) used solely for signing API responses.

Mirror keys MAY be distributed via one or more of:

- Static configuration embedded in the client
- Operator-managed configuration files
- Enterprise configuration systems

The mechanism for provisioning `mirror_pubkey` values is deployment-specific and out of scope for this specification, but:

- Clients MUST treat any change of `mirror_pubkey` as a security-relevant event.
- Implementations SHOULD support pinning mirror keys to prevent downgrade or substitution attacks.

### **4.4.7.2 Validating `sig_mirror`**

For any response containing `sig_mirror`:

1. Construct the canonical encoding of the full response body excluding the `sig_mirror` field.
2. Verify `sig_mirror` using the configured `mirror_pubkey` and the mirror’s signature algorithm (e.g., ML-DSA-65).
3. If verification fails:
   - The response MUST be discarded.
   - The client MUST raise `E_SIG_INVALID` or `E_MIRROR_UNAVAILABLE`.
   - The client SHOULD query an alternate mirror as per §4.5.1.

### **4.4.7.3 Mirror Trust Policy**

The policy for selecting which mirrors to trust (and how many) is deployment-specific and out of scope.

However:

- Clients MUST NOT treat any single mirror as inherently authoritative.
- Clients MUST obtain and validate ticks from at least two independent mirrors as described in §4.3 and §4.4.5.

---

## **4.5 Error Handling & Failure Codes**

The Epoch Clock MUST produce or propagate:

* **E_TICK_INVALID**
* **E_TICK_EXPIRED**
* **E_TICK_ROLLBACK**
* **E_TICK_DIVERGENCE**
* **E_PROFILE_INVALID**
* **E_PROFILE_MISMATCH**
* **E_PROFILE_EXPIRED**
* **E_MIRROR_DIVERGENCE**
* **E_MIRROR_UNAVAILABLE**
* **E_CANONICAL_MISMATCH**
* **E_HASH_MISMATCH**
* **E_SIG_INVALID**

All consuming systems MUST treat these as **FAIL_CLOSED**.

---

## **4.6 Transport Binding & Session Rules (PQSF Integration)**

EpochTicks MUST bind to PQSF transport requirements:

* embedded in ConsentProof
* included in Policy Enforcer evaluation
* MUST be fresh for exporter_hash binding
* included in TLSE-EMP transcripts
* included in STP offline messages
* used for session boundary enforcement

---

## **4.5.1 Error Recovery Procedures (NORMATIVE)**

Clients encountering errors MUST follow one of the mandatory recovery flows below.

### **4.5.1.1 Mirror Divergence**

* Query at least one additional mirror.
* If divergence persists → raise `E_MIRROR_DIVERGENCE` → FAIL_CLOSED.
* Retry only after `retry_interval_seconds` (implementation-defined).

### **4.5.1.2 Tick Expiry**

* Attempt to retrieve a fresh tick.
* If unavailable → freeze all time-dependent operations.
* If Stealth Mode is active, refresh MUST wait until exit conditions in §8.2 are met.

### **4.5.1.3 Profile Mismatch**

* Fetch the inscribed profile referenced by `profile_ref`.
* Validate canonical encoding, `hash_pq`, and `sig_pq`.
* If mismatch persists → FAIL_CLOSED.

### **4.5.1.4 Canonical Encoding Error**

* Reject the tick.
* Retry using an alternate mirror.
* Log the failure in the dependent system’s ledger (PQHD / PQSF / PQVL).

---

# **5. TIME / CLOCK / PROFILE INTEGRATION (NORMATIVE)**

## **5.1 Overview**

The Epoch Clock defines the authoritative time model for all PQSF-compliant systems. Every time-sensitive operation MUST be evaluated using EpochTicks.

## **5.2 Profile Structure**

The authoritative Epoch Clock Profile is defined by the JSON in your project folder (`epoch-clock-v2.json`).
All fields MUST appear exactly as defined.

## **5.3 Tick Structure**

A valid EpochTick object MUST contain:

* `t`
* `profile_ref`
* `alg`
* `sig`

No additional fields are permitted inside the canonical payload.

## **5.4 Tick Validation Rules**

A tick is valid if:

1. ML-DSA-65 signature verifies
2. profile_ref matches pinned profile
3. tick freshness ≤ 900 seconds
4. tick ≥ last_valid_tick
5. canonical encoding checks pass
6. ≥2 mirrors agree

## **5.5 Tick Reuse Rules (Authoritative)**

The **Tick Reuse Rule**:

1. MAY reuse a tick for up to **900 seconds**
2. MUST freeze signing after 900 seconds until new tick validated
3. MUST NOT fallback to system clock
4. MUST NOT bypass reuse rules in:

   * offline mode
   * air-gapped
   * Stealth Mode
   * PQAI alignment
   * PQHD signing
   * PQVL probes
5. No developer or emergency override may extend the reuse window.
6. EmergencyTick may shorten—never extend—reuse windows.

## **5.6 Mirror Reconciliation (Authoritative)**

Mirrors MUST:

* validate profile
* canonicalise profile
* validate hash_pq
* validate tick signatures
* reconcile with ≥1 other mirror
* publish only majority-agreed ticks

Clients MUST reject ticks if:

* no majority
* mismatched profiles
* mismatched encoding
* mirror divergence

## **5.7 Replay Resistance**

Replay attacks are mitigated by:

* signed tick structure
* freshness limit
* monotonicity
* profile_ref binding
* mirror majority
* deterministic encoding

Replay of:

* PSBTs
* ledger events
* ConsentProof
* identity credentials

…is impossible without a second valid tick.

## **5.8 Profile Pinning & Rotation**

A client MUST:

* pin one active profile
* reject ticks with unknown profile_ref
* update pinned profile only when new child profile accepted
* flush cached ticks during profile rotation
* ledger the rotation event (PQHD/PQSF)

---

## **5.9 Bootstrap Procedure (NORMATIVE)**

A client initializing the Epoch Clock for the first time MUST obtain and validate the Epoch Clock Profile through one or more of the following mechanisms:

### **5.9.1 Embedded Genesis Profile (Recommended)**

A client MAY embed the canonical v2.0 profile inside its installation package.
The embedded profile MUST:

* be byte-identical to the canonical JCS JSON
* include the correct `hash_pq`
* include the correct `sig_pq`
* match the `profile_ref` inscription
* satisfy all validation rules in §5.2 and §3.6

Clients MUST still independently re-fetch the inscribed profile to confirm integrity.

### **5.9.2 On-Chain Fetch (Required)**

Clients MUST fetch the profile using the Ordinals inscription referenced in `profile_ref`.

Validation requires:

1. Canonical JSON decoding
2. Recomputing `hash_pq` via SHAKE256-256 over the canonical profile body
3. Verifying `sig_pq` using the declared `pubkey_pq`
4. Confirming `p == "epoch-clock"`
5. Confirming `origin == "ordinal"`
6. Confirming `profile_ref` exactly matches the inscription ID

If any check fails → the profile MUST be rejected.

### **5.9.3 Mirror-Assisted Profile Retrieval (Optional)**

Mirrors MAY serve profile objects to help bootstrap.
Clients MUST NOT trust mirror-served profiles unless:

* the on-chain inscription has been fetched, and
* the mirror-served profile matches on-chain content bit-for-bit

Mirror-provided profiles MUST be treated as hints, never as authoritative.

### **5.9.4 Bootstrap Failure**

If the client cannot successfully validate the profile via embedded, on-chain, or mirror-assisted methods:

* The Epoch Clock MUST remain uninitialized.
* All dependent PQSF, PQHD, PQVL, and PQAI time-bound operations MUST fail closed.
* Clients MUST NOT attempt to construct synthetic replacement profiles or fallback to system time.  6. Profile Governance & Rotation (NORMATIVE)
6.1 Rotation Authority
The emergency_quorum field of the active Epoch Clock Profile defines the governance keys authorised to approve a new child profile.
A child profile inscription MUST include ML-DSA-65 signatures from a quorum of these governance keys.
Unless otherwise explicitly defined in the parent profile, the quorum threshold MUST be:
M = ceil(N / 2)
where N is the number of keys listed in emergency_quorum.
Clients MUST reject any child profile whose quorum signatures are missing, invalid, or insufficient to meet the threshold.
6.2 Rotation Triggers
A child profile MUST be issued when any of the following conditions occur:
* suspected or confirmed compromise of the profile signing key
* cryptographic downgrade or break affecting ML-DSA-65 or the classical alt key
* nearing expiry according to rotation_schedule_seconds
* hash function compromise affecting hash_pq
* governance-approved emergency conditions that require immediate profile rotation
6.3 Child Profile Requirements
A valid child profile MUST:
* include parent_profile_ref referencing the currently active profile
* follow all canonical encoding requirements in §3.6
* include quorum ML-DSA-65 signatures from governance keys
* recompute and include a valid hash_pq
* preserve the "epoch-clock" p field
* be inscribed as an independent Bitcoin Ordinal
Profiles that fail any of these requirements MUST be rejected.
6.4 Client Validation Rules
When a client encounters a candidate child profile, it MUST:
1. Fetch the profile from the ordinal inscription.
2. Validate canonical encoding.
3. Validate all ML-DSA-65 governance signatures.
4. Validate quorum threshold according to §6.1.
5. Recompute and validate hash_pq.
6. Validate parent_profile_ref lineage.
7. Validate that the profile satisfies all constraints defined in this specification.
If ANY validation step fails, the child profile MUST be rejected and the system MUST FAIL_CLOSED.
6.5 Promotion Rules
Once a child profile is fully validated:
* The client MUST promote it to the active profile.
* The pinned profile MUST update to the child profile.
* All cached ticks MUST be flushed.
* Mirror consensus MUST be re-evaluated under the new profile.
* A profile_rotation ledger event MUST be recorded.
* All future ticks MUST reference the new profile_ref.
No system MAY use ticks from a superseded profile beyond the normal reuse window.
6.6 Mirror Rotation Behaviour
Mirrors MUST:
* detect new child-profile inscriptions,
* validate lineage, signatures, and hash_pq,
* re-canonicalise the child profile,
* begin serving ticks under the new profile only after full validation,
* broadcast a deterministic rotation event.
If mirrors disagree on profile promotion, clients MUST treat this as mirror divergence and FAIL_CLOSED until consensus is restored.
6.7 Emergency Rotation
Under emergency-governance conditions:

* classical signatures MUST be ignored where they conflict with PQ signatures,
* only ML-DSA-65 signatures MAY be considered authoritative for profile rotation,
* the emergency quorum MAY rotate profile keys immediately,
* mirrors MUST update without delay once a valid rotated profile is available,
* clients MUST accept the rotated profile only after full signature and lineage validation.

EmergencyTicks MUST obey all normal tick-validation rules except those explicitly bypassed under emergency governance authority as defined in this section.


7. CONSENT AND POLICY ENFORCEMENT (NORMATIVE)
(To the extent the Epoch Clock participates in Consent/Policy through PQSF/PQHD.)
7.1 ConsentProof Structure
ConsentProof depends on EpochTicks for:
* tick_issued
* tick_expiry
* exporter_hash binding
* multisig participant enforcement
* replay protection
Epoch Clock provides the time boundary for ConsentProof validation.
7.2 Consent Validation
Consent MUST be rejected if:
* tick stale
* tick outside issued/expiry window
* mismatch between tick profile_ref and system profile
* tick canonical encoding invalid
* mirror divergence detected
7.3 Policy Enforcement (Policy Enforcer Integration)
PQHD Policy Enforcer requires:
valid_for_signing =
    valid_tick
    AND valid_consent
    AND valid_device
    AND valid_quorum
    AND valid_policy
    AND valid_ledger
Epoch Clock provides valid_tick.
7.4 Role & Quorum Enforcement (Indirect)
Although the Epoch Clock does not define roles, its ticks are required inputs for:
* quorum windows
* delay windows
* anomaly detection intervals
7.5 Out-of-Band Requirements
OOB flows (push confirm, secure UI, guardian confirmation) MUST:
* verify tick freshness
* reject expired tick windows
* record tick in ledger
7.6 Allowlist / Denylist Rules
Not applicable to the Epoch Clock directly; however, PQHD policies derived from it use tick windows for:
* destination approval lifetime
* anomaly scoring windows
7.7 Predicate Summary
The Epoch Clock enforces:
valid_tick = (
    signature_valid
    AND profile_ref_correct
    AND tick_fresh
    AND monotonic
    AND mirror_consensus
)
7.8 Consent & Policy Failure Modes
The Epoch Clock contributes:
* E_TICK_EXPIRED
* E_TICK_INVALID
* E_TICK_DIVERGENCE
* E_PROFILE_MISMATCH
* E_HASH_MISMATCH
All downstream systems MUST interpret these as immediate fail-closed.

8. LEDGER AND AUDIT (NORMATIVE)

The Epoch Clock does not maintain its own ledger; this section defines the rules for how dependent systems MUST record tick usage.

8.1 Ledger Structure and Object Model

PQSF, PQHD, PQVL, and PQAI MUST commit all tick-binding events into their local Merkle ledger exactly as defined in PQSF §7 and PQHD §16 (LEDGER RULES & MERKLE CONSTRUCTION). Every ledger entry involving time MUST include:

{
  "event":           tstr,
  "epoch_tick":      EpochTick,
  "tick_validated":  uint,
  "payload":         { * tstr => any },
  "signature":       bstr,
  "merkle_path":     [* bstr]
}

Tick inclusion is mandatory for:

* ConsentProof issuance or expiry
* Policy Enforcer enforcement
* PSBT signing
* device registration
* anomaly detection
* profile rotation
* recovery capsule creation or activation
* Stealth Mode entry or exit
* offline reuse windows
* identity vault events (PQHD Annex N — Credential Vault)
* AI alignment checkpoints (PQAI)
* OS drift detections (PQVL)

8.2 Merkle Construction

Ledger rules follow PQHD §16.2 (Merkle Construction):

* leaf_hash = SHAKE256(0x00 || canonical_entry)
* node_hash = SHAKE256(0x01 || left_hash || right_hash)

The Merkle tree MUST be deterministic. Ledger mismatch MUST halt all signing and state-changing operations.

8.3 Append Rules

Before a ledger entry involving a tick is appended, dependent systems MUST:

1. validate the tick
2. verify canonical encoding
3. validate the profile
4. validate mirror consensus
5. validate tick freshness
6. validate monotonicity
7. recompute the Merkle root

If ANY validation fails, the ledger MUST freeze.

8.4 Divergence Rules

If ledger roots across devices disagree:

* raise E_LEDGER_DIVERGENCE
* halt all signing
* halt tick reuse
* enter FAIL_CLOSED
* reconcile only under fresh ticks

8.5 Event Types

Time-bound ledger events include:

* "tick_validated"
* "tick_expired"
* "tick_reuse_violation"
* "profile_rotation"
* "profile_validation_failure"
* "stealth_mode_entered"
* "stealth_mode_exit"
* "offline_tick_cache_used"
* "emergency_tick_issued"
* "consent_issued"
* "consent_expired"
* "sign"
* "sign_denied"
* "recovery_attempt"
* "device_registration"

8.6 Cross-Device Reconciliation

PQHD multisig and PQVL systems require tick-aligned reconciliation:

1. exchange ledger roots
2. verify proofs
3. verify monotonic tick ordering
4. verify profile continuity
5. append reconciled entries
6. confirm Merkle root

If mismatch persists, the system MUST freeze.

8.7 Audit Bundles

Audit bundles MUST include:

{
  "ledger_root": bstr,
  "tick_range": [start_tick, end_tick],
  "entries": [* ledger_entry],
  "signature": bstr
}

8.8 Freeze Conditions

Ledger MUST freeze if:

* tick invalid
* tick reuse exceeded
* profile mismatch
* profile rotation incomplete
* mirror disagreement
* tick monotonicity violation
* encoding mismatch

Resume only after:

* fresh tick
* profile continuity validation
* device attestation
* ledger reconciliation


9. OPERATIONAL RULES (NORMATIVE)

9.1 Offline Mode
Offline clients rely on:
* cached tick
* strict ≤900s reuse
* canonical tick encoding
Offline clients MUST NOT:
* derive local/system time
* extend reuse window
* generate synthetic ticks
* adjust t values
9.2 Stealth Mode
Stealth Mode (PQHD §13) requires:
* no TLS
* no DNS
* STP-only transport
* strict tick reuse ≤900s
* no profile refresh
* tick expiry ⇒ freeze
* ledger local-only
Exit requires:
* ≥2 matching mirror ticks
* full profile lineage validation
* ledger reconciliation
* attestation renewal
9.3 Air-Gapped Operation
Air-gapped PQHD signers MUST:
* validate cached tick
* freeze on expiry
* refuse signing on stale ticks
* use QR/USB PSBT transfer
* require OOB approval if policy mandates
9.4 Network Partition Behaviour
During partitions:
* ticks cannot refresh
* reuse allowed ≤900s
* PQHD/PQAI/PQVL freeze after expiry
* ledger stays local
* profile cannot rotate
9.5 Recovery Mode
Recovery capsules MUST:
* embed the tick at creation
* refuse activation under stale tick conditions
* verify tick + profile_ref
* sync ticks before key or state reconstruction
9.6 Export / Import
Continuity Capsule exports MUST:
* include tick range
* bind capsule metadata to tick
* verify tick during import
* recompute ledger roots
9.7 Migration
Migration envelopes MAY include:
* validity windows
* tick_created
* tick_expiry
* policy snapshots
* ledger snapshots
9.8 Identity Operations
Expired ticks MUST block:
* identity retrieval
* vault access
* credential generation
9.9 AI Operations
PQAI MUST use ticks to:
* define alignment freshness
* timestamp behavioural fingerprints
* timestamp training deltas
* timestamp drift detections
* enforce session resets
Any drift event MUST include:
* tick
* profile_ref
* (optional) mirror ID

10. SECURITY CONSIDERATIONS (INFORMATIVE)

10.1 Cryptographic Security
Based on:
* ML-DSA-65 signatures
* SHAKE256 canonical hashing
* deterministic JSON/CBOR
* Bitcoin inscription anchoring
* multi-mirror consensus
* strict lineage
10.2 Transport Security
Tick delivery may use:
* PQSF hybrid TLS
* TLSE-EMP
* STP sovereign transport
10.3 Application Layer Security
Provides:
* deterministic consent windows
* replay-safe sessions
* tick-bound PSBT signing
* safe offline/Stealth Mode operation
10.4 Replay Protection
Replay is prevented by:
* signature-bound ticks
* monotonicity
* freshness window
* profile lineage
* deterministic encoding
10.5 Attack Surface Reduction
Eliminates:
* NTP poisoning
* DNS dependency
* local-clock rollback
* cloud time injection
* cross-session replay
10.6 OS/Runtime Integrity
PQVL probes timestamp:
* kernel/patch freshness
* integrity scans
* policy reload windows

11. QUANTUM THREAT MODEL & MITIGATIONS (INFORMATIVE)

11.1 Shor’s Algorithm Mitigation
ML-DSA-65 signatures protect:
* profile signatures
* tick signatures
* rotation signatures
11.2 Grover’s Algorithm Mitigation
SHAKE256-256 → quantum-safe hashing. hash_pq remains secure under quadratic speed-ups.
11.3 Forgery Mitigation
Mirror consensus + deterministic encoding make forgeries infeasible.
11.4 PQ KEM Attacks
ML-KEM optional; does not affect tick validation.
11.5 Hybrid Downgrade Attacks
Epoch Clock v2 forbids classical-only signature modes. All signatures MUST be PQ or PQ+classical.
11.6 Time Manipulation
Prevented by:
* signature enforcement
* monotonic validation
* lineage
* tick reuse limits
11.7 PQ-Only Emergency Mode

Under emergency-governance conditions where a PQ-only mode has been authorised:

* classical signatures MUST be ignored,
* only ML-DSA-65 signatures MAY be used for profile and tick validation,
* emergency quorum actions MAY rotate profile keys into a PQ-only configuration,
* mirrors MUST publish and serve the PQ-only profile without delay once fully validated,
* clients MUST record PQ-only profiles and transitions in their ledgers for auditability.

PQ-only emergency mode does not alter any other validation rules; all normal tick, profile, lineage, and mirror-consensus requirements continue to apply.


12. PRIVACY CONSIDERATIONS (INFORMATIVE)

12.1 User Sovereignty
Epoch Clock is:
* decentralised
* mirror-distributed
* non-cloud
* offline-capable
* P2P-friendly
Users are not dependent on any central authority for time.
12.2 Selective Disclosure
Ticks reveal no:
* user identity
* device identity
* location
* metadata
12.3 Device Privacy & Anti-Fingerprinting
Mirrors MUST NOT emit:
* device identifiers
* request-specific metadata
* per-client variation
12.4 Metadata Minimisation
Ticks carry only:
* time t
* profile_ref
* signature
Mirrors MUST NOT attach additional metadata.
12.5 No Cross-Domain Correlation
Ticks cannot be used for:
* tracking
* cross-service identification
* behavioural fingerprinting
12.6 Offline-First Privacy
Offline reuse:
* avoids remote lookup
* eliminates DNS dependency
* reduces observable behaviour
12.7 Policy & Consent Privacy
Tick-bound consent metadata remains local to PQSF/PQHD systems.
12.8 Ledger Privacy
Ledgers MUST NOT contain:
* PII
* device fingerprints
* IPs or hostnames

13. IMPROVEMENTS OVER EXISTING SYSTEMS (INFORMATIVE)

13.1 Weaknesses of Legacy Time
Legacy systems depend on:
* system clocks
* NTP
* DNS
* cloud time services
* unsigned timestamps
* miner-controlled blockchain timestamps
These produce:
* replay
* rollback
* session drift
* stale-session attack surfaces
13.2 Improvements Introduced
Epoch Clock v2 provides:
* cryptographically signed time
* deterministic monotonicity
* offline guarantees
* Stealth Mode safety
* replay resistance
* canonical encoding
* zero reliance on system clocks
13.3 Threats Eliminated
* NTP poisoning
* clock rollback
* downgrade attacks
* timestamp replay
* tick forgery
* cross-session replay
13.4 Threats Reduced
* mirror compromise
* connectivity loss
* profile forgery
13.5 Guarantees Introduced
Time becomes:
* provable
* verifiable
* global
* post-quantum
* immutable
* sovereign

### 13.6 Comparison Table

| Operational Aspect        | Traditional Air-Gapped Wallets               | PQHD Stealth Mode                                                 |
| :------------------------ | :------------------------------------------- | :---------------------------------------------------------------- |
| **Time Validation**       | Local system clock (untrusted, spoofable)    | **EpochTick** with strict ≤900-second reuse window                |
| **Transaction Freshness** | No guaranteed freshness or replay boundaries | Tick-enforced freshness; replay-impossible PSBT windows           |
| **Multi-Device Sync**     | Manual PSBT comparison; inconsistent state   | **STP** transport + deterministic Merkle ledger reconciliation    |
| **Policy Enforcement**    | Limited or absent; no temporal guarantees    | Full **ClockLock** semantics enforced offline                     |
| **Exit Safety**           | Minimal validation before reconnecting       | Requires fresh ticks, PQVL attestation, and ledger reconciliation |
| **Emergency Handling**    | None; no governance layer                    | Guardian-assisted recovery + tick-verified emergency rotation     |


14. DETAILED BACKWARDS COMPATIBILITY (INFORMATIVE)

14.1 Bitcoin / UTXO Compatibility
Epoch Clock uses:
* standard inscriptions
* witness data
* no consensus changes
* no miner cooperation required
14.2 Classical Compatibility
Dual-signature profile fields allow smooth migration from classical systems.
14.3 PQSF Compatibility
Epoch Clock v2 is compatible with PQSF v1.0.0:
* profile lineage
* canonical encoding
* tick semantics
* session rules
14.4 PQHD Compatibility
PQHD depends on:
* policy enforcement time
* key-derivation tick windows
* delayed recovery
* Stealth Mode rules
* Secure Import validation
14.5 PQVL Compatibility
PQVL drift logs MUST contain fresh ticks.
14.6 PQAI Compatibility
PQAI uses ticks to structure:
* drift boundaries
* session reset rules
* provenance chains
14.7 Offline / Air-Gapped Compatibility
Epoch Clock explicitly supports these deployments without system clock fallback.

15. IMPLEMENTATION NOTES (INFORMATIVE)

15.1 Developer Guidance
* validate canonical encoding before signature checks
* cache ticks respecting reuse windows
* reject synthetic timestamps
* enforce monotonicity
* pin the active profile
15.2 Integration Tips
* treat ticks as authoritative
* canonicalisation MUST be byte-stable
* freeze if freshness uncertain
15.3 Performance Considerations
SHAKE256 costs are trivial; tick verification is negligible.
15.4 Testing Notes
Test:
* stale ticks
* hash mismatches
* signature mismatches
* lineage transitions
* canonicalisation divergence
* mirror divergence
15.5 Reference Implementations
Rust, Python, Go, JS/WASM are viable reference implementations.
15.6 Recommended Libraries
* SHAKE256 (RustCrypto, libsodium, BoringSSL)
* ML-DSA-65
* JCS JSON
* deterministic CBOR
15.7 Edge Cases
* boundary reuse window expiry
* mirror disagreement
* rotation during Stealth Mode
* encoding mismatch due to Unicode
15.8 Performance & Scaling

16. REGISTRY / IDENTIFIER CONSIDERATIONS (OPTIONAL)

16.1 Algorithm Identifiers
* ML-DSA-65
* ECDSA-P256 (optional fallback)
* shake-256/256:<hex>
16.2 Error Code Registry
Prefixes:
* E_TICK_*
* E_PROFILE_*
* E_MIRROR_*
* E_CANONICAL_*
* E_SIG_*
* E_HASH_*
16.3 Domain Strings
* "EpochClock-Profile-v2"
* "EpochClock-Tick-v2"

17. CONFORMANCE REQUIREMENTS (NORMATIVE)

17.1 Conformance Levels
MVP (L1) Full (L2) High-Assurance (L3)

17.2 MUST / SHOULD / MAY Rules
* MUST validate signature
* MUST validate hash_pq
* MUST enforce reuse window
* MUST reject synthetic ticks
* SHOULD implement caching
* MAY implement ML-KEM for encrypted mirror transport
17.3 Test Vectors
Tick example:
{
  "t": 1730000000,
  "profile_ref": "ordinal:<txid:iN>",
  "alg": "ML-DSA-65",
  "sig": "<signature>"
}
Full test vector suite under:
/test-vectors/epoch-clock/
17.4 Interoperability Requirements
* MUST accept JCS JSON
* MUST reject non-canonical JSON
* MUST support deterministic CBOR
* MUST agree on hash_pq bit-for-bit
* mirrors MUST converge under majority
17.5 Certification Process
Future certification MAY include:
* deterministic conformance checks
* lineage validation
* divergence tests
* tick replay tests
* Stealth Mode rule tests

# **18. APPENDICES (INFORMATIVE)**

## **A. Example Workflows**

### Basic Tick Fetch

1. Fetch from mirror A
2. Fetch from mirror B
3. Compare
4. Validate signature
5. Accept

### PQHD Signing

* tick → consent → policy → attestation → sign

### PQSF Transport

* hybrid TLS handshake
* exporter_hash binding
* tick-bound session

---

## **B. Reference Epoch Clock Profile (Informative)**

The following JSON object is the canonical Epoch Clock v2.0 profile:

```json
{
  "alg_alt": "ECDSA-P256",
  "alg_pq": "ML-DSA-65",
  "duration_seconds": 31556952000,
  "emergency_quorum": [
    "kid:gov-A:bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw",
    "kid:gov-B:bc1q52gveypmv6qc4kpqtmxhxuhtzv0ap5e5knk75r",
    "kid:gov-C:bc1qgmuaxsymw4w7l9sl98senkhay8yy0fc3vpsulk"
  ],
  "format": "unix_seconds",
  "hash_pq": "shake-256/256:c9756c5646201220b10660a6ecc72dacede6ce7bd51b199500066783eafa47fd458c1d74f2e679f812ce4466ae01320449ece0170783b3bb1be09cade8ad061a",
  "origin": "ordinal",
  "p": "epoch-clock",
  "profile_ref": "ordinal:<txid:iN>",
  "pubkey_alt_spki_der_b64u": "<b64u-SPKI>",
  "pubkey_pq": "Srs7SyoTaf1HhZt9ft2RjSIaMO15E16n2WAAvBpEARqRwAwrwoNsT8faak7co4jXKpINxS3IqOkMp0XeMaj5QHgatOGxi0QIKfnT_cUEGBNF_Lf12JWyWT-ZhNww-lWxmCUY8UakYx6dE0Egc7-MNkBvZfU6NcrwUOKNwpxR7MuAxjSZZ6dUElteUoZm2YTIrsRCGTFSq8FnqVxcNDzb_d-FiKULdMgZDsqjpNwTfPtJMGmUL-b_eqoIfLLziCC5_LO6kJhQvz9C-SZj00kV-MM00HgZvroyYknhXl5ByYX6F0_Fnj1wzkwh_uT9TtUXA-9JpaC4v9lOAvwMBirJ7SXPAqs_kCjkLM5sodmAuq_-dIlUkDDrq8a5RLLs3H2H00RkF9H6BkTjSkPRv8-FMyemlzFAVhNLm7bNFcA-EROpVfyiPYc8-BH4ITaF-_eyb4J3wtBh_Hn4hUcSCRRX091zu8ZRzYbwuH9A5ZGzE1KnP4KSqTbKcx9pQwc81pEvykrCMhVPDjbputrWG-Z90i5yBmZ5S7g4e-ZFNuUw9W2OvtcCrjtVayQxwRXOxoffHKiOaW-mboXmr729ogavMgHIcfd411mtnnK9K1F8j3l6XVPFq_GGVwQ464eaUbI2mVxksfOlVwABb8erzkyCWV6wLFbETpf7PegldwEi7Y_qd7DFAjwkBUy9NaVJ7aOFxt8M-3k81iSVCqEQhbGePcoVVr54VJ_6sFcqLLPaaZjHA3EguSWnUIMpWcZo4HoF5FlbWmQsl7_PEr5nf-Jho913StVIDDwgpbGvwSdAWsnyRE8mUfceCswgylEN8egnA4985oTA1DLKGNtFKZiTihMrF0Sgv4z_-wPWqt8k_8Xp-_WEIJJyFHVY_p60p_LYQulShMK-luCqW9DDTIhV6OF_6T2yJue_2uewT43FWU7aXVN89vsB551c_sjlqVbqSvUsWL769juXAFCWXaOyhSVd5k-XnCwWlrw9OmsmZqvoshQ5dFysqeFbukVm_D2nC2m7BtazUGRhppQ_z_hc_eeoTX5GazUlenN3FGxypMNHtFKmdK7jGJQwHmZtdW97Hdr-WHdfiMr7omw3ImjpbrCgv20DqXi6Z8-JfBoaxtR5tTQ4dmefxu6dsTG1G-mpiuZqC8lfl2iZAnZwPM6vzjw_nJS7j5L0ZaOuSsULC1rM4j9orL9eN95ANJFK9UVTxUiVBgcvJnYO9lWPs_OYXowo48WNOiDcxMysmWhdDPMGc_apPz4-7IytC9lIq3KAYel9T-bm0RitoW7VNF7j4vYwL3kEQ0M4YF2GQh6oEz_Rd58NlJiw_idxNpB0-nGZZSw1wCOMGmZX6SZsk93vqR3w4Rev0kMSrJR95hU0sdSicZ_DYPLQ2etIxya5H4u6KNE7nTPQXic4d-hw0_6L6zpBjfDTcVK3ztgN5OC4HVOWbt1oeYzeDdHBv1WEDCmFioBbj1o8bcySqB97aq0UJQPnOlcipT87_QlUNZhr5hCp-S0N9jU_Sd-I8Z4tihHkvP_UW6wLZ66feGOD1gQuTiQ6yk2eAt0oKPPXH7XiLgxqsLmPIQ-3VMGKPvquo7L0Vl-Zq6I5lXEYnrGKn3XeyN00qCg1R8Xe8naPlpWujwHPv4twk_q6NlUHbCYQxiyFZO3wCEqbUWc3iwW5Pj376eCnrxBNcuhPWhLq39veTtxzSWTS0TsguPly-K0FzI5MDECDhXG5xa20MSluI9XeDTPe8Mk_O7zkIA5RC4uj1AbcUFrfiRErhA_hCpddEHOuUNnQZTtJlS3vasalcnQZwTXbX8BlmErgJ4YfvK5vLB9CKf20ZbY-OcC-iblMO6qPqmGFlPTsY3hFuhyGSWJNkZllG3n2noBBpVR73yasqDGwK-Dno1MhIcFBRJ5H0rwwczoenMD-ojgTN6vRfxZDNVGzI-ab-TnJXf5JMmC2eIf8kM9OyeYnr3PE5HGWmEBfER9py_J5qhRS_2sJaUFCM-YUDdOGTD29RVZAGGsqMLGh1YSGQJqM8qQweaqR15_zPi3VcRToriKv2v61G_FmiLRUigGg69j8IrHrICn4OFo2cdcXLTG0SZ8RW-u5cPbF57WsqjYaFjn1TOiTGcHf0BpanXWFVHKW3ZYShivppRF4erqiDddXNPc-fJv7r7qEjQGvlFpDWhTSBt8f3cD7nnUW3THtnM0V1-EE9ycvImlQK9TjTj7_Mol1n-XrBLpX-c5NweYWxFbTRljMF6tf3W5dOqQUM3P682ZLiVDtsmMdYTIsgX_Uh2BecIm_YRpFw6dFIy7YBrr0x-z00cELb2_G2ST6ZFPR2zm5Dy7-wLs2yTdRisUop_NfKj9WKb5eJzp6U4kjmZqDxnldbypr-rj_b2Q43d4o-sxluws4YP7Icj5JsWpRC6tZtNbqWusigGsELXIaeBMJPxekFt26wuR0nY47BOIKAeWrQUfoU_LJROqzhW_ix0DxOqbCG5QFaDfB_mxKmWB-lxhhOZqS17adhRnU19Vnkmi2RFZFShjY3Kign0fnyhLBrnglDMWEGPKrnyUOLvdrPDqz-rLGwL-_97Y81z6Oypd6fyQJdFA",
  "rotation_schedule_seconds": 15552000,
  "sig_pq": "t_7a48znEG-MZfPYBrGyeBByq9rIIdpJuZTUld6N2t1lFUeWx6PznVb5mXSh0wVieswPI60sFlnLm0JEYGSTfBC-wXXMy0eb8IQqPa655Uj2AV6Yy5BM6se_w45TFIIITyBHkRUM580LM5IXl4RCyHkAanRtcXEadHrkJ_oq00WChcUljNbBe8BKgzIw33CNF4CtQk-m7v734WEmLp7QK_kZ9BVgFjly5EW8GhkM6jTbU0KkH5Bn373g-xYZwkC75p2vbcETYNy8bja5XNSwu8dKD15tkGC-gQ9hRRWxA3HqLk6FLB0dJqZr5AjyVxMuUMlWLT5rOyHhYQZWetONmx60YLqJ8NF-RfY9_VbzkUeCG7sJHa8PdEOXRHlHKqUw64e7jvWZxLvda8WUzVXqoqD3DinvyBSNdWyuNMMOWLmZkwagjqjzZHvtapq3m2VFVW8Idrjd0P-22jCVczRWgD0tZ_UBIi2RYztPxsHvY7rHmny3SN9XYGgmTDIYiwDMwIXND9kGGP9UgJiskdkwk4ItvBGBR7QdlZCyLpurHB3uph8WRaanJpBbqjBtw_5ID5afVLt0SLIZKUCJQqj-OCKq_TnCx_tgDhG-env5hyQCDfFNvTij5IOYDlWwe8EhTSbR1B3lfq1PljkCtpYURQ8KjcUR3gIiYZjwxl-JjWZ393uS2PqbsmdoCf8rq8pRSfOvyumVvaI7GdZbdtoHTRzK400ueIqpqIUwn4X7ixX_7o5cQ9ECcSrWYIyzsGi5xj2tYcdmZpWVhP2YQx-EQmQHGgI6ZwUZb4-yYhPi9KYMTZscD5MtB5hwLpfqF2mCM8kgNXBM71dPdwACKywjudNjexQaNiKOhnPIiIVKnjifD6blUiDVs_Z18wfuVwW8pDPN-8KnBdTKik377sjeOKqmdd9uxiE6nDaLV0BplL5a1PeYXLrccbbQPtk8H39nlINtnKFFp5xbqoqk3zW6Hi8q9HEmit0zoHkCuPtD3vFsOhZaE83ur8WQWXDfy2NO6k7Ef1dtPmN2RvWdDu2V76Tn4ar_APW6ZMPQyh2mrsGJkoXwbTLXOQUT4uC8_YL847gU7LliGvzBbhr3fLknB-IzdS8fEh5yuwfs0vGVTy9NRPJ5fxWVrMkLX6KQ4Icr-T2khgvPHXiQ2c4CgJW7Rcvb6gDtxCEqula_vFnX8n8G2ur40jwQ-f0JibFmsUJiiW9-_kBDl9-O_zd2XkERJ4PWpU8i87XGOSHtU00XlimVG-3dTBAyoFa2_hVn6jyKq3x9_gNXU6tWDoVghDDJPFApVdGqFxSgaMAcJ9L7SF2lIbbK0SRvHb0Js_ykMCp2aPMRqOY_8t9lsvRdyTyEJPQvvJrEqEDhIBBitnq-2J3IujPa0Z2zj7ZHpQeu6JSJyAoSF6NpBiWJsQfHlKW4a5q03yaY7Twyc6M7WT3ndVyyU-iCU1H0KZPmlREFMl5ChMahFWZU4aZTANUU73vvpwXtldtZzJT_nfyDfaFpYNrYbsIK434EGEmNHRJoUnCMMW20Rvdoe6Ws03up3H_bN2XzTpAtmoYbAbhMufTobcdjB3B4IMhm1-QkfrHoCdjJAa2Dt7CzWWyGoMIwGBcnLpTbomSqzK_0hywqOFlCFo2aZVs7PaiDYFT2YMgEzco3IBlcsdccZwnHx3czxkDVbTY6I9e7eW4ztmY4vh_QGLkThIb2GoAXz3uPySiMYa8LaRuLqDm9aURjfGjXnJN5VTQ9XmufFqGNeTOUNetdrblUXYAXLoragg7uK-pIihAVcbQaydwIDI3ska3pjPLFYGNr0M7a2YV6MthDUNvm3OY1lw44RF0ui7sbyAxGSlqZ4bd3jR9cZ_JXQk4KVvzUTuhcMeJ_GXn_AGg6y596NLu45E2zu8byQZFTgHU8hu6Xx80bn0eaJtpJnq1ratGNRGRv1kfPJS7s0HXK-3JMPMRx8cB_Zz2II1t8S0zY9dFDcnsEbSWV4J1MFcNAVu93dsABoqjgAMbHdTxL7d7GWABdUDDiz9HBItrbDSGUba_FrA8ulVrOxGhZZRJuYmjiWLYQuhxnz9VPmzMZyLehsVS_Vg8v1YsJbKWJU0jdNtex4pRGQj6wT7GFWqZM5DWyVdfFBNiQFTyJ6cPLXcRErbgxnD4e1hj2XAGGiDnFa0FW5X4nZNsdIjVS9CEugjHh6Uto9ju4bcc96QYsPIxhS-kmjX4nLBXA2F5ytfCiSreO5Q24NeJ37bu2Qv2SwHJRBulUAMctp_LAxQKTEKPX9hka_5z1L8xwo8IuV9W6iY863or6N1GAmTHMLgtZw4O9oGk_MOAEYFS9_BLRSFB7e8T15WjwB5hcnM6KBn-d-YSKayvES4BdJW87G2JSiMPgNC7nN8Nnr6PrT0Wceu5ZE9t2mQZHIJVkNI_ocX6lSZ9DWAS9BbdjozwfjZwPo8Lse4bz8R9McOyw1Cbyd-rfNMm-Vyb96p3joNXBlBKFOGMfF16hhQWCxMZ0Q7Ph9cLbui3-ODxua5kLA-hnKyurswjfuViCA2VhDg1Md4YBnKuEkW7UPW1Ie5hUoPhCGBJWn00tWGVaKxy3wDJfQb_fJieBpqvRx9E5jtcmFgSC0FRiocneOgulUD9Q4dqvGeOwkNcBbBG34WGTJkZhmZi_m5RvmBspVoYDmiW6P75mu1EhQELu3eAOJ9t5cZsou0IgrQG0dEUqIWOHJR6MjDFXte6V4MgCIUx-VGwRgmLUKKTWD1HtPwgEbN1Y8a6IzYCrprsrTHNTwyv1Ow2umQrsiVXJcpg-FoSgDbMnf2IRr529peoXFNOWW7KZY-hbLJm_CgfWmkDqHqUmpEF308H0owvksYjPMZXUJEJU2WNYnkwgKx6Ynku694Y5ivsfoy_3TGo5rgD-F08sb57MzhP7SBfE_A0_fTRrhIHeyqUn6Q1MngoYi49AOw6Cyw_hFkzh5RA1FkOSuwWUaAbKIvt9OYgqqO_xFCnY-n0gSsAXLj16lqNTQfmscl3ynxogTEeB4lfmLw4fe4MAB6JkhXhEGlz6ZUVm6Xfeg-MSLvox9aLBeG12BJp23PE6bXRWesMyU0vYJ3-vzRPKfvEfV0z4S8aws1Ap4DieyMR65Whsh2djIG-RUBIyeEeCdqs9OUbnq9Qy8axJCi6Ro97SxNNx4WVgZiFK5fyWcudN1n23u40eVTAZILPkKWMb4af26pIM9C6B2d4VOHuFx2w-5AwaCxY4SdVc3oijSXESpgIH4AyIUHotD5Z7dtc05L3znlN2LMfUNNRYx1BRHX8uXAEXy8aCb1K-JfHkVBO-6Rj9yMvP9Bl9sJb69qBUH0xyMj3ESCILHKuQ1BkCJL91zLXRPAes_U6Ctfd2xuleFgRZ4XS59L2oANuTXWctR2duu8Whgz07PIZCILVjO0EIgv_NZD72k7L_fa-d9O9Q-b5rNUwXFd8c9C_2K7gOM2Ry9nEhRE3dvUvXGrydCTUKgdI1bhgFMqg0Phe2OKc1LxAnxA1t_MxJC0arFBnQk7sY5ZO0Dm1GfaDut_4lEyT6_TKgWDNMZj0bqfsMXu1CgEPBLFz-hWd7Hna4TP8A2PuTTJc_8yRmq15MrdeMFeFNFoZW9AjOKAWwK7D9ojRWfLU1O1Xq4YkNFNzNG3bqXAamF1D-N2bMR-8TVqH3XyyRnXThzo1-D2j5N7pbPjrgyStRp6-jcD69eDmOy9c5xTdZ1FfY_at1ApcCG5-Lc_kyCeS4OCVZ2BrpM5HRCDMrF1SevYJ7KCBvSUbC67YfRtepD4Cj1UXc9VCDeKCN8LKBGwVGAy6ue3j05avg_WOuSdy2vNpns3L81GID8tn7CJO2ZkoV7fkTEu3Amv_kjtP09-gRGmuBKLgaKA_-PLr_oZCExcJNvTEzTPuguETJm1dECiZttHwEi9IvAGAwvTSkIEcPPlx_pLRv5RroHQsyrMPV2_Rhj2AC_wk5qQRmalffnbZbya4PDEnPbY6WM4kXxA7z2aNistzDQJ5bFiR3UEUAz_bm92cE4WISnr0YCjeULnZ3R11IvMj-HZ9SgS-lJfINeWBC_7IP1keUf-jY5rTxtJqlXTS15VQU296CELmMqDApar5wk3eruDqtiiQB0XJC_9YSTMKF9zQWt8WNye2mXpWupbAgFEcxMPQZgjVrWVJc5ZAemQIhwF9uJAc5gZTD8ByfOxDdyTpbRN9gNN-u81jwDy1P7V5LMnwC62lbYsOxEpIAs-7eg_sYqPvux1wxMp0r0zScI0lGvD6rnzZDJ630P1TVk5YU_zpFUu3VDqgGKwgKGR9CZ4ySvcXZ5wEaHHF6pdPlHyOUweQRGDJJ8QMUMktddXvB7DKIn6rW9gAAAAAAAAAAAAAMFBkeJy0",
  "start_unix": 0,
  "v": "2"
}
```

---

## **C. Test Vectors**

Developers should test:

* canonical JSON variations
* CBOR minimal integer encodings
* signature verification failures

---

## **D. OS-Specific Notes**

Linux recommended for mirror nodes due to:

* stable networking
* strong crypto libraries
* good process isolation

---

## **E. Secure Import Examples (PQHD Integration)**

Not defined here, but ticks are required for hybrid signature windows.

---

## **F. AI Drift Examples**

PQAI drift logs include:

```
{
  "event": "pqai_drift_detected",
  "tick": <tick>,
  "model_hash": <hash>,
  ...
}
```

---

## **G. Threat Comparison**

Tick forgery is defeated by:

* ML-DSA
* deterministic encoding
* mirror consensus
* profile lineage



## **Acknowledgements (Informative)**

This specification acknowledges the foundational contributions of:

Peter Shor, whose algorithm motivates the use of post-quantum signatures for secure time attestation.

Ralph Merkle, for introducing Merkle trees, which influence deterministic lineage and proof models.

Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche, inventors of Keccak, from which the SHAKE-family hash functions used in tick and profile validation are derived.

Pieter Wuille, for his work in deterministic Bitcoin structures and commitment formats that inform inscription-based data anchoring.

These contributions provide structural and cryptographic foundations essential to the Epoch Clock’s deterministic, sovereign time model.

---

If you find this work useful and want to support it, you can do so here:
bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw