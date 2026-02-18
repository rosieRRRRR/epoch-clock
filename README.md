# Epoch Clock -- Cryptographic Time Authority

* **Specification Version:** 2.1.0
* **Status:** STABLE / INSCRIBED
* **Canonical v2 Profile:** `ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0`
* **v3 Profile:** Pending inscription (schema defined in §4.1.2A)
* **Date:** 2026
* **Author:** rosiea
* **Contact:** [PQRosie@proton.me](mailto:PQRosie@proton.me)
* **Licence:** Apache License 2.0 — Copyright 2026 rosiea
* **PQ Ecosystem:** CORE — The PQ Ecosystem is a post-quantum security framework built on deterministic enforcement, fail-closed semantics, and refusal-driven authority. Bitcoin is the reference deployment. It is not the scope.

---

## Summary

Epoch Clock provides a cryptographically verifiable source of time for security-critical decisions.

It issues signed time ticks and profiles that allow systems to reason about freshness, ordering, and expiry without relying on local system clocks.

Epoch Clock does not enforce policy. Time-based decisions are made by consuming systems, primarily PQSEC.

**Note:** The v3.0.0 schema is defined in §4.1.2A but is not yet inscribed.

---

## Index

1. [Purpose and Scope](#1-purpose-and-scope-normative)
   - [1.1 Purpose](#11-purpose)
   - [1.2 Scope](#12-scope)
   - [1.2A Canonical Profile Reference](#12a-canonical-profile-reference-normative)
   - [1.2B Trustless Temporal Authority](#12b-trustless-temporal-authority-normative)
   - [1.2C What This Specification Covers](#12c-what-this-specification-covers-informative)
   - [1.3 Relationship to PQSF and PQSEC](#13-relationship-to-pqsf-and-pqsec)
   - [1.4 Relationship to PQHD](#14-relationship-to-pqhd-normative)
   - [1.4A Authority Anchor Pattern](#14a-authority-anchor-pattern-normative-informative)
   - [1.4B Consuming Protocols](#14b-consuming-protocols-normative)
   - [1.5 Non-Goals](#15-non-goals)
   - [1.6 Deployment Environments](#16-deployment-environments)
   - [1.7 Terminology and Definitions](#17-terminology-and-definitions)
   - [1.8 Compatibility With Existing Standards](#18-compatibility-with-existing-standards)
   - [1.9 Backwards Compatibility](#19-backwards-compatibility)
   - [1.10 Threat Model](#110-threat-model-high-level)
2. [Architecture Overview](#2-architecture-overview-normative)
   - [2.1 Architecture Layers](#21-architecture-layers)
   - [2.2 Components](#22-components)
   - [2.3 Data Flow Overview](#23-data-flow-overview)
   - [2.4 Actor Roles](#24-actor-roles)
   - [2.5 Security Model Overview](#25-security-model-overview)
   - [2.6 Trust Model](#26-trust-model)
   - [2.6A Meaning of "Decentralised"](#26a-meaning-of-decentralised-normative)
   - [2.7 Protocol Overview](#27-protocol-overview)
   - [2.8 Dependencies](#28-dependencies)
   - [2.9 Sovereign Deployment](#29-sovereign-deployment)
3. [Cryptographic Primitives](#3-cryptographic-primitives-normative)
   - [3.1 Signature Algorithms](#31-signature-algorithms)
   - [3.2 KEM Algorithms](#32-kem-algorithms)
   - [3.3 Hash Functions](#33-hash-functions)
     - [3.3.1 Hash Output Length](#331-hash-output-length-normative)
   - [3.4 Randomness Requirements](#34-randomness-requirements)
   - [3.5 Domain Separation](#35-domain-separation)
   - [3.6 Canonical Encoding Requirements](#36-canonical-encoding-requirements)
     - [3.6.1 Bitcoin Inscription Format](#361-bitcoin-inscription-format-normative)
   - [3.7 Cryptographic Failure Modes](#37-cryptographic-failure-modes)
4. [Core Protocol Mechanics](#4-core-protocol-mechanics-normative)
   - [4.1 Data Structures](#41-data-structures-cddl-json)
     - [4.1.1 EpochTick v2](#411-epochtick-authoritative)
     - [4.1.1A Tick v2 Signing Preimage](#411a-tick-v2-signing-preimage-normative)
     - [4.1.2 Profile v2](#412-epoch-clock-profile-v2-authoritative)
     - [4.1.2-1 Profile v2 Hash and Signature Preimage](#412-1-profile-v2-hash-and-signature-preimage-normative)
     - [4.1.2A Profile v3](#412a-epoch-clock-profile-v3-authoritative)
     - [4.1.2A.1 Canonical Sub-Object Identifiers](#412a1-canonical-sub-object-identifiers-normative)
     - [4.1.2A.2 Profile Signature Preimage](#412a2-profile-signature-preimage-normative)
     - [4.1.2A.3 Example v3 Profile Template](#412a3-example-v3-profile-template-informative)
     - [4.1.2B EpochTick v3](#412b-epochtick-v3-multi-signature)
     - [4.1.2B.1 Tick Signing Preimage](#412b1-tick-signing-preimage-normative)
     - [4.1.2B.2 Tick Signature Entry Format](#412b2-tick-signature-entry-format-normative)
     - [4.1.2B.3 Tick v3 Validation](#412b3-tick-v3-validation-normative)
     - [4.1.2B.4 Example v3 Tick Template](#412b4-example-v3-tick-template-informative)
     - [4.1.2C Genesis Profile Defaults](#412c-genesis-profile-defaults-normative)
     - [4.1.2D Version Detection](#412d-version-detection-normative)
     - [4.1.3 Parent–Child Profile Lineage](#413-parentchild-profile-lineage-pqsf-aligned)
     - [4.1.4 MirrorConsensusPacket](#414-mirrorconsensuspacket)
     - [4.1.5 Tick Time Base](#415-tick-time-base-normative)
   - [4.2 State Machines](#42-state-machines--enforcement-pipelines)
   - [4.3 Validation Rules](#43-validation-rules-authoritative)
   - [4.4 Operational Workflows](#44-operational-workflows)
   - [4.4A Tick Fetch and Caching Discipline](#44a-tick-fetch-and-caching-discipline-normative)
   - [4.5 Mirror Discovery](#45-mirror-discovery-normative)
   - [4.6 Mirror API](#46-mirror-api-normative)
   - [4.7 Mirror Identity and Trust Model](#47-mirror-identity-and-trust-model-normative)
   - [4.8 Error Handling & Failure Codes](#48-error-handling--failure-codes)
   - [4.9 Error Recovery Procedures](#49-error-recovery-procedures-normative)
   - [4.10 Transport Binding & Session Rules](#410-transport-binding--session-rules-pqsf-integration)
5. [Time / Clock / Profile Integration](#5-time--clock--profile-integration-normative)
   - [5.1 Overview](#51-overview)
   - [5.2 Profile Structure](#52-profile-structure)
   - [5.3 Tick Structure](#53-tick-structure)
     - [5.3.1 Tick v2](#531-tick-v2-single-signature)
     - [5.3.2 Tick v3](#532-tick-v3-multi-signature)
   - [5.4 Tick Validation Rules](#54-tick-validation-rules)
     - [5.4.1 Common Validation](#541-common-validation-v2-and-v3)
     - [5.4.2 v2 Tick Signature Validation](#542-v2-tick-signature-validation)
     - [5.4.3 v3 Tick Signature Validation](#543-v3-tick-signature-validation)
     - [5.4.4 Version Detection](#544-version-detection)
   - [5.5 Tick Reuse Rules](#55-tick-reuse-rules-authoritative)
   - [5.6 Mirror Reconciliation](#56-mirror-reconciliation-authoritative)
   - [5.7 Replay Resistance](#57-replay-resistance)
   - [5.8 Profile Pinning & Rotation](#58-profile-pinning--rotation)
   - [5.9 Bootstrap Procedure](#59-bootstrap-procedure-normative)
6. [Profile Governance & Rotation](#6-profile-governance--rotation-normative)
   - [6.1 Rotation Authority](#61-rotation-authority)
   - [6.2 Rotation Triggers](#62-rotation-triggers)
   - [6.3 Child Profile Requirements](#63-child-profile-requirements)
   - [6.4 Client Validation Rules](#64-client-validation-rules)
   - [6.5 Promotion Rules](#65-promotion-rules)
   - [6.6 Mirror Rotation Behaviour](#66-mirror-rotation-behaviour)
   - [6.7 Emergency Rotation](#67-emergency-rotation)
   - [6.8 Issuer Key Compromise Response](#68-issuer-key-compromise-response-normative)
7. [Consent and Policy Enforcement](#7-consent-and-policy-enforcement-normative)
8. [Ledger and Audit](#8-ledger-and-audit-normative)
9. [Operational Rules](#9-operational-rules-normative)
   - [9A. Offline Degradation Semantics](#9a-offline-degradation-semantics-normative)
     - [9A.1 Purpose](#9a1-purpose)
     - [9A.2 Staleness Model](#9a2-staleness-model)
     - [9A.3 Freshness States](#9a3-freshness-states)
     - [Default Staleness Thresholds (Normative)](#default-staleness-thresholds-normative)
     - [9A.4 No-Tick Mode (Offline)](#9a4-no-tick-mode-offline)
     - [9A.5 Reconnection Semantics](#9a5-reconnection-semantics)
     - [9A.6 Cross-Specification Alignment](#9a6-cross-specification-alignment)
     - [9A.7 Authority Boundary](#9a7-authority-boundary)
10. [Security Considerations](#10-security-considerations-informative)
11. [Quantum Threat Model & Mitigations](#11-quantum-threat-model--mitigations-informative)
12. [Privacy Considerations](#12-privacy-considerations-informative)
13. [Improvements Over Existing Systems](#13-improvements-over-existing-systems-informative)
14. [Detailed Backwards Compatibility](#14-detailed-backwards-compatibility-informative)
15. [Implementation Notes](#15-implementation-notes-informative)
16. [Registry / Identifier Considerations](#16-registry--identifier-considerations-optional)
17. [Conformance Requirements](#17-conformance-requirements-normative)

**Appendices (Informative)**

- [A. Example Workflows](#a-example-workflows)
- [B. Reference Epoch Clock Profile](#b-reference-epoch-clock-profile-informative)
- [C. Test Vectors](#c-test-vectors)
- [D. OS-Specific Notes](#d-os-specific-notes)
- [E. Secure Import Examples](#e-secure-import-examples-pqhd-integration)
- [F. AI Drift Examples](#f-ai-drift-examples)
- [G. Threat Comparison](#g-threat-comparison)

**Annexes**

- [Annex H — Canonical Profile Anchor and Inspection Mirrors](#annex-h--canonical-profile-anchor-and-inspection-mirrors)
- [Annex I — Time Binding](#annex-i--time-binding-informative)

[Changelog](#changelog)

---

# **ABSTRACT**

The Epoch Clock defines a deterministic, decentralised, cryptographically signed time authority designed for systems that require verifiable, replay-resistant, and sovereignty-preserving temporal semantics. It provides ML-DSA-65–signed EpochTicks anchored to a canonical Bitcoin inscription, allowing clients to validate time without relying on system clocks, NTP, DNS, cloud services, or centralised providers. All profile and tick objects use JCS Canonical JSON to ensure cross-implementation consistency.

EpochTicks integrate with PQSF and dependent specifications by supplying a verifiable temporal reference for consent windows, policy enforcement, transport binding, replay prevention, and session boundaries. The Epoch Clock also defines deterministic profile-lineage rules, mirror-reconciliation behaviour, offline constraints, and Stealth Mode operation. Runtime-integrity subsystems (consumed via PQSEC predicates) may contribute additional validity signals, but the Epoch Clock remains independently verifiable using only on-chain profile data and deterministic mirror rules.

---

# **PROBLEM STATEMENT**

Distributed systems commonly assume that local clocks, NTP infrastructure, DNS-based services, or cloud time providers can be trusted to provide accurate temporal information. These assumptions introduce failure modes: clocks drift or can be altered, NTP and DNS are susceptible to spoofing or poisoning, cloud services introduce centralisation and monitoring risks, and application-layer timestamps lack verifiable provenance. Replay, rollback, stale timestamps, and cross-session inconsistencies become feasible in these models.

Applications that require deterministic authorisation—such as replay protection, policy enforcement, consent-expiry windows, multi-device coordination, recovery delays, or AI-alignment freshness—cannot rely on ambient or centralised time sources. Time must be independently verifiable, tamper-evident, privacy-preserving, and reproducible across devices, including offline or partitioned environments.

The Epoch Clock addresses these issues by anchoring a canonical profile to Bitcoin, signing all ticks with post-quantum signatures, enforcing canonical encoding, and defining deterministic validation, lineage, and reconciliation rules. This enables systems to rely on verifiable time without trusting any single mirror, local clock, or external infrastructure. Runtime attestation subsystems (consumed via PQSEC predicates) may supply runtime-validity data, but time itself remains independently verifiable.

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

### **Authority Model Clarification (Normative)**

Epoch Clock does not enforce time at the Bitcoin consensus or Script level. Instead, it provides a cryptographically verifiable temporal reference that is consumed by wallets, signers, and custody systems. All enforcement occurs through refusal semantics: a wallet or signer MUST refuse to authorise operations when EpochTick validation fails. No Bitcoin Script opcode, miner behaviour, or mempool property is relied upon for enforcement.


## **1.2 Scope**

This specification defines:

* the Epoch Clock Profile structure and inscription model
* the EpochTick structure and validation rules
* signature, hashing, and canonical-encoding requirements
* mirror operation, consensus, and reconciliation
* profile lineage, rotation, and emergency governance
* offline, Stealth Mode, and air-gapped operation
* integration boundaries with PQSF and consuming specifications (including PQSEC and PQHD)
* security, privacy, and sovereignty requirements

**Epoch Clock produces signed time artefacts only.**

This specification does **not** define:

* Bitcoin consensus or transaction formats
* consumer-side enforcement semantics (freshness, monotonicity, acceptance, refusal)
* application-level timing semantics or business logic
* wallet custody rules (PQHD)
* runtime-integrity measurement (via PQSEC predicates)
* AI alignment or drift analysis (PQAI)

All consumer-side validation logic, freshness enforcement, refusal semantics, freeze semantics, and enforcement behaviour are defined exclusively by PQSEC and consuming specifications.

External attestation subsystems (consumed via PQSEC predicates) may satisfy runtime-validity predicates, but Epoch Clock validation does not depend on them.

## **1.2A Canonical Profile Reference (NORMATIVE)**

The canonical Epoch Clock v2.0 profile used by all PQSF and consuming specifications (including PQSEC and PQHD) is:

```
profile_ref = "ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0"
```

All compliant implementations MUST validate this inscription directly and MUST reject any EpochTick whose `profile_ref` does not match this value. Profile lineage, mirror reconciliation, rotation behaviour, and freshness rules MUST all be evaluated using this canonical profile as the authoritative parent.

The authority of an Epoch Clock profile derives solely from its canonical inscription reference and validated lineage. Authority does not derive from network position, mirror identity, or runtime environment.

---

## **1.2B Trustless Temporal Authority (NORMATIVE)**

The Epoch Clock is designed so that time validation never depends on central servers, cloud infrastructure, DNS, or NTP. All security properties derive from Bitcoin-inscribed profiles, ML-DSA-65 signatures, canonical encoding, and mirror consensus.

Users may verify, fork, mirror, or self-host Epoch Clock infrastructure without coordination or permission from any operator. Explorer services are provided for convenience only and are never authoritative; clients MUST validate the canonical profile using the on-chain inscription referenced by `profile_ref`.

**(Informative) Public explorers for convenience only:**

- https://ordinals.com/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
- https://bestinslot.xyz/ordinals/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
- https://www.ord.io/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0

---

## **1.2C What This Specification Covers (INFORMATIVE)**

The following areas are defined normatively by this document:

1. **Temporal Authority**  
   The canonical profile, Bitcoin anchoring model, lineage rules, and emergency-rotation semantics.

2. **EpochTick Semantics**  
   ML-DSA-65 signatures, SHAKE256 hashing, canonical encoding, freshness, monotonicity, and `profile_ref` binding.

3. **Mirror and Reconciliation Model**  
   Deterministic validation rules, cross-mirror consistency, divergence handling, and fail-closed behaviour.

4. **Canonical Encoding**  
   JCS Canonical JSON format required for all Epoch Clock artefacts (profiles and ticks).

5. **Offline, Stealth, and Sovereign Operation**  
   Strict tick-reuse windows, freeze rules, reconciliation requirements, and partition-tolerant behaviour.

6. **Integration Semantics**  
   How dependent systems interpret EpochTicks for consent windows, policy timing, runtime-integrity timestamping, AI-alignment freshness, and session boundaries.

7. **Security, Privacy, and Sovereignty Guarantees**  
   Metadata minimisation, centralisation-avoidance, and full local verifiability using only deterministic validation rules.

Optional annexes provide examples and extended workflows without modifying the normative core.

---

## **1.3 Relationship to PQSF and PQSEC**

PQSF and PQSEC depend on the Epoch Clock for deterministic, post-quantum-signed time artefacts.

**Epoch Clock has no dependencies on PQSF, PQSEC, or other PQ stack specifications.**

PQSF and PQSEC consume Epoch Clock artefacts as follows:

* **EpochTick artefacts** — PQSF and PQSEC use EpochTick artefacts as temporal evidence for consent windows, policy enforcement, ledger operations, and runtime predicates (see PQSF and PQSEC for temporal evidence integration).

* **Profile lineage** — PQSF and PQSEC validate `profile_ref` against the active Epoch Clock v2 profile and child-profile lineage (see PQSF for profile validation rules).

* **Freshness and monotonicity** — PQSEC enforces tick age and monotonicity rules using Epoch Clock artefacts as evidence (see PQSEC §18 for freshness and monotonicity enforcement).

* **Canonical encoding** — PQSF and PQSEC process Epoch Clock artefacts in their canonical JCS JSON format (see PQSF §7.4 for Epoch Clock canonical JSON exception, PQSF §14 for Epoch Clock integration objects, PQSEC §13 for canonical encoding enforcement).

* **Replay and rollback detection** — PQSEC uses Epoch Clock artefacts to detect invalid, stale, or rollback conditions and enforces fail-closed behaviour for all dependent operations (see PQSEC for replay and rollback detection rules).

**Epoch Clock provides temporal artefacts only. All enforcement semantics (freshness windows, monotonicity rules, acceptance/refusal decisions, freeze conditions) are defined by PQSEC and consuming specifications.**

## **1.4 Relationship to PQHD (Normative)**

PQHD consumes EpochTicks as its sole temporal authority for custody predicates and refusal semantics.

PQHD implementations MUST:

* validate EpochTicks according to this specification before evaluating any custody predicate;
* fail closed if EpochTick validation fails, is stale, or mirror consensus cannot be established;
* treat Epoch Clock as a read-only authority source and MUST NOT assume any Bitcoin Script-level enforcement.

Epoch Clock does not depend on PQHD. PQHD depends on Epoch Clock for deterministic, sovereign, verifiable time.

## **1.4A Authority Anchor Pattern (Normative–Informative)**

Epoch Clock follows a general pattern in which an Ordinal inscription is used as an immutable public reference anchor for an authority domain, while all enforcement occurs off-chain through signer and wallet policy.

In this pattern:

* the inscription defines authoritative parameters (for example, time profiles, lineage rules, or validity constraints);
* the inscription is never read by Bitcoin Script;
* wallets and signers validate the inscription and its lineage independently;
* refusal to sign is the sole enforcement mechanism.

This pattern is intentionally general and may be reused by other authority domains (for example governance, execution policy, recovery semantics, or threat-model declarations) without modifying Bitcoin consensus or Script.

## **1.4B Consuming Protocols (Normative)**

Epoch Clock is designed to be consumed by external protocols and wallet systems that require a verifiable temporal reference.

Examples include:

* PQHD, which consumes EpochTicks as its sole temporal authority for custody predicates;
* EPOCH Protocol, which binds execution-time commitments to wallet-validated epoch values;
* other authority systems that require monotonic, replay-resistant time for policy enforcement.

Epoch Clock does not depend on any consuming protocol. All consuming protocols MUST treat Epoch Clock as a read-only authority source and MUST NOT assume any Script-level enforcement.

## **1.5 Non-Goals**

The Epoch Clock does **not** aim to:

* replace Bitcoin consensus or timestamps;
* serve as an oracle or data feed;
* inject time into Bitcoin Script, miner decision-making, or consensus;
* provide subjective time or timezone information;
* manage private keys or custody models;
* define wallet-level policy;
* define application-level semantics.

Epoch Clock MUST NOT be interpreted as an oracle. Any system that treats Epoch Clock as an on-chain oracle is non-conformant.


## **1.6 Deployment Environments**

The Epoch Clock supports:

* web browsers
* hardware devices
* air-gapped systems
* offline-first clients
* PQHD signers
* PQSEC runtime probes
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
* **Canonical encoding**: JCS Canonical JSON (RFC 8785) exclusively for Epoch Clock artefacts.

## **1.8 Compatibility With Existing Standards**

Epoch Clock integrates with:

* Bitcoin Ordinals
* JCS Canonical JSON (RFC 8785)
* PQSF transport (hybrid TLS, STP, TLSE-EMP) - note that PQSF may use CBOR for its own transport, but Epoch Clock artefacts remain JCS JSON only
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

* forged time
* replayed time
* NTP poisoning
* system-clock rollback
* cross-domain replay
* stale-tick attacks
* consensus downgrade attacks
* mirror manipulation
* profile lineage forgery
* partial compromise of mirrors
* classical cryptographic break
* quantum adversaries

Attackers are assumed capable of:

* network interception
* TLS tampering
* state rollback
* classical key theft
* forging classical time sources
* replaying valid ticks
* partially compromising mirror infrastructure

(Informative)
This section describes only the temporal-authority threat surface. The complete, cross-module attack analysis — including transport, runtime, custody, identity, cloud, AI, supply-chain, and physical-world threats — is defined in PQSEC (See PQSEC Annex AL — Security & Attack Surface Analysis).

---

# **2. ARCHITECTURE OVERVIEW (NORMATIVE)**

## **2.1 Architecture Layers**

The Epoch Clock comprises:

* **Bitcoin inscription layer**
* **Profile layer** (long-lived parameters)
* **Tick issuance layer** (ML-DSA-65 signatures)
* **Mirror layer** (distributed validation and reconciliation)
* **Client validation layer** (PQSF and consuming specifications)
* **Governance and emergency layer**

## **2.2 Components**

* **Profile**: JCS Canonical JSON object defining duration, public keys, emergency quorum, etc.* **Tick issuer**: Entity producing signed ticks.
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

## **2.6A Meaning of "Decentralised" (Normative)**

This specification distinguishes between:

- **Decentralised distribution**: tick material may be replicated, mirrored, and retrieved from multiple independent sources.
- **Decentralised authority**: tick validity is determined by verification rules that do not depend on a single signing authority.

Where this specification uses the term "decentralised", it refers to properties defined by the tick validation rules in this document (including single-issuer or multi-issuer models, as applicable to the tick version in use).

Implementations and deployments MUST clearly distinguish which form of decentralisation applies to their configuration and MUST NOT imply decentralised authority if tick validity depends on a single issuer.

Single-issuer profiles (v2) MUST NOT claim decentralised authority. They may claim decentralised distribution only.

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
* JCS Canonical JSON (RFC 8785)
* Bitcoin ordinal inscriptions

**Epoch Clock has no dependencies on PQSF, PQSEC, PQHD, PQAI, or other PQ stack specifications.**

PQSF, PQSEC, PQHD, and PQAI depend on Epoch Clock for temporal artefacts.

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

The Epoch Clock uses SHAKE256 with a 256-bit (32-byte) output for all hashing operations.

The canonical identifier for this hash function in profile and tick objects is:

```
"shake-256-256"
```

SHAKE256-256 is used for:

* profile hashing
* tick hashing
* profile lineage verification
* mirror reconciliation
* downstream PQSF binding

## **3.3.1 Hash Output Length (NORMATIVE)**

All SHAKE256 invocations defined in this specification MUST use an output length of exactly 256 bits (32 bytes).

This requirement applies to:

* profile hashing (`hash_pq`)
* tick hashing
* profile-lineage verification
* mirror-consensus validation
* governance_config_id computation
* tick_keyset_id computation
* any downstream binding that depends on Epoch Clock hashing

Implementations MUST NOT vary the digest length.

All compliant systems MUST produce bit-identical 32-byte digests for the same canonical input.

The canonical string identifier for this hash function is:

```
"shake-256-256"
```

## **3.4 Randomness Requirements**

Tick issuers must use CSPRNG entropy meeting NIST SP 800-90B requirements.

## **3.5 Domain Separation**

Domain strings MUST be prepended to the JCS-encoded bytes before hashing in all signing and hash preimage constructions:

* `"EpochClock-Profile-v2"` — prepended to v2 profile signing preimage (§4.1.2-1)
* `"EpochClock-Tick-v2"` — prepended to v2 tick signing preimage (§4.1.1A)
* `"EpochClock-Profile-v3"` — prepended to v3 profile signing preimage (§4.1.2A.2)
* `"EpochClock-Tick-v3"` — prepended to v3 tick signing preimage (§4.1.2B.1)
* `"EpochClock-CompromiseNotice-v1"` — prepended to CompromiseRevocationNotice signing preimage (§6.8.1)
* `"EpochClock-MirrorPacket-v1"` — prepended to MirrorConsensusPacket signing preimage (§4.1.4)

Domain strings are encoded as UTF-8 bytes and concatenated directly (no length prefix, no separator) with the JCS-encoded body bytes before hashing.

Content-binding hashes computed over complete artefacts (for example, `epoch_clock_hash` computed over canonical Epoch Clock artefact bytes) are not signing preimages and MUST NOT prepend textual domain separation labels unless explicitly stated by the consuming specification.

## **3.6 Canonical Encoding Requirements**

**Epoch Clock profiles and ticks MUST be encoded exclusively as JCS Canonical JSON (RFC 8785).**

Requirements:

1. All Epoch Clock artefacts (profiles and ticks) MUST use JCS Canonical JSON encoding.
2. CBOR encoding MUST NOT be used for Epoch Clock artefacts.
3. Canonical encoding MUST be byte-stable across implementations.
4. Re-encoding the decoded object MUST produce byte-identical output.
5. Any re-encoding or alternate representation MUST be rejected.

**Note:** Consuming specifications (PQSF, PQSEC, PQHD) may use deterministic CBOR for their own transport layers, but Epoch Clock artefacts themselves are JCS JSON only.

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

### **3.6.2 Child Profile Inscriptions**

Child profiles MUST:

* include `parent_profile_ref`
* follow identical canonical encoding rules
* be inscribed as independent ordinal inscriptions
* be validated according to Epoch Clock §6 (Profile Governance & Rotation) and §4.1.3 (Parent–Child Profile Lineage)

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

## **4.1 Data Structures (CDDL / JSON)**

### **4.1.1 EpochTick (Authoritative)**

Ticks MUST be encoded in JCS Canonical JSON only (see §3.6).

**Logical structure** (CDDL notation used for type reference only — the wire format is JCS Canonical JSON, NOT CBOR):

```
EpochTick = {
  t:              uint,        ; unix seconds (JSON integer)
  profile_ref:    tstr,        ; "ordinal:<txid:iN>" (JSON string)
  alg:            tstr,        ; "ML-DSA-65" (JSON string)
  sig:            tstr         ; base64url-encoded ML-DSA-65 signature (JSON string)
}
```

Note: In the JSON wire format, the `sig` field is a base64url-encoded string, not raw bytes. CDDL `bstr` is used above for logical typing; the actual JSON encoding is `tstr` containing base64url. Implementations MUST encode and decode ticks as JCS Canonical JSON per §3.6.

### **4.1.1A Tick v2 Signing Preimage (Normative)**

The v2 tick signature `sig` MUST be computed as follows:

1. Construct `tick_body` as the tick object with the `sig` field **omitted**
2. Encode as JCS canonical JSON (UTF-8 bytes)
3. Prepend the domain separation label
4. Hash with SHAKE256-256
5. Sign with ML-DSA-65

```
tick_body       = tick minus sig
tick_body_bytes = JCS(tick_body)
tick_body_hash  = SHAKE256-256("EpochClock-Tick-v2" || tick_body_bytes)
sig             = ML-DSA-65-SIGN(privkey_pq, tick_body_hash)
```

Verification:

```
ML-DSA-65-VERIFY(pubkey_pq, tick_body_hash, sig) == true
```

Where `tick_body_hash` is recomputed identically by the verifier.

If signature verification fails, the tick MUST be rejected.

**Refusal code:** `E_TICK_SIGNATURE_INVALID`

### **4.1.2 Epoch Clock Profile v2 (Authoritative)**

This structure corresponds exactly to the inscribed v2 profile. This is the current production profile.

**Canonical Profile Reference:**
```
ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
```

**JSON Schema:**

```json
{
  "alg_alt":                     string,   // classical algorithm ("ECDSA-P256")
  "alg_pq":                      string,   // PQ algorithm ("ML-DSA-65")
  "duration_seconds":            integer,  // profile validity duration
  "emergency_quorum":            [string], // governance key IDs ("kid:gov-X:bc1q...")
  "format":                      string,   // time format ("unix_seconds")
  "hash_pq":                     string,   // profile hash ("shake-256-256:<hex>")
  "origin":                      string,   // anchor type ("ordinal")
  "p":                           string,   // protocol identifier ("epoch-clock")
  "profile_ref":                 string,   // inscription reference ("ordinal:<txid:iN>")
  "pubkey_alt_spki_der_b64u":    string,   // classical public key (base64url SPKI DER)
  "pubkey_pq":                   string,   // PQ public key (base64url)
  "rotation_schedule_seconds":   integer,  // rotation interval
  "sig_pq":                      string,   // profile signature (base64url)
  "start_unix":                  integer,  // epoch start time
  "v":                           string    // version ("2")
}
```

**Field Encoding:**

| Field | Encoding |
|-------|----------|
| `pubkey_pq` | Base64url-encoded ML-DSA-65 public key bytes |
| `pubkey_alt_spki_der_b64u` | Base64url-encoded SPKI DER (ECDSA-P256) |
| `sig_pq` | Base64url-encoded ML-DSA-65 signature bytes |
| `hash_pq` | Prefixed hash: `shake-256-256:<hex>` |
| `emergency_quorum` | Array of `kid:gov-<letter>:bc1q<address>` strings |
| `profile_ref` | `ordinal:<txid>i<index>` |

### **4.1.2-1 Profile v2 Hash and Signature Preimage (Normative)**

The v2 profile contains two computed fields: `hash_pq` and `sig_pq`. To avoid circularity, these MUST be computed in the following order:

**Step 1: Compute `hash_pq`**

```
profile_body_for_hash = profile minus hash_pq and sig_pq
profile_body_bytes    = JCS(profile_body_for_hash)
hash_pq               = "shake-256-256:" || HEX(SHAKE256-256(profile_body_bytes))
```

**Step 2: Compute `sig_pq`**

```
profile_body_for_sig  = profile minus sig_pq (hash_pq is included)
profile_body_bytes    = JCS(profile_body_for_sig)
profile_body_hash     = SHAKE256-256("EpochClock-Profile-v2" || profile_body_bytes)
sig_pq                = ML-DSA-65-SIGN(privkey_pq, profile_body_hash)
```

**Verification:**

1. Reconstruct `profile_body_for_hash` (profile minus `hash_pq` and `sig_pq`), compute JCS, hash with SHAKE256-256, and verify the result matches `hash_pq` (after prefix).
2. Reconstruct `profile_body_for_sig` (profile minus `sig_pq`, with `hash_pq` included), compute JCS, hash with domain-separated SHAKE256-256, and verify `sig_pq` against `pubkey_pq`.

If either check fails, the profile MUST be rejected.

**Refusal code:** `E_PROFILE_INVALID`

### **4.1.2A Epoch Clock Profile v3 (Authoritative)**

Profile v3 introduces decentralised tick issuance through multi-signature threshold validation. This enables 2-of-3 (or M-of-N) tick signing for improved availability and reduced single-party risk.

**JSON Schema:**

```json
{
  // === Identity and Versioning ===
  "spec":                        string,   // MUST be "epoch-clock.profile"
  "v":                           integer,  // MUST be 3
  "profile_id":                  string,   // human-readable identifier (e.g., "epoch-clock.v3")
  "profile_name":                string,   // display name (e.g., "Epoch Clock v3")

  // === Lineage and Ancestry ===
  "profile_ref":                 string,   // this profile's inscription ref ("ordinal:<txid>i<N>")
  "genesis_profile_ref":         string,   // root profile of lineage (v2 inscription ref)
  "parent_profile_ref":          string,   // immediate parent profile ref
  "fork_id":                     string,   // 16-byte fork identifier ("0x<32 hex chars>")
  "lineage_height":              integer,  // chain position (0=genesis, 1=first child, etc.)

  // === Cryptographic Configuration ===
  "hash_alg":                    string,   // hash algorithm ("shake-256-256")
  "suite_profile":               string,   // crypto suite ("pqec.suite.mldsa65_shake256")
  "sig_pq_alg":                  string,   // signature algorithm ("ml-dsa-65")
  "pubkey_pq":                   string,   // profile signing pubkey (base64url)
  "sig_pq":                      string,   // profile signature (base64url) - OMITTED when signing

  // === Rotation and Announcement ===
  "rotation_schedule_seconds":   integer,  // rotation interval
  "min_announcement_seconds":    integer,  // minimum announcement lead time

  // === Governance Configuration ===
  "governance_threshold":        integer,  // required signatures for profile rotation
  "governance_members":          [string], // governance member IDs ("kid:gov-X:bc1q...")
  "governance_config_id":        string,   // SHAKE256-256(JCS(GovernanceConfig)) as "0x<hex>"

  // === Tick Issuance Configuration ===
  "tick_interval_seconds":       integer,  // tick production interval (e.g., 60)
  "tick_time_source":            string,   // time anchor source ("bitcoin")
  "tick_anchor_rule":            string,   // anchor binding rule ("block_hash")
  "tick_anchor_min_confirmations": integer, // minimum confirmations for anchor (e.g., 1)

  // === Multi-Signature Tick Keyset ===
  "tick_sig_threshold":          integer,  // minimum tick signatures required (e.g., 2)
  "tick_pubkeys_pq":             [string], // tick signing pubkeys (base64url)
  "tick_keyset_id":              string,   // SHAKE256-256(JCS(TickKeyset)) as "0x<hex>"

  // === Content Hash ===
  "hash_pq":                     string,   // "shake-256-256:" || HEX(SHAKE256-256(profile_body_for_hash))
  "sig_pq":                      string    // profile signature (base64url) - OMITTED when signing
}
```

**v3 Field Semantics:**

| Field | Description |
|-------|-------------|
| `spec` | Protocol identifier. MUST be `"epoch-clock.profile"`. |
| `v` | Schema version. MUST be `3` for v3 profiles. |
| `profile_id` | Machine-readable identifier (e.g., `"epoch-clock.v3"`). |
| `profile_name` | Human-readable display name. |
| `profile_ref` | This profile's inscription reference. May be placeholder until inscription. |
| `genesis_profile_ref` | Reference to the root profile of this lineage (the inscribed v2 profile). |
| `parent_profile_ref` | Reference to the immediate parent profile. Required for `lineage_height ≥ 1`. |
| `fork_id` | 16-byte fork identifier. Genesis/main lineage uses `0x00000000000000000000000000000000`. |
| `lineage_height` | Position in profile chain. Genesis = 0, first child = 1, etc. |
| `hash_alg` | Hash algorithm for all profile/tick hashing. MUST be `"shake-256-256"`. |
| `suite_profile` | Cryptographic suite identifier (e.g., `"pqec.suite.mldsa65_shake256"`). |
| `sig_pq_alg` | Signature algorithm for profile and tick signing. MUST be `"ml-dsa-65"`. |

The `pqec.*` namespace is Epoch Clock-specific and is not required to match PQSF `pqsf.*` suite_profile identifiers. Epoch Clock artefacts are validated using this specification's rules and the referenced public keys; no cross-spec suite_profile string equivalence is required.
| `pubkey_pq` | Profile signing public key (base64url-encoded ML-DSA-65 pubkey). |
| `sig_pq` | Profile signature (base64url). Omitted from signing preimage. |
| `rotation_schedule_seconds` | Interval between scheduled profile rotations. |
| `min_announcement_seconds` | Minimum lead time for announcing profile rotations. |
| `governance_threshold` | Number of governance signatures required for profile rotation approval. |
| `governance_members` | Array of governance member identifiers (`kid:gov-<X>:bc1q<addr>`). |
| `governance_config_id` | Content-addressed binding: `SHAKE256-256(JCS(GovernanceConfig))` as `0x<hex>`. |
| `tick_interval_seconds` | Target interval between tick issuance (e.g., 60 seconds). |
| `tick_time_source` | Source for time anchoring. MUST be `"bitcoin"`. |
| `tick_anchor_rule` | How ticks bind to anchor. MUST be `"block_hash"`. |
| `tick_anchor_min_confirmations` | Minimum block confirmations for anchor validity. |
| `tick_sig_threshold` | Minimum valid tick signatures required. MUST be ≥ 1 and ≤ len(tick_pubkeys_pq). |
| `tick_pubkeys_pq` | Ordered array of tick signing public keys (base64url-encoded). |
| `tick_keyset_id` | Content-addressed binding: `SHAKE256-256(JCS(TickKeyset))` as `0x<hex>`. |
| `hash_pq` | Content-addressed profile hash: `"shake-256-256:" \|\| HEX(SHAKE256-256(profile_body_for_hash))`. The hash preimage is the JCS-serialised profile body with `hash_pq` and `sig_pq` fields removed. |

For conformance with this specification, `hash_alg` MUST equal `"shake-256-256"`. Any other value MUST cause profile rejection.

**Refusal code:** `E_PROFILE_INVALID`

### **4.1.2A.1 Canonical Sub-Object Identifiers (Normative)**

Two content-addressed identifiers are defined for governance and tick issuance.

#### GovernanceConfig

GovernanceConfig is the JSON object:

```json
{
  "governance_threshold": <uint>,
  "governance_members": [ <tstr>, ... ]
}
```

`governance_config_id` MUST equal:

```
governance_config_id = SHAKE256-256( JCS( GovernanceConfig ) )
```

#### TickKeyset

TickKeyset is the JSON object:

```json
{
  "tick_sig_threshold": <uint>,
  "tick_pubkeys_pq": [ <bstr-as-0x-hex>, ... ]
}
```

`tick_keyset_id` MUST equal:

```
tick_keyset_id = SHAKE256-256( JCS( TickKeyset ) )
```

If either identifier mismatches its canonical sub-object bytes, the profile MUST be rejected.

**Refusal code:** `E_PROFILE_INVALID`

### **4.1.2A.2 Profile Signature Preimage (Normative)**

The Epoch Clock profile signature `sig_pq` MUST be computed over the JCS canonical bytes of the full profile object with the following rule:

1. The field `sig_pq` is **omitted** from the signing preimage
2. No other fields are omitted
3. Encoding is UTF-8

Define:

```
profile_body       = profile minus sig_pq
profile_body_bytes = JCS(profile_body)
profile_body_hash  = SHAKE256-256("EpochClock-Profile-v3" || profile_body_bytes)
sig_pq             = ML-DSA-65-SIGN(privkey_pq, profile_body_hash)
```

Verification:

```
ML-DSA-65-VERIFY(pubkey_pq, profile_body_hash, sig_pq) == true
```

Where `profile_body_hash` is recomputed identically by the verifier using the domain-separated preimage.

If signature verification fails, the profile MUST be rejected.

**Refusal code:** `E_PROFILE_INVALID`

### **4.1.2A.3 Example v3 Profile Template (Informative)**

Complete v3 profile JSON before signing (omit `sig_pq` until signature is computed):

```json
{
  "spec": "epoch-clock.profile",
  "v": 3,

  "profile_id": "epoch-clock.v3",
  "profile_name": "Epoch Clock v3",

  "profile_ref": "ordinal:<your-v3-inscription-txid>i0",
  "genesis_profile_ref": "ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0",
  "parent_profile_ref": "ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0",

  "fork_id": "0x00000000000000000000000000000000",
  "lineage_height": 1,

  "hash_alg": "shake-256-256",
  "suite_profile": "pqec.suite.mldsa65_shake256",
  "sig_pq_alg": "ml-dsa-65",

  "rotation_schedule_seconds": 604800,
  "min_announcement_seconds": 604800,

  "governance_threshold": 3,
  "governance_members": [
    "kid:gov-A:bc1q...",
    "kid:gov-B:bc1q...",
    "kid:gov-C:bc1q..."
  ],
  "governance_config_id": "0x<computed-by-hashpack>",

  "tick_interval_seconds": 60,
  "tick_time_source": "bitcoin",
  "tick_anchor_rule": "block_hash",
  "tick_anchor_min_confirmations": 1,

  "tick_sig_threshold": 2,
  "tick_pubkeys_pq": [
    "<base64url-pubkey-1>",
    "<base64url-pubkey-2>",
    "<base64url-pubkey-3>"
  ],
  "tick_keyset_id": "0x<computed-by-hashpack>",

  "pubkey_pq": "<base64url-profile-signing-pubkey>"
}
```

**Signing Workflow:**

1. Create profile JSON without `sig_pq`
2. Run hashpack to compute `governance_config_id` and `tick_keyset_id`
3. Insert computed IDs into profile JSON
4. Run hashpack to get `profile_body_hash`
5. Sign `profile_body_hash` with ML-DSA-65 to produce `sig_pq`
6. Insert `sig_pq` (base64url) into profile JSON
7. Inscribe final JSON

### **4.1.2B EpochTick v3 (Multi-Signature)**

For v3 profiles, ticks carry multiple signatures and explicit anchoring.

**JSON Schema:**

```json
{
  // === Identity ===
  "spec":               string,   // MUST be "epoch-clock.tick"
  "v":                  integer,  // MUST be 3

  // === Profile Binding ===
  "profile_ref":        string,   // reference to active v3 profile ("ordinal:<txid>i<N>")
  "fork_id":            string,   // fork identifier ("0x<32 hex chars>")

  // === Time ===
  "tick":               integer,  // tick sequence number
  "t":                  integer,  // unix seconds (informative, derived from anchor)

  // === Bitcoin Anchor ===
  "anchor": {
    "chain":            string,   // MUST be "bitcoin"
    "block_height":     integer,  // anchor block height
    "block_hash":       string    // anchor block hash ("0x<64 hex chars>")
  },

  // === Hashing Configuration ===
  "hash_alg":           string,   // MUST be "shake-256-256"
  "tick_sig_threshold": integer,  // threshold for this tick (must match profile)

  // === Signature Fields (added after hashing) ===
  "tick_body_hash":     string,   // SHAKE256-256 of tick body ("0x<64 hex chars>")
  "tick_sigs":          [TickSig] // array of tick signatures
}
```

**TickSig Structure:**

```json
{
  "key_id":             string,   // SHAKE256-256(pubkey_bytes) as "0x<64 hex chars>"
  "sig":                string    // ML-DSA-65 signature (base64url)
}
```

**Tick Field Semantics:**

| Field | Description |
|-------|-------------|
| `spec` | Artefact type. MUST be `"epoch-clock.tick"`. |
| `v` | Schema version. MUST be `3` for v3 ticks. |
| `profile_ref` | Reference to the profile this tick is issued under. |
| `fork_id` | Fork identifier. MUST match the profile's `fork_id`. |
| `tick` | Monotonically increasing tick sequence number. |
| `t` | Unix timestamp (informative). Derived from anchor block time. |
| `anchor.chain` | Anchor chain. MUST be `"bitcoin"`. |
| `anchor.block_height` | Height of the anchor block. |
| `anchor.block_hash` | Hash of the anchor block as `0x<64 hex chars>`. |
| `hash_alg` | Hash algorithm. MUST be `"shake-256-256"`. |
| `tick_sig_threshold` | Required signatures. MUST match profile's `tick_sig_threshold`. |
| `tick_body_hash` | Hash of tick body (without `tick_sigs` and `tick_body_hash`). |
| `tick_sigs` | Array of signatures from tick signing keys. |
```

### **4.1.2B.1 Tick Signing Preimage (Normative)**

The tick body hash MUST be computed as follows:

1. Construct `tick_body` as the tick object **minus** `tick_sigs` and `tick_body_hash`
2. Encode as JCS canonical JSON
3. Prepend the domain separation label
4. Hash with SHAKE256-256

```
tick_body       = tick minus tick_sigs and tick_body_hash
tick_body_bytes = JCS(tick_body)
tick_body_hash  = SHAKE256-256("EpochClock-Tick-v3" || tick_body_bytes)
```

Each signature in `tick_sigs` MUST sign `tick_body_hash`.

### **4.1.2B.2 Tick Signature Entry Format (Normative)**

Each signature entry is:

```json
{ "key_id": "0x<64 hex chars>", "sig": "<base64url>" }
```

Where:
- `key_id = SHAKE256-256(tick_pubkey_bytes)` as 0x-prefixed hex (64 characters)
- `sig` is an ML-DSA-65 signature over `tick_body_hash` (base64url encoded)

### **4.1.2B.3 Tick v3 Validation (Normative)**

A tick is valid only if:

1. `tick_body_hash` matches the canonical tick body bytes (recomputed)
2. At least `tick_sig_threshold` signatures verify
3. Signatures are from distinct `key_id` values
4. Each `key_id` maps to a key in the active profile's `tick_pubkeys_pq`:
   - For each pubkey in `tick_pubkeys_pq`, compute `SHAKE256-256(pubkey_bytes)`
   - Match against `key_id` in signature entry
5. `profile_ref` references a valid v3 profile

**Refusal code:** `E_TICK_SIGNATURE_THRESHOLD_UNMET`

### **4.1.2B.4 Example v3 Tick Template (Informative)**

Complete v3 tick JSON before signing (omit `tick_body_hash` and `tick_sigs` until computed):

```json
{
  "spec": "epoch-clock.tick",
  "v": 3,

  "profile_ref": "ordinal:<v3-profile-inscription>i0",
  "fork_id": "0x00000000000000000000000000000000",

  "tick": 123456,
  "t": 1730000123,

  "anchor": {
    "chain": "bitcoin",
    "block_height": 900000,
    "block_hash": "0x0000000000000000000123456789abcdef..."
  },

  "hash_alg": "shake-256-256",
  "tick_sig_threshold": 2
}
```

**After signing, add:**

```json
{
  "tick_body_hash": "0x<64 hex chars from hashpack>",
  "tick_sigs": [
    { "key_id": "0x<shake256-256 of pubkey1>", "sig": "<base64url sig1>" },
    { "key_id": "0x<shake256-256 of pubkey2>", "sig": "<base64url sig2>" }
  ]
}
```

### **4.1.2C Genesis Profile Defaults (Normative)**

The genesis profile (v2) predates explicit governance and tick keyset identifiers.

Implicit defaults apply to the genesis profile only:

| Field | Implicit Value |
|-------|----------------|
| `fork_id` | `0x00000000000000000000000000000000` |
| `lineage_height` | 0 |
| `tick_sig_threshold` | 1 |
| `tick_pubkeys_pq` | `[ pubkey_pq ]` (single key, same as profile key) |
| `governance_config_id` | absent (implicit from emergency_quorum) |
| `tick_keyset_id` | absent (implicit single-key) |
| `genesis_profile_ref` | self-referential (profile_ref) |

Child profiles (lineage_height ≥ 1) MUST declare all v3 fields explicitly.

**Refusal code:** `E_PROFILE_SCHEMA_INCOMPLETE`

### **4.1.2D Version Detection (Normative)**

Implementations MUST detect profile version:

| Detection | Profile Type | Tick Format |
|-----------|--------------|-------------|
| `"v": "2"` (string) | v2 profile | Single signature (`sig` field) |
| `"v": 3` (integer) AND `"spec": "epoch-clock.profile"` | v3 profile | Multi-signature (`tick_sigs` array) |

For ticks:

| Detection | Tick Type |
|-----------|-----------|
| `"v": "2"` or no `spec` field | v2 tick (single `sig` field) |
| `"v": 3` AND `"spec": "epoch-clock.tick"` | v3 tick (`tick_sigs` array) |

Implementations MUST support both v2 and v3 validation concurrently during the transition period.

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
  sig_mirror: tstr  ; base64url-encoded ML-DSA-65 signature (JSON string)
}
```

Note: In the JSON wire format, `sig_mirror` is a base64url-encoded string. Logical CDDL `bstr` representations are used for type description only; the canonical encoding is JCS JSON per §3.6.

**Signing Preimage (Normative):**

The `sig_mirror` MUST be computed as follows:

```
packet_body       = packet minus sig_mirror
packet_body_bytes = JCS(packet_body)
packet_hash       = SHAKE256-256("EpochClock-MirrorPacket-v1" || packet_body_bytes)
sig_mirror        = ML-DSA-65-SIGN(mirror_privkey, packet_hash)
```

Verification MUST recompute `packet_hash` identically.

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

A client validating an EpochTick MUST perform the following structural and cryptographic validation steps:

1. **Fetch** tick from ≥2 mirrors
2. **Canonicalise**
3. **Validate profile_ref**
4. **Verify ML-DSA-65 signature(s)**
5. **Recompute SHAKE256-256 hash(es)**
6. **Mirror consensus check**

Freshness enforcement (≤ 900 seconds), monotonicity checks (t ≥ last_valid_tick), reuse window enforcement, and operational acceptance/refusal decisions are defined and enforced exclusively by PQSEC and consuming specifications.

The Epoch Clock specification defines structural validity only.

### **4.2.2 Mirror Behaviour State Machine**

Mirror implementations MUST implement the following state machine:

**States:**

| State | Description |
|-------|-------------|
| `INIT` | Mirror starting up, no profile loaded |
| `SYNCING` | Profile loaded, fetching and validating ticks |
| `ACTIVE` | Steady state, publishing valid ticks |
| `STALE` | Tick age exceeds freshness window, awaiting fresh tick |
| `FAILED` | Unrecoverable error, requires operator intervention |

**Transitions:**

| From | To | Trigger | Action |
|------|----|---------|--------|
| `INIT` | `SYNCING` | Profile fetched and validated (structure + sig_pq + hash_pq) | Store active profile |
| `INIT` | `FAILED` | Profile fetch fails or validation fails | Log error, enter FAILED |
| `SYNCING` | `ACTIVE` | First valid tick verified and published | Begin steady-state tick serving |
| `SYNCING` | `FAILED` | Tick fetch repeatedly fails (≥3 consecutive failures) | Log error, enter FAILED |
| `ACTIVE` | `ACTIVE` | New valid tick received | Publish tick, update last_valid_tick |
| `ACTIVE` | `ACTIVE` | Lineage extension detected (child profile) | Validate child profile, promote if valid, rehash, broadcast rotation |
| `ACTIVE` | `STALE` | No valid tick within freshness window | Stop serving stale ticks |
| `ACTIVE` | `FAILED` | Profile revoked or signature algorithm compromised | Log critical, enter FAILED |
| `STALE` | `ACTIVE` | Fresh valid tick received | Resume serving |
| `STALE` | `FAILED` | Stale duration exceeds maximum stale window (RECOMMENDED default: 3600 seconds, policy-configurable) | Log error, enter FAILED |
| `FAILED` | `INIT` | Operator restart | Reset state, begin fresh bootstrap |

**Invariants:**
- A mirror in `FAILED` state MUST NOT serve ticks.
- A mirror in `STALE` state MUST NOT serve ticks older than the freshness window.
- Profile promotion (lineage extension) MUST validate the child profile against Epoch Clock §6 (Profile Governance & Rotation) and §4.1.3 (Parent–Child Profile Lineage) before promoting.

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

Profile lifetime expiry checks (for example, evaluating whether `duration_seconds` has elapsed relative to `start_unix`) are enforced by PQSEC and consuming specifications. Epoch Clock defines profile structure and cryptographic validity only.

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
* matching t (exact integer equality — ticks from different issuance moments are distinct ticks, not approximate matches)
* matching signature validity

If mirrors diverge → FAIL_CLOSED.

Mirror consensus requires exact equality of the `t` field value. Ticks issued at different seconds are distinct ticks. Propagation delay between mirrors is handled by the freshness window (§5.5), not by consensus tolerance. If two mirrors serve ticks with different `t` values, the client MUST fetch from additional mirrors until at least 2 agree, or fail closed.

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

### **4.4.3 Runtime Integrity Probe Workflow**

Runtime integrity probes (consumed via PQSEC predicates) integrate ticks for drift timestamps:

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

## **4.4A Tick Fetch and Caching Discipline (Normative)**

### **4.4A.1 Purpose**

This section prevents operational tempo leakage through tick fetch behaviour. External observers MUST NOT be able to infer operation frequency, timing, or intent from the pattern of tick requests.

### **4.4A.2 Caching Requirement**

Implementations MUST cache verified EpochTicks locally.

1. A verified tick MAY be reused until it fails freshness or monotonicity rules.
2. Implementations MUST NOT fetch ticks in direct response to individual operation requests.
3. Tick retrieval MUST occur on a fixed schedule independent of operation frequency.

### **4.4A.3 Fetch Schedule**

Implementations MUST define:

```
tick_refresh_interval = max(
  profile.tick_interval_seconds,
  policy.min_tick_refresh_seconds
)
```

Tick fetches MUST occur no more frequently than `tick_refresh_interval`.

If `policy.min_tick_refresh_seconds` is not configured, it defaults to `profile.tick_interval_seconds`.

### **4.4A.4 Cold Start Exception**

On cold start or after cache expiration, the implementation MUST perform a single tick fetch as part of initialization, before accepting any operation requests. This initialization fetch is not considered an operation-triggered fetch.

Lockout exit (see PQSEC §21A) constitutes an initialization event and is also exempt from the operation-triggered fetch prohibition.

### **4.4A.5 Failure Behaviour**

If a fresh tick cannot be obtained:

1. The implementation MUST continue using the last verified tick until it becomes stale.
2. Once stale, Authoritative operations MUST fail closed.
3. The implementation MUST NOT increase fetch frequency in response to operation attempts.

### **4.4A.6 Authority Boundary**

Tick fetch discipline is an operational privacy control. It does not modify tick validity semantics, alter enforcement rules, or grant authority.

---

## **4.5 Mirror Discovery (NORMATIVE)**

Clients MUST implement at least one supported method for discovering Epoch Clock mirrors.
Implementations MAY support multiple mechanisms simultaneously to increase resilience.

### **4.5.1 Static Mirror List (Required for MVP)**

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

### **4.5.2 Profile-Embedded Mirror List (Recommended)**

Future profile versions MAY include:

```
"mirrors": ["https://...", "stp://..."]
```

If present:

* Clients MUST validate mirror URLs.
* Clients MAY use embedded mirrors but MUST NOT trust them exclusively.

### **4.5.3 DNS-Based Discovery (Optional)**

Clients MAY use DNS records such as:

```
_epochtick._tcp.example.com
```

DNS results MUST be ignored if:

* DNSSEC validation fails
* domain does not match `profile_ref`
* mirror list diverges from majority consensus

### **4.5.4 Local / Enterprise Discovery (Optional)**

STP broadcast or enterprise configuration MAY be used.
All discovered mirrors MUST adhere to the same validation rules as publicly listed mirrors.

---

## **4.6 Mirror API (NORMATIVE)**

Mirrors MUST expose at least one deterministic, canonical API for profile and tick retrieval.

### **4.6.1 HTTPS GET Endpoint (Required)**

**Endpoint:**

```
GET /tick
```

**Response** (JCS Canonical JSON only):

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

### **4.6.2 Profile Fetch**

```
GET /profile
```

Returns the canonical Epoch Clock Profile JSON (JCS).

### **4.6.3 STP Endpoint (Optional, INFORMATIVE)**

Mirrors MAY implement an STP (“Sovereign Transport Protocol”) endpoint for environments where DNS, public CA infrastructure, or traditional HTTPS are not available or not desired.

- The detailed STP handshake, framing, and security properties are specified in the PQSF transport layer (see PQSF STP Annex).
- When used, STP MUST carry the same canonical `tick` and `profile` objects as defined in §4.1, encoded using JCS Canonical JSON.
- All validation rules in §3, §4, and §5 apply identically to ticks and profiles received over STP.

This specification does not redefine STP itself; it only states how EpochTicks and profiles are transported over an STP channel.

### **4.6.4 Mirror Error Codes**

* `E_MIRROR_UNAVAILABLE`
* `E_MIRROR_DIVERGENCE`
* `E_PROFILE_MISMATCH`
* `E_TICK_INVALID`

### **4.6.5 Rate-Limiting (Informative)**

Mirrors SHOULD implement basic rate-limiting but MUST NOT introduce non-determinism or personalized responses.

Numeric rate limits (e.g., requests-per-second thresholds) are deployment-specific and intentionally not specified by this document. Implementers MUST ensure that any rate-limiting strategies do not alter the semantic content of responses or introduce per-client variation that could affect determinism or privacy.

---

### 4.6.6 Example Mirror Implementation Snippets (Informative)
The following examples provide non-normative reference patterns for implementing Epoch Clock mirror endpoints. Mirrors MAY use any framework or language, provided all responses remain deterministic and comply with canonical encoding rules.

#### 4.6.6.1 Minimal /tick Endpoint (Illustrative)
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

#### 4.6.6.2 Minimal /profile Endpoint (Illustrative)
def get_profile():
    profile_bytes = load_canonical_profile()
    response = {
        "profile": profile_bytes,
        "mirror_id": MIRROR_ID,
        "sig_mirror": sign_with_mirror_key(profile_bytes)
    }
    return canonical_encode(response)

#### 4.6.6.3 Illustrative Tick Reconciliation Logic
def reconcile_tick_sources():
    local_tick = fetch_local_tick()
    peer_ticks = fetch_peer_mirror_ticks()
    candidates = [local_tick] + peer_ticks
    valid = [t for t in candidates if verify_tick_signature(t)]
    selected = max(valid, key=lambda x: x["t"])
    return selected

#### 4.6.6.4 Example Canonical Encoder Wrapper
def canonical_encode(obj):
    return jcs_canonical_json_dumps(obj)

## **4.7 Mirror Identity and Trust Model (NORMATIVE)**

Mirrors MUST authenticate their responses using a long-term public key, and clients MUST verify `sig_mirror` before trusting any tick or profile data.

### **4.7.1 Mirror Public Keys**

Each mirror MUST have a stable public key (`mirror_pubkey`) used solely for signing API responses.

Mirror keys MAY be distributed via one or more of:

- Static configuration embedded in the client
- Operator-managed configuration files
- Enterprise configuration systems

The mechanism for provisioning `mirror_pubkey` values is deployment-specific and out of scope for this specification, but:

- Clients MUST treat any change of `mirror_pubkey` as a security-relevant event.
- Implementations SHOULD support pinning mirror keys to prevent downgrade or substitution attacks.

### **4.7.2 Validating `sig_mirror`**

For any response containing `sig_mirror`:

1. Construct the canonical encoding of the full response body excluding the `sig_mirror` field.
2. Verify `sig_mirror` using the configured `mirror_pubkey` and the mirror’s signature algorithm (e.g., ML-DSA-65).
3. If verification fails:
   - The response MUST be discarded.
   - The client MUST raise `E_SIG_INVALID` or `E_MIRROR_UNAVAILABLE`.
   - The client SHOULD query an alternate mirror as per §4.5.1.

### **4.7.3 Mirror Trust Policy**

The policy for selecting which mirrors to trust (and how many) is deployment-specific and out of scope.

However:

- Clients MUST NOT treat any single mirror as inherently authoritative.
- Clients MUST obtain and validate ticks from at least two independent mirrors as described in §4.3 and §4.4.5.

---

## **4.8 Error Handling & Failure Codes**

The Epoch Clock MUST produce or propagate:

**Core Errors (v2 and v3):**

* **E_TICK_INVALID** — tick structure malformed
* **E_TICK_EXPIRED** — tick beyond reuse window
* **E_TICK_ROLLBACK** — tick t < last_valid_tick
* **E_TICK_DIVERGENCE** — mirrors disagree on tick
* **E_PROFILE_INVALID** — profile structure malformed
* **E_PROFILE_MISMATCH** — profile_ref does not match expected
* **E_PROFILE_EXPIRED** — profile expiry condition detected by consuming specification
* **E_MIRROR_DIVERGENCE** — mirrors disagree on canonical bytes
* **E_MIRROR_UNAVAILABLE** — insufficient mirrors reachable
* **E_CANONICAL_MISMATCH** — JCS encoding differs
* **E_HASH_MISMATCH** — hash_pq verification failed
* **E_SIG_INVALID** — signature verification failed

**v3 Multi-Signature Errors:**

* **E_TICK_SIGNATURE_INVALID** — individual tick signature failed verification
* **E_TICK_SIGNATURE_THRESHOLD_UNMET** — valid signatures < tick_sig_threshold
* **E_PROFILE_VERSION_UNSUPPORTED** — unrecognised profile version string

**v3 Profile Governance Errors:**

* **E_PROFILE_SCHEMA_INCOMPLETE** — required v3 fields missing in non-genesis profile
* **E_GOVERNANCE_CONFIG_INVALID** — invalid governance_threshold/members constraints
* **E_PROFILE_CONFIRMATION_INSUFFICIENT** — insufficient independent confirmations for new profile
* **E_FORK_NOT_ADOPTED** — fork lineage encountered but not explicitly adopted by policy
* **E_LINEAGE_HEIGHT_INVALID** — lineage_height does not match expected chain position
* **E_GENESIS_REF_MISMATCH** — genesis_profile_ref does not match lineage root

All consuming systems MUST treat these as **FAIL_CLOSED**.

---


## **4.9 Error Recovery Procedures (NORMATIVE)**

Clients encountering errors MUST follow one of the mandatory recovery flows below.

### **4.9.1 Mirror Divergence**

* Query at least one additional mirror.
* If divergence persists → raise `E_MIRROR_DIVERGENCE` → FAIL_CLOSED.
* Retry only after `retry_interval_seconds`. RECOMMENDED default: 30 seconds (policy-configurable). Minimum: 5 seconds. Maximum: 300 seconds. Implementations MUST NOT retry more frequently than the minimum. Implementations MAY use exponential backoff within these bounds.

### **4.9.2 Tick Expiry**

* Attempt to retrieve a fresh tick.
* If unavailable → freeze all time-dependent operations.
* If Stealth Mode is active, refresh MUST wait until exit conditions in §8.2 are met.

### **4.9.3 Profile Mismatch**

* Fetch the inscribed profile referenced by `profile_ref`.
* Validate canonical encoding, `hash_pq`, and `sig_pq`.
* If mismatch persists → FAIL_CLOSED.

### **4.9.4 Canonical Encoding Error**

* Reject the tick.
* Retry using an alternate mirror.
* Log the failure in the dependent system’s ledger (PQHD / PQSF / PQSEC).

## **4.10 Transport Binding & Session Rules (PQSF Integration)**

EpochTicks MUST bind to PQSF transport requirements:

* embedded in ConsentProof
* included in Policy Enforcer evaluation
* MUST be fresh for exporter_hash binding
* included in TLSE-EMP transcripts
* included in STP offline messages
* used for session boundary enforcement
  
---

# **5. TIME / CLOCK / PROFILE INTEGRATION (NORMATIVE)**

## **5.1 Overview**

The Epoch Clock defines the authoritative time model for all PQSF-compliant systems. Every time-sensitive operation MUST be evaluated using EpochTicks.

## **5.2 Profile Structure**

The authoritative Epoch Clock Profile is defined by the JSON in your project folder (`epoch-clock-v2.json` for v2, `epoch-clock-v3.json` for v3).
All fields MUST appear exactly as defined. See §4.1.2 for v2 schema, §4.1.2A for v3 schema.

## **5.3 Tick Structure**

### **5.3.1 Tick v2 (Single Signature)**

A valid v2 EpochTick object MUST contain:

* `t` — unix seconds
* `profile_ref` — reference to v2 profile
* `alg` — "ML-DSA-65"
* `sig` — single ML-DSA-65 signature

No additional fields are permitted inside the canonical payload.

### **5.3.2 Tick v3 (Multi-Signature)**

A valid v3 EpochTick object MUST contain:

* `t` — unix seconds
* `profile_ref` — reference to v3 profile
* `tick_body_hash` — SHAKE256-256 hash of the canonical tick bytes with `tick_sigs` and `tick_body_hash` fields excluded
* `tick_sigs` — array of `{ key_id, sig }` objects where `key_id = SHAKE256-256(pubkey_bytes)` identifying the signing key

The `tick_sigs` array MUST contain at least `tick_sig_threshold` valid signatures.

## **5.4 Tick Validation Rules**

### **5.4.1 Common Validation (v2 and v3)**

A tick artefact is structurally valid if:

1. `profile_ref` references a known, valid profile
2. canonical JCS JSON encoding validates
3. all required fields present
4. ≥2 mirrors agree on identical canonical bytes

### **5.4.2 v2 Tick Signature Validation**

For profiles where `v` equals `"2"` (exact string match):

1. Verify single `sig` field against `profile.pubkey_pq`
2. If signature invalid, reject tick

**Refusal code:** `E_TICK_SIGNATURE_INVALID`

### **5.4.3 v3 Tick Signature Validation**

For v3 profiles:

1. Recompute `tick_body_hash = SHAKE256-256(canonical tick bytes excluding tick_sigs and tick_body_hash)`.
2. Verify recomputed hash matches the `tick_body_hash` field in the tick.
3. Initialise `valid_count = 0`
4. For each entry in `tick_sigs`:
   a. Compute `expected_key_id = SHAKE256-256(pubkey_bytes)` for each key in `profile.tick_pubkeys_pq`
   b. Match `key_id` to a profile key. If no match, skip entry with warning.
   c. Verify each `key_id` appears at most once. Duplicate `key_id` values MUST cause tick rejection.
   d. Verify `sig` against the matched pubkey over `tick_body_hash`
   e. If valid, increment `valid_count`
   f. If invalid, log warning but continue (partial validity allowed)
5. If `valid_count < profile.tick_sig_threshold`, reject tick

**Refusal codes:**
- `E_TICK_SIGNATURE_THRESHOLD_UNMET` — insufficient valid signatures
- `E_TICK_KEY_ID_UNKNOWN` — key_id does not match any profile key
- `E_TICK_KEY_ID_DUPLICATE` — same key_id appears more than once in tick_sigs
- `E_TICK_BODY_HASH_MISMATCH` — recomputed tick_body_hash does not match

### **5.4.4 Version Detection**

Implementations MUST detect tick version from the referenced profile:

```python
def validate_tick(tick, profile):
    if profile.v == 3:
        return validate_tick_v3(tick, profile)
    elif profile.v == "2":
        return validate_tick_v2(tick, profile)
    else:
        return E_PROFILE_VERSION_UNSUPPORTED
```

Version values are:

- `"2"` (string) for v2 profiles
- `3` (integer) for v3 profiles

Implementations MUST compare both type and value exactly.
Prefix or substring matching is NOT permitted.

**Epoch Clock validates artefact structure only.**

Freshness enforcement (≤ 900 seconds), monotonicity enforcement (t ≥ last_valid_tick), reuse window enforcement, and acceptance/refusal decisions are defined and enforced exclusively by PQSEC and consuming specifications.

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
   * PQSEC runtime probes
5. No developer or emergency override may extend the reuse window.
6. EmergencyTick may shorten—never extend—reuse windows.

The 900-second reuse window is a fixed security invariant of this specification and MUST NOT be altered by profile configuration, mirror configuration, or local policy.

Freshness and reuse windows expressed in seconds MUST be enforced using differences between verified `EpochTick.t` values, not system clocks.

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
* All dependent PQSF, PQHD, and PQAI time-bound operations MUST fail closed.
* Clients MUST NOT attempt to construct synthetic replacement profiles or fallback to system time.  

# **6. PROFILE GOVERNANCE & ROTATION (NORMATIVE)**
## **6.1 Rotation Authority**
The emergency_quorum field of the active Epoch Clock Profile defines the governance keys authorised to approve a new child profile.
A child profile inscription MUST include ML-DSA-65 signatures from a quorum of these governance keys.
Unless otherwise explicitly defined in the parent profile, the quorum threshold MUST be:
M = ceil(N / 2)
where N is the number of keys listed in emergency_quorum.
Clients MUST reject any child profile whose quorum signatures are missing, invalid, or insufficient to meet the threshold.

## **6.2 Rotation Triggers**
A child profile MUST be issued when any of the following conditions occur:
* suspected or confirmed compromise of the profile signing key
* cryptographic downgrade or break affecting ML-DSA-65 or the classical alt key
* nearing expiry according to rotation_schedule_seconds
* hash function compromise affecting hash_pq
* governance-approved emergency conditions that require immediate profile rotation

## **6.3 Child Profile Requirements**
A valid child profile MUST:
* include parent_profile_ref referencing the currently active profile
* follow all canonical encoding requirements in §3.6
* include quorum ML-DSA-65 signatures from governance keys
* recompute and include a valid hash_pq
* preserve the "epoch-clock" p field
* be inscribed as an independent Bitcoin Ordinal
Profiles that fail any of these requirements MUST be rejected.

## **6.4 Client Validation Rules**
When a client encounters a candidate child profile, it MUST:
1. Fetch the profile from the ordinal inscription.
2. Validate canonical encoding.
3. Validate all ML-DSA-65 governance signatures.
4. Validate quorum threshold according to §6.1.
5. Recompute and validate hash_pq.
6. Validate parent_profile_ref lineage.
7. Validate that the profile satisfies all constraints defined in this specification.
If ANY validation step fails, the child profile MUST be rejected and the system MUST FAIL_CLOSED.

## **6.5 Promotion Rules**
Once a child profile is fully validated:
* The client MUST promote it to the active profile.
* The pinned profile MUST update to the child profile.
* All cached ticks MUST be flushed.
* Mirror consensus MUST be re-evaluated under the new profile.
* A profile_rotation ledger event MUST be recorded.
* All future ticks MUST reference the new profile_ref.
No system MAY use ticks from a superseded profile beyond the normal reuse window.

## **6.6 Mirror Rotation Behaviour**
Mirrors MUST:
* detect new child-profile inscriptions,
* validate lineage, signatures, and hash_pq,
* re-canonicalise the child profile,
* begin serving ticks under the new profile only after full validation,
* broadcast a deterministic rotation event.
If mirrors disagree on profile promotion, clients MUST treat this as mirror divergence and FAIL_CLOSED until consensus is restored.

## **6.7 Emergency Rotation**
Under emergency-governance conditions:

* classical signatures MUST be ignored where they conflict with PQ signatures,
* only ML-DSA-65 signatures MAY be considered authoritative for profile rotation,
* the emergency quorum MAY rotate profile keys immediately,
* mirrors MUST update without delay once a valid rotated profile is available,
* clients MUST accept the rotated profile only after full signature and lineage validation.

EmergencyTicks MUST obey all normal tick-validation rules except those explicitly bypassed under emergency governance authority as defined in this section.


## **6.8 Issuer Key Compromise Response (Normative)**

In the event of suspected or confirmed compromise of an Epoch Clock tick signing key, the emergency governance authority MAY issue a CompromiseRevocationNotice.

```json
{
  "spec":                "epoch-clock.compromise-revocation",
  "v":                   1,
  "profile_ref":         "ordinal:<txid>i<N>",
  "suspect_from_unix":   0,
  "suspect_until_unix":  0,
  "issued_unix":         0,
  "suite_profile":       "tstr",
  "gov_sigs":            [GovSig]
}
```

**GovSig** structure:

```json
{
  "signer_id":   "tstr",
  "sig":         "base64url"
}
```

Where `signer_id` is an identifier corresponding to a governance member listed in the referenced profile's governance set (v2: `emergency_quorum`, v3: `governance_members`), and `sig` is an ML-DSA-65 signature (base64url).

### 6.8.1 Signature Authority

**Signing Preimage:**

Each governance signature in `gov_sigs` MUST be computed as follows:

```
notice_body       = notice minus gov_sigs
notice_body_bytes = JCS(notice_body)
notice_hash       = SHAKE256-256("EpochClock-CompromiseNotice-v1" || notice_body_bytes)
gov_sig           = ML-DSA-65-SIGN(gov_privkey, notice_hash)
```

Verification MUST recompute `notice_hash` identically and verify each `gov_sig` against the governance member's public key.

**Signature Requirements:**

1. A CompromiseRevocationNotice MUST be signed by the emergency governance authority of the referenced profile.
2. For v2 profiles, signatures MUST satisfy the emergency quorum threshold defined for the profile's `emergency_quorum` governance (default: `M = ceil(N / 2)` unless otherwise specified by the profile governance rules).
3. For v3 profiles, signatures MUST satisfy the `governance_threshold` over the active `governance_members` set.
4. Signatures under the compromised tick signing key MUST be rejected. The tick signing key (`pubkey_pq` in v2, tick signing keys in v3) is not a governance key and MUST NOT be accepted for CompromiseRevocationNotice validation.
5. Any CompromiseRevocationNotice whose signatures do not satisfy the applicable governance threshold MUST be rejected.

### 6.8.2 Client Behaviour

1. Upon accepting a CompromiseRevocationNotice, clients MUST treat any ticks with `t` in the suspect range (`suspect_from_unix` ≤ `t` ≤ `suspect_until_unix`) as untrusted for Authoritative operations.
2. Suspect-range evaluation is consumed by PQSEC (and other consumers) during evidence-chain validation, not during tick structural validation. A tick that was previously accepted as structurally valid does not retroactively fail tick validation. The enforcement decisions that referenced it become suspect. This preserves the monotonicity invariant: a tick's structural validity does not change after acceptance.
3. For Authoritative operations, consumers MUST enter fail-closed behaviour until a fresh evaluation is performed under a non-compromised profile or using ticks outside the suspect range.

### 6.8.3 Storage

Clients MUST persist accepted CompromiseRevocationNotice artefacts in an append-only store, ordered by `issued_unix`. Removal of revocation entries MUST NOT be permitted.

### 6.8.4 Limitation

This mechanism enables containment and auditing. It does not provide retroactive correction for already-executed operations. Any operations whose enforcement decisions were made using ticks in the suspect range and which have already been executed cannot be reversed by this mechanism.

### 6.8.5 Implementation Guidance

Implementations SHOULD expose a query primitive:

```
is_tick_suspect(t_unix) → boolean
```

This primitive is consumed during evidence-chain evaluation. It MUST NOT be called during tick structural validation. The tick validator continues to report structural and signature validity. Consumers add the provenance check: "the tick signing key is trusted for the time window in which this tick was issued."

Mirrors SHOULD serve CompromiseRevocationNotice artefacts alongside ticks and include them in reconciliation responses so clients do not require a separate discovery channel.


# **7. CONSENT AND POLICY ENFORCEMENT (NORMATIVE)**
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
The Epoch Clock validates the following structural and cryptographic properties of a tick:
structurally_valid_tick = (
    signature_valid
    AND profile_ref_correct
    AND canonical_encoding_valid
    AND mirror_consensus
)
Enforcement of freshness, monotonicity, and operational refusal semantics is defined exclusively by PQSEC and consuming specifications.

7.8 Consent & Policy Failure Modes
The Epoch Clock contributes:
* E_TICK_EXPIRED
* E_TICK_INVALID
* E_TICK_DIVERGENCE
* E_PROFILE_MISMATCH
* E_HASH_MISMATCH
All downstream systems MUST interpret these as immediate fail-closed.

# **8. LEDGER AND AUDIT (NORMATIVE)**

The Epoch Clock does not maintain its own ledger; this section defines the rules for how dependent systems MUST record tick usage.

8.1 Ledger Structure and Object Model

PQSF, PQHD, and PQAI MUST commit all tick-binding events into their local Merkle ledger exactly as defined in PQSF §19 (Merkle Ledger Serialisation) and PQHD §16 (Ledger Authority). Every ledger entry involving time MUST include:

{
  "event":           tstr,
  "epoch_tick":      EpochTick,
  "tick_validated":  uint,
  "payload":         opaque_payload,
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
* OS drift detections (via PQSEC runtime predicates)

8.2 Merkle Construction

Ledger rules follow PQHD §16 (Ledger Authority):

The 0x00 and 0x01 prefixes serve as Merkle domain separators and are distinct from the textual domain separation labels defined in §3.5. They MUST be applied exactly as shown and MUST NOT be replaced with textual domain strings.

* leaf_hash = SHAKE256-256(0x00 || canonical_entry)
* node_hash = SHAKE256-256(0x01 || left_hash || right_hash)

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

PQHD multisig and PQSEC runtime systems require tick-aligned reconciliation:

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


# **9. OPERATIONAL RULES (NORMATIVE)**

All operational refusal semantics described in this section are normatively enforced by PQSEC and consuming specifications. Epoch Clock defines state conditions only.

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
Stealth Mode requires:
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
* PQHD/PQAI freeze after expiry
* ledger stays local
* profile cannot rotate
9.5 Recovery Mode
Recovery capsules MUST:
* embed the tick at creation
* refuse activation under stale tick conditions
* verify tick + profile_ref
* sync ticks before key or state reconstruction
### 9.6 Export / Import
Continuity Capsule exports MUST:
* include tick range
* bind capsule metadata to tick
* verify tick during import
* recompute ledger roots
### 9.7 Migration
Migration envelopes MAY include:
* validity windows
* tick_created
* tick_expiry
* policy snapshots
* ledger snapshots
### 9.8 Identity Operations
Expired ticks MUST block:
* identity retrieval
* vault access
* credential generation
### 9.9 AI Operations
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

---

## 9A. Offline Degradation Semantics (Normative)

### 9A.1 Purpose

This section defines formal degradation behaviour when fresh ticks
are unavailable. It provides a deterministic, auditable model for
graceful degradation that preserves human sovereignty while
preventing operations under uncertain time.

### 9A.2 Staleness Model

Staleness is measured exclusively in Epoch Clock ticks.

```
tick_age = current_verified_tick − last_verified_tick
```

Two policy-defined thresholds govern degradation:

```
STALE_WARN_TICKS    (default: 2)
STALE_HARD_TICKS    (default: 3)
```

Constraints:

1. STALE_WARN_TICKS MUST be less than STALE_HARD_TICKS
2. Defaults apply if policy does not override
3. Policy MUST NOT set STALE_WARN_TICKS to 0
4. Policy MUST NOT set STALE_HARD_TICKS less than or equal to
   STALE_WARN_TICKS

> **Informative note:** With the default Epoch Clock tick interval
> of 60 seconds, STALE_WARN_TICKS = 2 corresponds to approximately
> 2 minutes, and STALE_HARD_TICKS = 3 corresponds to approximately
> 3 minutes. This note MUST NOT be referenced by enforcement logic.

### 9A.3 Freshness States

Three freshness states are defined.

#### FRESH

```
tick_age ≤ STALE_WARN_TICKS
```

All operations proceed normally.
All predicates evaluate as usual.

#### STALE_WARN

```
STALE_WARN_TICKS < tick_age ≤ STALE_HARD_TICKS
```

- Consuming enforcement specifications (e.g. PQSEC) MUST treat this state as requiring refusal of Authoritative operations
- Non-authoritative operations MAY proceed at the consuming specification's discretion
- The holder SHOULD surface a staleness warning to the human
- All operations SHOULD be logged as operating under degraded time

#### STALE_HARD

```
tick_age > STALE_HARD_TICKS
```

- Consuming enforcement specifications MUST treat this state as requiring refusal of all operations
- No distinction between authoritative and non-authoritative
- System enters inert mode pending reconnection

### Default Staleness Thresholds (Normative)

Unless explicitly overridden by active policy or consuming specification configuration, implementations SHOULD apply the following default staleness thresholds:

- `STALE_WARN` at **2 × tick_interval_seconds**
- `STALE_HARD` at **3 × tick_interval_seconds**

These defaults define the baseline degradation posture only. Policies MAY tighten these thresholds but MUST NOT relax them for Authoritative operations.

### 9A.4 No-Tick Mode (Offline)

If no verified tick is available at all:

#### Human-side state (PQPS Part A)

- MUST remain readable
- MUST remain inspectable
- MUST remain editable
- MUST NOT be treated as stale or invalid

Human-side state belongs to the human. It is not
time-sensitive evidence.

#### AI-side state (PQPS Part B)

- MUST be suspended
- MUST NOT be read by the runtime
- MUST NOT be updated
- MUST NOT influence AI behaviour

AI-side state is time-bounded, drift-controlled, and
enforcement-dependent. Without time authority, it cannot
be safely consumed.

#### Operations

- Authoritative operations MUST refuse
- Non-authoritative operations MAY proceed only if they do not:
  - consume AI-side state
  - emit time-dependent artefacts
  - claim freshness or validity

### 9A.5 Reconnection Semantics

When a fresh tick becomes available after any degraded or
offline period, the following steps are mandatory before
normal operation resumes.

#### 1. Tick reconciliation

- Verify monotonicity against last known tick
- Reject rollback
- If monotonicity cannot be established, fail closed

#### 2. Offline period audit

Record the following in tamper-evident storage:

- Start tick (or "unknown" if no tick was available)
- End tick (the reconnection tick)
- Operations attempted during degraded mode
- Operations refused during degraded mode

The audit record MUST be immutable once written.

#### 3. AI-side state revalidation

AI-side state remains suspended until:

- A fresh tick is verified
- Drift controls are re-evaluated against current tick
- Holder policy allows resumption

#### 4. No retroactive authority

Operations that were refused during degraded mode:

- MUST NOT be retroactively validated
- MUST NOT be automatically re-executed
- MUST be re-requested explicitly by the human

#### 5. State transition

The system exits STALE_WARN, STALE_HARD, or OFFLINE mode
only after all of the above steps complete successfully.
Partial completion MUST NOT restore normal operation.

### 9A.6 Cross-Specification Alignment

- Epoch Clock defines the staleness model and freshness states
- PQSEC enforces refusal semantics based on those states
- PQPS consumes the model to allow Part A access and suspend
  Part B access during degraded or offline operation
- No specification invents its own notion of "offline" or "stale"

One time model. One authority.

### 9A.7 Authority Boundary

This section defines degradation behaviour only.
It does not grant authority, modify enforcement semantics,
or create new predicate types.

All enforcement decisions remain exclusively within PQSEC.

---

# **10. SECURITY CONSIDERATIONS (INFORMATIVE)**

## **10.1 Cryptographic Security**
Based on:
* ML-DSA-65 signatures
* SHAKE256 canonical hashing
* JCS Canonical JSON encoding
* Bitcoin inscription anchoring
* multi-mirror consensus
* strict lineage
## **10.2 Transport Security**
Tick delivery may use:
* PQSF hybrid TLS
* TLSE-EMP
* STP sovereign transport
## **10.3 Application Layer Security**
Provides:
* deterministic consent windows
* replay-safe sessions
* tick-bound PSBT signing
* safe offline/Stealth Mode operation
## **10.4 Replay Protection**
Replay is prevented by:
* signature-bound ticks
* monotonicity
* freshness window
* profile lineage
* deterministic encoding
## **10.5 Attack Surface Reduction**
Eliminates:
* NTP poisoning
* DNS dependency
* local-clock rollback
* cloud time injection
* cross-session replay
## **10.6 OS/Runtime Integrity**
Runtime integrity probes (consumed via PQSEC predicates) timestamp:
* kernel/patch freshness
* integrity scans
* policy reload windows

# **11. QUANTUM THREAT MODEL & MITIGATIONS (INFORMATIVE)**

## **11.1 Shor's Algorithm Mitigation**
ML-DSA-65 signatures protect:
* profile signatures
* tick signatures
* rotation signatures
## **11.2 Grover's Algorithm Mitigation**
SHAKE256-256 → quantum-safe hashing. hash_pq remains secure under quadratic speed-ups.
## **11.3 Forgery Mitigation**
Mirror consensus + deterministic encoding make forgeries infeasible.
## **11.4 PQ KEM Attacks**
ML-KEM optional; does not affect tick validation.
## **11.5 Hybrid Downgrade Attacks**
Epoch Clock v2 forbids classical-only signature modes. All signatures MUST be PQ or PQ+classical.
## **11.6 Time Manipulation**
Prevented by:
* signature enforcement
* monotonic validation
* lineage
* tick reuse limits
## **11.7 PQ-Only Emergency Mode**

Under emergency-governance conditions where a PQ-only mode has been authorised:

* classical signatures MUST be ignored,
* only ML-DSA-65 signatures MAY be used for profile and tick validation,
* emergency quorum actions MAY rotate profile keys into a PQ-only configuration,
* mirrors MUST publish and serve the PQ-only profile without delay once fully validated,
* clients MUST record PQ-only profiles and transitions in their ledgers for auditability.

PQ-only emergency mode does not alter any other validation rules; all normal tick, profile, lineage, and mirror-consensus requirements continue to apply.


# **12. PRIVACY CONSIDERATIONS (INFORMATIVE)**

## **12.1 User Sovereignty**
Epoch Clock is:
* decentralised
* mirror-distributed
* non-cloud
* offline-capable
* P2P-friendly
Users are not dependent on any central authority for time.
## **12.2 Selective Disclosure**
Ticks reveal no:
* user identity
* device identity
* location
* metadata
## **12.3 Device Privacy & Anti-Fingerprinting**
Mirrors MUST NOT emit:
* device identifiers
* request-specific metadata
* per-client variation
## **12.4 Metadata Minimisation**
Ticks carry only:
* time t
* profile_ref
* signature
Mirrors MUST NOT attach additional metadata.
## **12.5 No Cross-Domain Correlation**
Ticks cannot be used for:
* tracking
* cross-service identification
* behavioural fingerprinting
## **12.6 Offline-First Privacy**
Offline reuse:
* avoids remote lookup
* eliminates DNS dependency
* reduces observable behaviour
## **12.7 Policy & Consent Privacy**
Tick-bound consent metadata remains local to PQSF/PQHD systems.
## **12.8 Ledger Privacy**
Ledgers MUST NOT contain:
* PII
* device fingerprints
* IPs or hostnames

# **13. IMPROVEMENTS OVER EXISTING SYSTEMS (INFORMATIVE)**

## **13.1 Weaknesses of Legacy Time**
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
## **13.2 Improvements Introduced**
Epoch Clock v2 provides:
* cryptographically signed time
* deterministic monotonicity
* offline guarantees
* Stealth Mode safety
* replay resistance
* canonical encoding
* zero reliance on system clocks
## **13.3 Threats Eliminated**
* NTP poisoning
* clock rollback
* downgrade attacks
* timestamp replay
* tick forgery
* cross-session replay
## **13.4 Threats Reduced**
* mirror compromise
* connectivity loss
* profile forgery
## **13.5 Guarantees Introduced**
Time becomes:
* provable
* verifiable
* global
* post-quantum
* immutable
* sovereign

## **13.6 Comparison Table**

| Operational Aspect        | Traditional Air-Gapped Wallets               | PQHD Stealth Mode                                                 |
| :------------------------ | :------------------------------------------- | :---------------------------------------------------------------- |
| **Time Validation**       | Local system clock (untrusted, spoofable)    | **EpochTick** with strict ≤900-second reuse window                |
| **Transaction Freshness** | No guaranteed freshness or replay boundaries | Tick-enforced freshness; replay-impossible PSBT windows           |
| **Multi-Device Sync**     | Manual PSBT comparison; inconsistent state   | **STP** transport + deterministic Merkle ledger reconciliation    |
| **Policy Enforcement**    | Limited or absent; no temporal guarantees    | Full **ClockLock** semantics enforced offline                     |
| **Exit Safety**           | Minimal validation before reconnecting       | Requires fresh ticks, runtime attestation, and ledger reconciliation |
| **Emergency Handling**    | None; no governance layer                    | Guardian-assisted recovery + tick-verified emergency rotation     |


# **14. DETAILED BACKWARDS COMPATIBILITY (INFORMATIVE)**

## **14.1 Bitcoin / UTXO Compatibility**
Epoch Clock uses:
* standard inscriptions
* witness data
* no consensus changes
* no miner cooperation required
## **14.2 Classical Compatibility**
Dual-signature profile fields allow smooth migration from classical systems.
## **14.3 PQSF Compatibility**
Epoch Clock v2 is compatible with PQSF v1.0.0:
* profile lineage
* canonical encoding
* tick semantics
* session rules
## **14.4 PQHD Compatibility**
PQHD depends on:
* policy enforcement time
* key-derivation tick windows
* delayed recovery
* Stealth Mode rules
* Secure Import validation
## **14.5 Runtime Attestation Compatibility (via PQSEC)**
Runtime integrity drift logs (consumed via PQSEC predicates) MUST contain fresh ticks.
## **14.6 PQAI Compatibility**
PQAI uses ticks to structure:
* drift boundaries
* session reset rules
* provenance chains
## **14.7 Offline / Air-Gapped Compatibility**
Epoch Clock explicitly supports these deployments without system clock fallback.

# **15. IMPLEMENTATION NOTES (INFORMATIVE)**

## **15.1 Developer Guidance**
* validate canonical encoding before signature checks
* cache ticks respecting reuse windows
* reject synthetic timestamps
* enforce monotonicity
* pin the active profile
## **15.2 Integration Tips**
* treat ticks as authoritative
* canonicalisation MUST be byte-stable
* freeze if freshness uncertain
## **15.3 Performance Considerations**
SHAKE256 costs are trivial; tick verification is negligible.
## **15.4 Testing Notes**
Test:
* stale ticks
* hash mismatches
* signature mismatches
* lineage transitions
* canonicalisation divergence
* mirror divergence
## **15.5 Reference Implementations**
Rust, Python, Go, JS/WASM are viable reference implementations.
## **15.6 Recommended Libraries**
* SHAKE256 (RustCrypto, libsodium, BoringSSL)
* ML-DSA-65
* JCS Canonical JSON (RFC 8785 implementations)
## **15.7 Edge Cases**
* boundary reuse window expiry
* mirror disagreement
* rotation during Stealth Mode
* encoding mismatch due to Unicode
## **15.8 Performance & Scaling**

# **16. REGISTRY / IDENTIFIER CONSIDERATIONS (OPTIONAL)**

## **16.1 Algorithm Identifiers**
* ML-DSA-65
* ECDSA-P256 (optional fallback)
* shake-256-256:<hex>
## **16.2 Error Code Registry**
Prefixes:
* E_TICK_*
* E_PROFILE_*
* E_MIRROR_*
* E_CANONICAL_*
* E_SIG_*
* E_HASH_*
## **16.3 Domain Strings**
* "EpochClock-Profile-v2"
* "EpochClock-Tick-v2"

# **17. CONFORMANCE REQUIREMENTS (NORMATIVE)**

## **17.1 Conformance Levels**
MVP (L1) Full (L2) High-Assurance (L3)

## **17.2 MUST / SHOULD / MAY Rules**
* MUST validate signature
* MUST validate hash_pq
* MUST enforce reuse window
* MUST reject synthetic ticks
* SHOULD implement caching
* MAY implement ML-KEM for encrypted mirror transport
## **17.3 Test Vectors**
Tick example:
{
  "t": 1730000000,
  "profile_ref": "ordinal:<txid:iN>",
  "alg": "ML-DSA-65",
  "sig": "<signature>"
}
Full test vector suite under:
/test-vectors/epoch-clock/
## **17.4 Interoperability Requirements**
* MUST accept JCS Canonical JSON
* MUST reject non-canonical JSON
* MUST NOT accept CBOR for Epoch Clock artefacts
* MUST agree on hash_pq bit-for-bit
* mirrors MUST converge under majority
## **17.5 Certification Process**
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
  "hash_pq": "shake-256-256:c9756c5646201220b10660a6ecc72dacede6ce7bd51b199500066783eafa47fd458c1d74f2e679f812ce4466ae01320449ece0170783b3bb1be09cade8ad061a",
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

* JCS Canonical JSON encoding variations
* signature verification failures
* hash_pq recomputation accuracy
* profile lineage validation
* mirror consensus divergence scenarios
  
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

# Annexes 

## **Annex H — Canonical Profile Anchor and Inspection Mirrors**

Canonical profile reference:
ordinal:439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0

Explorers for human inspection only:
https://ordinals.com/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
https://bestinslot.xyz/ordinals/inscription/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0
https://www.ord.io/439d7ab1972803dd984bf7d5f05af6d9f369cf52197440e6dda1d9a2ef59b6ebi0

---

## **Annex I — Time Binding (Informative)**

### I.1 Purpose

This appendix defines how Epoch Clock time artefacts are bound to enforcement and evidence across the ecosystem.

### I.2 Time Binding Fields

All time-sensitive artefacts across the ecosystem use these standard fields:

| Field | Type | Description |
|-------|------|-------------|
| `issued_tick` | uint | The Epoch Clock tick at which the artefact was created |
| `epoch_clock_hash` | bstr (32 bytes) | SHAKE256-256 hash of the Epoch Clock artefact that defines the tick |

**Relationship:**
```
epoch_clock_hash = SHAKE256-256(canonical_epoch_clock_artefact_bytes)
```

The Epoch Clock artefact at a given tick provides:
- The tick number
- The Bitcoin block hash anchoring that tick
- The timestamp bounds

### I.3 Encoding Rules

**Critical requirement:** Epoch Clock artefacts MUST NOT be re-encoded or transformed by consuming specifications.

If JCS (JSON Canonicalization Scheme) is used for the inscribed artefact:
- Consumers MUST handle the JCS-encoded bytes without modification
- Consumers MUST NOT re-serialize to CBOR or other formats for hashing
- The `epoch_clock_hash` MUST be computed over the exact bytes as inscribed

### I.4 Freshness Evaluation

To evaluate freshness of an artefact:

1. Obtain the current Epoch Clock tick from a trusted source
2. Compare `issued_tick` against the current tick
3. If `issued_tick + freshness_window < current_tick`, the artefact is stale

Freshness windows are policy-defined and vary by artefact type.

### I.4.1 v3 Threshold Validation (Normative)

For Epoch Clock v3 and later profiles, clients MUST validate tick artefacts under the active profile, including threshold tick signature requirements (`tick_sig_threshold`).

Unvalidated ticks MUST NOT be used for freshness evaluation.

Epoch Clock verification MAY require multi-signature threshold validation as defined by the active Epoch Clock profile. Receipts referencing `epoch_clock_hash` MUST be rejected if the referenced tick artefact fails profile validation.

### I.5 Authority Boundary

Time binding provides temporal evidence only.

**Time binding MUST NOT grant authority.** The fact that an artefact was issued at a particular time does not imply permission to act.

Time binding enables:
- Freshness checks
- Expiry enforcement
- Replay detection
- Ordering verification

Time binding does not enable:
- Authority escalation
- Policy bypass
- Enforcement override

---

## Changelog

### Version 2.1.0

### Added

* **Profile v3 schema** with multi-signature governance and threshold tick validation.
* **Tick v3 multi-signature format** (`tick_sigs`, `tick_body_hash`, threshold validation).
* Content-addressed identifiers:

  * `governance_config_id`
  * `tick_keyset_id`
* Explicit **Profile signature preimage rules**.
* **Version detection rules** (v2 vs v3 profiles and ticks).
* **Genesis profile defaults** for backward compatibility.
* **CompromiseRevocationNotice** structure and issuer key compromise response.
* Expanded mirror reconciliation and state-machine behaviour.
* Formalised error-code registry (including v3-specific refusal codes).
* Offline degradation semantics (9A) with defined staleness thresholds.
* Clarified Strict Unix Time base for `t`.
* Explicit SHAKE256 output length requirement (32 bytes).
* Sovereign deployment and bootstrap hardening language.

### Changed

* Status updated to **STABLE / INSCRIBED**.
* Canonical profile reference formalised in §1.2A.
* Expanded integration guidance across PQSF, PQSEC, PQHD, PQAI.
* Strengthened fail-closed semantics for mirror divergence and lineage mismatch.
* Clarified authority boundaries (time artefacts only; enforcement external).
* Tightened canonical encoding requirements (JCS only, no CBOR).
* Strengthened mirror identity verification requirements.

### Unchanged

* Core v2 profile structure and canonical inscription.
* ML-DSA-65 as required signature algorithm.
* SHAKE256-256 hashing.
* 900-second tick reuse window.
* Mirror-majority validation requirement.
* No consensus-layer changes.
* Refusal-only enforcement model.

---

If you find this work useful and wish to support continued development, donations are welcome:

**Bitcoin:**
bc1q380874ggwuavgldrsyqzzn9zmvvldkrs8aygkw
