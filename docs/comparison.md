# Witness vs. Alternatives

A survey of the closest alternatives to Witness, focused on self-hostable and/or
open-source systems. Maintained as reference material; update when the
landscape changes materially.

## TL;DR

**No direct alternative exists.** Witness occupies a unique niche: a
self-hostable, open-source, accountless, content-private, **quorum
threshold-signed** timestamper with instant latency and optional multi-anchor
external anchoring. The closest analogues each cover a subset of its feature
space, but none combine all of: instant threshold signatures + federation +
multi-anchor anchoring + accountless + content-private + self-hostable.

---

## Landscape at a Glance

| Project | License | Self-Host? | Mechanism | Trust Model | Content-Private | Accountless | Quorum/Threshold | External Anchors | Active? |
|---|---|---|---|---|---|---|---|---|---|
| **Witness** | Apache-2.0 | Yes | Ed25519/BLS12-381 threshold sig + RFC 9162 STH | Federated quorum (m-of-n) | Yes (hash only) | Yes | **Yes (per-attestation)** | Internet Archive, Trillian, DNS, Ethereum | Yes (v0.6.0) |
| **OpenTimestamps** | LGPL-3.0 | Yes | Bitcoin OP_RETURN + Merkle aggregation | Bitcoin PoW (trust-minimized) | Yes | Yes | No | Bitcoin (core); Litecoin, Ethereum (partial) | Yes |
| **Sigstore Rekor** | Apache-2.0 | Yes | RFC 6962 Merkle transparency log | Single log operator | Yes | No (OIDC for signing) | No (witness co-signing of checkpoints only) | RFC 3161 TSA | Yes (GA, v2) |
| **Sigstore TSA** | Apache-2.0 | Yes | RFC 3161 (X.509/PKI) | Centralized TSA | Yes | Yes | No | No | Yes |
| **Trillian / Tessera** | Apache-2.0 | Yes | RFC 6962 / C2SP tlog-tiles Merkle log | Single log operator | Configurable | N/A (library) | Witness co-signing of checkpoints (Tessera) | No | Yes |
| **Chainpoint/Tierion** | AGPL-3.0 | Yes | Tendermint calendar chain + Bitcoin anchoring | BFT consensus among Cores | Yes | Yes | Partial (BFT for calendar state, not per-timestamp) | Bitcoin, Ethereum | **Stagnant** (~2022) |
| **OriginStamp** | Proprietary | Partial (client hashing only) | Bitcoin/Ethereum anchoring | Centralized SaaS | Yes | No (API key) | No | Bitcoin, Ethereum | Yes (commercial) |
| **Proof of Existence** | MIT / unclear | Yes | Bitcoin OP_RETURN (1 tx/doc) | Bitcoin PoW | Yes | Yes | No | Bitcoin | **Defunct** (last release 2019) |
| **Bloock** | MIT (SDKs only) | No | Multi-chain anchoring | Centralized SaaS | Yes | No (API key) | No | Ethereum, private chains | Yes (commercial) |
| **FreeTSA** | Not OSS | No | RFC 3161 | Centralized TSA | Yes | Yes | No | No | Yes |
| **Open TSA** | MIT | Yes | RFC 3161 | Centralized TSA | Yes | Yes | No | No | New (Apr 2026) |
| **DigiStamp** | Proprietary | Partial (HSM appliance) | RFC 3161 + RFC 6283 | Centralized TSA (HSM) | Yes | No (account) | No | No | Yes (20+ yrs) |

---

## The Closest Comparisons

### 1. OpenTimestamps — closest in *spirit*, different in *mechanism*

The most credible open-source alternative for trust-minimized timestamping.
Clients submit hashes to calendar servers, which aggregate them into Merkle
trees and anchor roots to Bitcoin via `OP_RETURN`. Verification is
trust-minimized (Bitcoin PoW).

**Where it beats Witness:** No operator trust required at all — security
derives from Bitcoin's hash rate. Mature, battle-tested, multi-language
clients.

**Where it differs fundamentally:**

- **Latency:** Timestamps are only complete after a Bitcoin block confirms
  (~10 min). Witness returns a threshold-signed attestation in 50–150ms.
- **Trust model:** Bitcoin PoW consensus vs. federated threshold signatures.
  These are philosophically opposite — OTS trusts no one but the chain;
  Witness trusts that *enough* independent witnesses won't collude.
- **No threshold signing:** OTS has no per-timestamp multi-party signature.
  Calendar servers are trusted only for availability, not integrity.
- **No federation cross-anchoring.** Multiple calendars can be queried
  client-side for redundancy, but there's no cryptographic federation protocol.
- **Single anchor** (Bitcoin; Litecoin/Ethereum only for creation, not
  verification).

### 2. Sigstore (Rekor + TSA) — closest in *infrastructure quality*, different in *purpose*

Sigstore is the most mature open-source transparency-log and RFC 3161
ecosystem, backed by the Linux Foundation. Rekor provides RFC 6962 Merkle
logs with inclusion proofs; the TSA provides RFC 3161 tokens.

**Where it's strong:** Production-grade, audited, widely adopted in software
supply chains. Rekor v2 supports checkpoint co-signing by witnesses.
Self-hostable with Helm/Docker.

**Where it differs:**

- **Not accountless:** The signing workflow requires OIDC identity (GitHub,
  Google, etc.).
- **No per-entry threshold signing:** Rekor's witness protocol co-signs *log
  checkpoints* for consistency, not individual timestamps. A compromised log
  operator can still issue fraudulent entries before detection.
- **Single-operator trust per log instance** — no federated quorum over
  individual attestations.
- **Designed for software signing**, not general-purpose content timestamping.

### 3. Chainpoint/Tierion — closest in *architecture*, but defunct

Chainpoint was architecturally the most similar: a distributed network of
Gateways and Cores, Merkle aggregation, Tendermint BFT consensus among Cores,
and Bitcoin/Ethereum anchoring.

**Why it's not a real alternative:** The project appears effectively dead (last
releases ~2020–2022). The Tendermint BFT consensus operated on the *Calendar
chain state*, not on individual timestamps — there was no per-attestation
threshold signature. AGPL-3.0 licensing may also be restrictive.

### 4. RFC 3161 TSAs (Sigstore TSA, Open TSA, FreeTSA, DigiStamp, dnl50/tsa)

The traditional standard for cryptographic timestamping. Several are
open-source and self-hostable (Sigstore TSA in Go is the most mature; Open TSA
and dnl50/tsa are simpler).

**Fundamental difference:** All are **centralized single-operator** services.
A compromised TSA key can forge arbitrary timestamps. There's no quorum, no
federation, no external anchoring. They're the thing Witness's README FAQ
explicitly contrasts itself against: *"Traditional TSAs require trusting a
single party. Witness requires multiple independent parties to collude."*

### 5. Trillian / Tessera — building blocks, not alternatives

Google's Merkle log infrastructure (Trillian v1, Tessera v2). These are
*substrates* — you build a "personality" on top. Notably, **Witness already
uses Trillian as an external anchor target**, so they're complementary, not
competitive. Tessera adds witness checkpoint co-signing, but again at the log
level, not per-entry.

---

## What No Alternative Combines

| Capability | Witness | Any single alternative? |
|---|---|---|
| Per-attestation threshold signing (m-of-n) | ✅ Ed25519 + BLS12-381 | ❌ None |
| Instant timestamps (50–150ms) | ✅ | ❌ (OTS ~10min; RFC 3161 TSAs ~100ms but centralized) |
| Federation cross-anchoring | ✅ | ❌ None |
| Multi-anchor external anchoring | ✅ IA, Trillian, DNS, Ethereum | Partial (OTS=Bitcoin; Chainpoint=BTC+ETH) |
| Accountless + content-private + quorum | ✅ all three | ❌ No project combines all three |
| Self-hostable + open-source + threshold | ✅ | ❌ None |
| RFC 9162 STH chains with independent auditor | ✅ | Partial (Trillian/Tessera/Rekor — infrastructure only) |

---

## Honest Caveats

- **Witness is pre-1.0, unaudited, and not Byzantine-fault-tolerant.** Its
  threshold-signing model mitigates (not eliminates) gateway compromise, and
  it has had no external security audit. OpenTimestamps, by contrast, derives
  its security from Bitcoin's hash rate — a far more battle-tested trust
  model.
- **Trust model is philosophically different from OTS.** Witness trades
  "trust no one, wait 10 minutes" for "trust that N independent operators
  won't collude, get instant results." Which is "better" depends entirely on
  your threat model and whether you can assemble a trustworthy federation.
- **Sigstore is far more mature and audited** for software-supply-chain use
  cases. If your goal is signing artifacts rather than general content
  timestamping, Sigstore is the stronger choice.

---

## Recommendations by Use Case

| If you need… | Use |
|---|---|
| Trust-minimized timestamping, no operator trust, can wait ~10 min | **OpenTimestamps** |
| Self-hostable RFC 3161 TSA (centralized is acceptable) | **Sigstore TSA** (Go) or **Open TSA** (new) |
| Software supply-chain transparency logging | **Sigstore Rekor** |
| Merkle log infrastructure to build on | **Tessera** (modern) or **Trillian** (stable) |
| Federated quorum threshold-signed *instant* timestamps with external anchoring, accountless and content-private | **Witness** (the only option in this space) |
