# Threat Model

This document describes the current security model for Witness. It is not a
formal audit.

## Security Goals

Witness aims to provide:

- threshold-signed evidence that a SHA-256 hash existed at or before a stated
  time
- content privacy by accepting hashes instead of user content
- public verification of attestations against a network configuration
- secret-free distribution of the public verification configuration
- append-only log proofs for light clients and auditors
- optional cross-network federation and external anchoring for independent
  durability
- anonymous abuse control through Freebird when deployed on public gateways

## Non-Goals

Witness does not currently provide:

- proof of content authorship or ownership
- global ordering across independent Witness networks
- Byzantine consensus or finality beyond configured threshold signatures
- content confidentiality if clients upload content elsewhere or include
  identifying metadata
- anonymity against an operator who correlates IP addresses, timing, User-Agent
  strings, application identifiers, or reverse-proxy logs
- protection from timestamp spam unless Freebird or equivalent admission control
  is required
- tamper-evident operator logs outside the signed tree-head/proof model

## Assets

Important assets include:

- witness node private signing keys
- witness signing bearer tokens
- gateway SQLite databases
- gateway network configuration files
- federation inbound and outbound auth tokens
- external anchor provider credentials and private keys
- Freebird verifier configuration and trusted issuer policy
- admin API keys, metrics tokens, and WebSocket tokens
- release artifacts and container image provenance
- published SDK contents and dependency metadata

## Actors

| Actor | Capability |
| --- | --- |
| Honest client | Submits a hash and verifies the returned attestation. |
| Spam client | Attempts to create many attestations cheaply. |
| Malicious gateway | Attempts to omit data, equivocate, or expose metadata. |
| Compromised witness | Signs invalid or misleading attestations. |
| Threshold collusion | Controls enough witnesses to satisfy the network threshold. |
| Federation peer | Cross-anchors batches or submits malformed anchor requests. |
| External anchor provider | Accepts or rejects batch roots and may be unavailable. |
| Network attacker | Observes or modifies traffic when TLS/proxy policy is wrong. |
| Admin attacker | Obtains admin key/session, database access, or deployment config. |

## Assumptions

- Clients verify returned attestations against the correct network config.
- `GET /v1/network` is treated as a source for a secret-free
  `NetworkVerificationConfig`; `/v1/config` is informational and is not a trust
  anchor. Clients pin or independently review verification configs when a
  stronger trust anchor is required.
- Witness signing keys are generated with a secure RNG and stored on protected
  hosts.
- Witness bearer tokens are high entropy and not reused across unrelated
  deployments.
- Production traffic uses HTTPS at the edge.
- Reverse proxies forward client IP headers only when the gateway is configured
  with `WITNESS_BEHIND_PROXY=true`.
- Public gateways require Freebird or equivalent admission control.
- Operators back up gateway databases and configuration before upgrades.

## Privacy Model

Witness only receives SHA-256 hashes. Hash privacy depends on the entropy and
guessability of the underlying content. A hash of a public document or small
dictionary value can be guessed by anyone who knows the candidate content.

Witness does not hide network metadata. Operators and infrastructure providers
may still observe:

- source IP address
- request timing and frequency
- User-Agent or client version
- gateway account or application identifiers layered above Witness
- reverse-proxy and load-balancer logs

Freebird can make request eligibility unlinkable from issuance, but it does not
hide transport metadata by itself.

## SDK Wire and Release Controls

The TypeScript SDK uses `lossless-json` for HTTP responses, request bodies,
WebSocket events, and WASM JSON inputs. Generated Rust `u64` fields are
`number | bigint`; safe integers remain numbers while larger exact values
through `u64::MAX` remain exact bigints. Unsafe JavaScript numbers and invalid
u64 values are rejected. This prevents precision loss from changing a signed
attestation or log position before local verification. The explicit
`AttestationSignatures` decoder rejects partial and ambiguous multi-sig/BLS
union shapes rather than relying on implicit JSON-schema coercion.

Hash values emitted or echoed by the SDK are canonical lowercase hex. This is a
representation guarantee, not a substitute for cryptographic verification.
WebSocket `auth_required` challenges without a token stop reconnecting and
raise `AuthRequiredError`; authenticated connections reply within the server
window, and close/abort cancels reconnect timers.

The npm package is public but pre-1.0 and unaudited. Its release gate runs
build, tests, typecheck, the authoritative generation-drift script, and
`npm pack --dry-run`; the dry-run file list must be reviewed for secrets,
generated local state, and missing WASM. Publishing does not imply a security
audit or Byzantine-fault tolerance.

## Federation Security Boundaries

Federation adds independently signed cross-anchors for batch roots. A
`Federated` verification result requires valid signatures from the configured
peer networks, the configured peer threshold, and caller-supplied peer
`NetworkVerificationConfig`s. Missing or unavailable peers reduce the achieved
verification level. Federation improves independent durability, but does not
provide Byzantine consensus or protect against collusion by enough witnesses or
operators.

## Replay And Abuse Model

The gateway has per-IP rate limits as a defense-in-depth control. Public
gateways should not rely on this alone. Freebird consuming mode calls
`/v1/verify`, which records the token nullifier and rejects reuse. Non-consuming
mode calls `/v1/check`, which validates possession but does not prevent token
reuse.

Use non-consuming mode only when the surrounding application has another replay
or rate-control boundary.

## Current High-Priority Gaps

- external cryptographic and protocol audit
- CI gates for formatting, clippy, tests, and release builds
- signed release artifacts and image provenance
- public API schemas and versioned test vectors
- end-to-end integration tests against current Freebird V4 and V5 verifier
  flows
- clearer operator guidance for federation token rotation
