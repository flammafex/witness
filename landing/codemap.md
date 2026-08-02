# landing/

## Responsibility

The project's public-facing single landing page, `index.html` — a self-contained marketing/demo page for Witness. It presents the product pitch ("Federatable anonymous quorum timestamper"), key features, how-it-works flow, and a quick-start curl snippet, and doubles as a *live attestation ticker* that connects over WebSocket to a running gateway and chimes on each new attestation. Presented under the banner of "The Carpocratian Church of Commonality & Equality" (`church.png`), which operates the public instance.

## Design

Single static HTML file (`index.html`, no build step, no JS framework). Dark monospace aesthetic driven by CSS custom properties (`--bg`, `--accent`, `--success`, etc.) in a `<style>` block. Structure:

- **Header**: `<img church.png>`, the Carpocratian Church byline, `<h1>Witness</h1>`, subtitle.
- **Live ticker**: a status dot + connection text, a big event counter, and an events list fed by a WebSocket; an inline base64-WAV `<audio>` chime plays on each event. JS (vanilla) opens `wss://gateway.metacan.org/ws/events`, parses each JSON message (`{type, timestamp, hash}`), prepends an event card, caps the list at 50 entries, and auto-reconnects every 3s on close. Note the `addEvent` path builds innerHTML from `data.type`/`data.hash` — the page assumes trusted event payloads.
- **Landing section**: `pre-1.0 · unaudited` badge; lead paragraph (content-private, accountless, N-of-M threshold signing); an 8-card features grid (quorum threshold signing, instant & free 50–150ms, content-private, accountless, dual signature schemes Ed25519/BLS12-381, external anchoring to Internet Archive/Trillian/DNS/Ethereum, federation cross-anchoring, RFC 9162 STH-chain auditability); a 4-step "How it works" flow (submit hash → batch & route → threshold sign → return/anchor); a quick-start `curl` snippet; and footer links to `README.md`, `docs/`, `SECURITY.md`, `PRODUCTION.md`, and the source repo.

## Flow

1. Visitor loads `index.html` (static, from the web root).
2. Page JS connects to `wss://gateway.metacan.org/ws/events`; dot transitions connecting → connected ("Connected to 💀 metacan.org").
3. Each incoming attestation event increments the counter, renders an event card (type, local time, hash), and plays the chime; the landing content below remains the marketing copy.

## Integration

- **WebSocket endpoint**: the ticker depends on the gateway's `/ws/events` route — the same route the nginx template (`configs/server/nginx.conf`) allowlists to `{{ADMIN_IP}}` + `{{CLIENT_IP}}`. A visitor's IP must be allowlisted at the edge for the live feed to work; the landing page itself is public.
- **README/docs links** resolve to repo-root files (`../README.md`, `../docs/`, `../SECURITY.md`, `../PRODUCTION.md`).
- **Quick-start discrepancy**: the landing page's curl example posts to `http://localhost:8080/v1/attestations`, while the nginx template and gateway route set expose the create endpoint as `/v1/timestamp`. The snippet is illustrative/local; flag if route naming is reconciled.
- Content describes features implemented across `crates/witness-core` (BLS/Ed25519, RFC 9162 proofs), `crates/witness-gateway` (batching, federation, external anchoring), and `crates/witness-auditor` (STH chains).
