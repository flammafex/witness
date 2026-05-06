# Security Policy

Witness is pre-1.0 software. Treat public deployments as experimental unless
you have reviewed the code, configuration, and operational controls for your
own threat model.

## Reporting Vulnerabilities

Use the repository's private vulnerability reporting channel if one is
available. If private reporting is not available, open a public issue asking
the maintainers for a private security contact and do not include exploit
details, secrets, logs, private keys, bearer tokens, or proof-of-concept code in
the public issue.

Useful reports include:

- affected commit or release
- deployment mode and relevant feature flags
- reproduction steps
- expected and actual behavior
- whether the issue affects gateway, witness node, CLI, auditor, federation,
  external anchors, Freebird verification, admin routes, or deployment assets

## Supported Versions

Until tagged stable releases exist, security fixes target the main development
branch. Operators should pin a reviewed commit or release tag and update
deliberately after reading the changelog or commit diff.

## Known Security Boundaries

Witness separates four concerns:

- witness nodes hold signing keys and sign attestations for a configured
  network only
- gateways collect threshold signatures, store attestations, expose proofs, and
  coordinate batching, federation, and external anchoring
- auditors monitor signed tree heads and consistency proofs
- clients verify threshold signatures and proof bundles against network
  configuration

Witness timestamps hashes, not content. This protects content confidentiality
only if clients hash locally and do not leak content through filenames,
transport metadata, logs, or application-specific identifiers.

## Known Limitations

- The project has not had an external security audit.
- The gateway is not a Byzantine consensus system. It produces threshold-signed
  attestations from configured witnesses.
- Gateway compromise is mitigated by independent witnesses, federation, external
  anchors, and client verification, but it is not eliminated.
- Public gateways should require Freebird or an equivalent abuse-control layer.
  Built-in IP rate limits are not sufficient for internet-scale abuse.
- Witness signing endpoints require bearer tokens, but witness nodes still
  should be reachable only from trusted gateways or private networks.
- Admin routes require an API key when enabled, but public deployments should
  also restrict them at the reverse proxy, VPN, or network-policy layer.
- Metrics are public unless `WITNESS_METRICS_TOKEN` is configured or `/metrics`
  is blocked at the reverse proxy.
- WebSocket events are public unless `WITNESS_WS_AUTH_TOKEN` is configured.
- Federation anchor routes should use `federation.inbound_auth_token` before
  accepting internet traffic.
- External anchor providers make outbound network calls. Keep the SSRF filter
  enabled and review provider URLs before deployment.
- Audit logs and gateway databases are operational records, not automatically
  tamper-evident security logs.

## Production Baseline

For an internet-exposed gateway:

- terminate TLS at a reverse proxy or load balancer
- run the gateway behind that proxy with `WITNESS_BEHIND_PROXY=true`
- keep the gateway bound to loopback or a container-internal interface when
  possible
- set high-entropy witness `auth_token` values in `network.json`
- enable Freebird with `FREEBIRD_REQUIRED=true`
- use Freebird consuming mode (`FREEBIRD_CONSUME_TOKENS=true`) for timestamp
  requests unless a specific proof-of-possession flow requires `/v1/check`
- leave `FREEBIRD_ALLOW_INSECURE_LOCAL` unset or false
- set `WITNESS_ADMIN_API_KEY` before enabling `--admin-ui`
- set `WITNESS_METRICS_TOKEN` or block `/metrics`
- set `WITNESS_WS_AUTH_TOKEN` or keep `/ws/events` intentionally public
- configure federation inbound auth tokens before enabling federation
- back up the SQLite database and deployment configuration
- pin container images or release artifacts by version or digest

See also:

- [Threat Model](docs/threat-model.md)
- [Production Deployment](PRODUCTION.md)
- [Release Packaging](docs/release.md)
- [Freebird Integration](docs/freebird-integration.md)
