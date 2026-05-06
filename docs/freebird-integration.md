# Freebird Integration

Witness can use Freebird verifier tokens as anonymous admission control for
`POST /v1/timestamp`.

## Current Contract

Witness targets the current Freebird verifier contract:

| Method | Path | Use |
| --- | --- | --- |
| `GET` | `/.well-known/verifier` | Verifier ID, audience, and V4 scope digest. |
| `POST` | `/v1/verify` | Validate and consume a V4 or V5 token. Reuse is rejected. |
| `POST` | `/v1/check` | Validate a V4 or V5 token without consuming it. |

Verifier requests contain:

```json
{
  "token_b64": "<base64url-freebird-token>"
}
```

The Freebird verifier derives token version, issuer, expiry, audience/scope,
and nullifier state from the token and its issuer key discovery configuration.
Witness accepts token files with exactly the current Freebird verifier input:
`token_b64`.

## Gateway Configuration

```bash
export FREEBIRD_VERIFIER_URL=https://freebird-verifier.example.org
export FREEBIRD_REQUIRED=true
export FREEBIRD_CONSUME_TOKENS=true
```

`FREEBIRD_REQUIRED=true` rejects timestamp requests that do not include a token.
This should be the default for public gateways.

`FREEBIRD_CONSUME_TOKENS=true` uses `/v1/verify` and prevents token reuse. This
is the recommended mode for timestamp creation.

`FREEBIRD_CONSUME_TOKENS=false` uses `/v1/check`. This proves token possession
without consuming the token, so it must be paired with another replay or rate
limit boundary.

Issuer trust, key discovery, expiry, and V4/V5 audience or scope checks belong
in the Freebird verifier. Witness does not duplicate that policy.

For local integration tests only, set:

```bash
export FREEBIRD_ALLOW_INSECURE_LOCAL=true
```

This permits a plaintext loopback verifier URL. It rejects non-loopback hosts
and should never be used for a public gateway.

## Client Request Shape

Timestamp requests may include a Freebird token:

```json
{
  "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "freebird_token": {
    "token_b64": "<base64url-freebird-token>"
  }
}
```

The CLI can load the same JSON shape:

```bash
witness timestamp --file document.pdf --freebird-token token.json
```

## Production Notes

- Run the Freebird verifier over HTTPS.
- Use verifier-side trusted issuer/key discovery for V4 and V5.
- Use Redis-backed Freebird nullifier storage for public verifiers.
- Keep Witness and Freebird clocks synchronized.
- Prefer short-lived tokens for high-volume public gateways.
- Test both V4 private-verification tokens and V5 public bearer passes before
  claiming full Freebird compatibility.

## Compatibility Checklist

- [ ] Token file with only `token_b64` parses in `witness-cli`.
- [ ] Gateway sends only `token_b64` to `/v1/verify` or `/v1/check`.
- [ ] Consuming mode rejects a reused token.
- [ ] Non-consuming mode allows a token to be checked and later consumed.
- [ ] V4 tokens are accepted when bound to the verifier scope digest.
- [ ] V5 public bearer tokens are accepted when the verifier trusts the issuer
      public key and audience.

## Smoke Test

When the Freebird repository is checked out next to Witness, run:

```bash
./scripts/freebird-witness-smoke.sh
```

The script starts a local Freebird issuer/verifier, issues a current
`token_b64` token, starts a local Witness network with Freebird required, and
timestamps a hash through the Witness CLI.
