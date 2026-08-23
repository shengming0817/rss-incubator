# Rotation Control

`rotation-control` is the non-publishable JSON-only operator CLI for Azure PBI #2121. It performs
OIDC Authorization Code login with PKCE S256 for every network operation, keeps tokens only in
memory, and reaches the canonical policy/status contracts solely through
`rss-device-security-client`.

Commands:

- `login` proves issuer, JWKS signature, audience, state, nonce, expiry, and `tenantId` validation.
- `policy check --input FILE` validates a policy and reports duration and usage/SAN counts; SANs are
  never rendered.
- `rotate` submits one canonical policy PUT with caller-selected expected generation and an optional
  reusable idempotency UUID.
- `status` renders only canonical desired/observed generations, active command, and closed
  conditions. It never derives `Ready` locally.
- `audit --input FILE|-` validates and re-renders the correlation in one schema-v1 successful
  `rotate` result. It is not a server-side durable audit/history query.

Remote issuer, JWKS, token, and RSS endpoints require HTTPS. HTTP is accepted only for an OIDC
loopback redirect; tests use an injected HTTP port rather than weakening the production URL gate.
`--ca-certificate` adds an explicit private CA to the shared rustls trust store without disabling
certificate verification. Login waits at most 120 seconds; API calls wait at
most 30 seconds; every response is capped at 1 MiB. The CLI has no password grant, token argument or
persistence, automatic mutation retry, certificate/private-key output, raw provider error, or raw
response-body diagnostic.

Exit codes are stable: `0` success, `2` CLI/input, `3` authentication/authorization, `4` typed
validation/not-found/conflict, `5` transport/upstream, and `6` malformed or untrusted response.

Resource Security Facts are not seeded or diagnosed by this CLI. #2123 owns privileged disposable
fixture seeding and the live external T2 journey; a 403 remains the single public `forbidden`
diagnostic and does not reveal whether a fact was missing, stale, or denied. #2117 owns service
mounting/image delivery and does not block this CLI's mock-contract proof.
