# Secure Device Rotation External T2 Journey

Azure PBI #2123 owns this external consumer journey. It is a permanent member of the single Cargo
workspace and declares an exact `rss-candidate` registry dependency. The canonical candidate job
runs it from the committed root lock with Cargo locked and offline.

The positive test consumes canonical policy acceptance, command ACK, credential report, application
receipt, and status DTOs through `rss-device-security-client`. It requires one authorization
receipt and desired generation across the trace, independent ACK/report/receipt event identities,
ACK with a still-pending status, a matching committed receipt, and only then a public
`Ready=True/StateMatches` observation.

Two focused negatives remain:

- a stale Resource Security Fact fixture is represented only by the public non-retryable 403
  response and creates no local acceptance;
- the reference-agent's existing revoked-catalog test proves the private catalog-to-policy-rejected
  mapping, while this journey proves that the public rejection cannot advance the generation or
  observe Ready.

This is a reusable test whose runtime is disposable, not a deployed environment. It does not start
an RSS image, inspect RSS source or storage, derive authorization, infer Ready, query durable audit,
or claim server-side no-write, persistence, deployment readiness, production acceptance, or T3.
Consumer binaries, the candidate registry, credentials, logs, and receipt intermediates remain
runner-temporary and are not committed or uploaded.
