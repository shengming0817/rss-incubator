# Contributing

Changes must preserve `rss-incubator` as an independent product-incubation boundary.

## Product scope

A new product crate requires an accepted product or capability scope, a named owner, behavior tests,
and an explicit release and incubation-exit plan. Do not create empty crates for prospective MDM,
zero-trust, device-security, tenant-organization, or other products. A normal pull request must not
self-declare a crate mature, official, production-ready, an official profile, or T3 evidence.

Product graduation requires a separate scope, ADR, and PBI that closes product identity, capability
ownership, maintenance and security, SemVer, release and upgrade policy, data migration, operations,
and rollback. Graduation may use only stable RSS Release Surface artifacts and must not depend on RSS
internal or T3 surfaces.

## Dependency and architecture rules

- Consume RSS only as a released registry artifact or an immutable, exact-version candidate pinned
  with checksum and source revision by an incubator-owned proof.
- Do not add RSS path, Git, workspace, submodule, vendored, internal, generated, provider-catalog,
  runtime-plan, test-fixture, or governance dependencies.
- Do not copy RSS domains, adapters, assembly, provider/SPI surfaces, selectors, fixtures, `xtask`
  gates, evidence systems, closeout machinery, required-status handshakes, or release control planes.
- Keep each product's ownership, tests, release path, rollback, and security response in this
  repository.

## Verification

Run the workspace commands below before requesting review:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```
