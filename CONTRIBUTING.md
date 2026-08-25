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

- Consume RSS only as a released registry artifact or an immutable, exact-version candidate bound
  to the RSS producer's package proof and public candidate manifest.
- Do not add RSS path, Git, workspace, submodule, vendored, internal, generated, provider-catalog,
  runtime-plan, test-fixture, or governance dependencies.
- Do not copy RSS domains, adapters, assembly, provider/SPI surfaces, selectors, fixtures, `xtask`
  gates, evidence systems, closeout machinery, required-status handshakes, or release control planes.
- Keep each product's ownership, tests, release path, rollback, and security response in this
  repository.

## Verification

Run repository-owned checks before requesting review:

```sh
cargo fmt --all -- --check
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
bash scripts/test-candidate-graph-policy.sh
```

The canonical candidate-consumption job is the only full matrix. It binds the immutable producer
artifact, materializes the temporary registry transport, and then runs locked/offline check, test,
doc, clippy, coverage, release builds, and the external T2 journey over the complete workspace.
