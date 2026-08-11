# rss-incubator

`rss-incubator` is the first-party RSS product-incubation repository, with an independent source,
workspace, and lifecycle boundary. It is not the RSS source workspace, an RSS Product Surface, an
official profile, or the owner of production acceptance.

The current `crates/rss-consumer-smoke` package is a non-publishable Tokio/Tower smoke that jointly
consumes `rss-diag-context` and `rss-trace-context`. It proves only that this product-consumption seam
works; it is not an accepted product, an official profile, a maturity claim, or a production gate.

## Ownership

| Boundary | Owner responsibilities |
| --- | --- |
| RSS | Release Surface and API, SemVer, package metadata and artifact correctness, plus fix, yank, and release approval |
| `rss-incubator` | Workspace, source, root lockfile, product build and CI, dependency upgrades and candidate pins, rollback, and product security response |

## Dependency boundary

Products may consume RSS only through immutable released artifacts, or through an exact candidate
version whose checksum and source revision are pinned by an incubator-owned proof. RSS dependencies
must not use path, Git, workspace, submodule, vendored, internal, generated, provider-catalog, runtime
plan, test-fixture, or governance surfaces.

A candidate proof establishes only this repository's product-consumption seam. It does not establish
RSS release correctness, RC status, maturity, or publish approval. Until Azure PBI 2095 establishes the
incubator-owned CI and candidate first-green, the ADR-026 legacy carrier remains transitional; this
change does not perform that cutover.

## Local verification

The committed root `Cargo.lock` is the single dependency resolution for this workspace.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```
