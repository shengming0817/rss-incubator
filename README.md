# rss-incubator

`rss-incubator` is the first-party RSS product-incubation repository, with an independent source,
workspace, and lifecycle boundary. It is not the RSS source workspace, an RSS Product Surface, an
official profile, or the owner of production acceptance.

The current `crates/rss-consumer-smoke` package is a non-publishable Tokio/Tower smoke that jointly
consumes `rss-diag-context` and `rss-trace-context`. It proves only that this product-consumption seam
works; it is not an accepted product, an official profile, a maturity claim, or a production gate.

## Incubating products

The [Secure Device Credential Rotation](docs/secure-device-credential-rotation.md) skeleton is an
accepted incubation scope. Its `rotation-model` package contains only transport-neutral product
correlation and observation facts. The future registry client, control CLI, reference device agent,
reference deployment, and external T2 journey retain separate implementation owners.

The rotation product does not absorb `rss-consumer-smoke`. The observability smoke remains an
independent compatibility proof and supplies no identity, authorization, or device-state authority.

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
RSS release correctness, RC status, maturity, or publish approval. The ADR-026 ownership cutover is
complete: this repository owns the consumer proof and RSS retains the Release Surface artifact proof.

## Local verification

The committed root `Cargo.lock` is the single dependency resolution for this workspace.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

GitHub Actions runs the same committed-lock matrix on every pull request and push to `main`. The
workflow also runs the candidate-proof policy tests before compiling the workspace.

## Candidate artifact proof

RSS owns candidate archive correctness and exports a short-lived bundle only after its existing
Release Surface `package-proof` succeeds. This repository consumes that bundle with one closed
entrypoint:

```sh
python3 scripts/candidate-proof.py --bundle /absolute/path/to/rss-candidate-bundle
```

The bundle carries the complete RSS Release Surface exact-set. The proof dynamically selects the
subset directly consumed by this workspace, rewrites only a committed-HEAD temporary snapshot, and
then runs Cargo metadata, check, test, and clippy with `--locked --offline`. It rejects checksum or
archive-VCS drift, missing or extra registry entries, path/Git/workspace RSS dependencies, internal
RSS packages, and any change to the real checkout. The committed root `Cargo.lock` remains the
released baseline; the candidate lock exists only for the proof lifetime.

On a fresh runner, the proof first fetches the committed released lock and then the already-validated
local candidate registry into its isolated Cargo home. Network access is preparation only; the
candidate metadata/build/test/lint matrix is explicitly locked and offline.

Maintainers trigger the `CI` workflow manually with the exact successful RSS candidate-bundle run
ID. `RSS_ARTIFACTS_READ_TOKEN` is a fine-grained Actions secret with read-only access to the RSS
repository's workflow artifacts. The workflow derives the RSS revision, run attempt, artifact name,
and digest from that immutable run and publishes the first-green identities in the job summary.

A green candidate proof establishes only this repository's product-consumption seam. It does not
establish RSS release correctness, RC status, package maturity, publish approval, an official
profile, production acceptance, or T3 evidence. Results are linked from the owning issue or pull
request; they are not committed as receipts or copied into a second registry.
