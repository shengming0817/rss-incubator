# rss-incubator

`rss-incubator` is the first-party RSS product-incubation repository, with an independent source,
workspace, and lifecycle boundary. It is not the RSS source workspace, an RSS Product Surface, an
official profile, or the owner of production acceptance.

The non-publishable `crates/rss-consumer-smoke` package jointly consumes `rss-diag-context` and
`rss-trace-context`. The non-publishable `crates/platform-authoring-smoke` package directly consumes
`rss-contract`, `rss-request-context`, and Platform vNext, authors a typed contract and asynchronous
handler, and exercises product-owned host admission. Together they prove only that these external
product-consumption seams work; they are not accepted products, official profiles, maturity claims,
or production gates.

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

## Local policy verification

The committed root `Cargo.lock` is the single dependency resolution for this workspace. Before the
Platform candidate packages are published, the regular workspace excludes only
`platform-authoring-smoke`; the candidate proof atomically re-enrolls it only in its isolated
snapshot. A fresh clone and the pull-request/push lane run:

```sh
cargo fmt --all -- --check
find crates/platform-authoring-smoke -type f -name '*.rs' -exec rustfmt --edition 2024 --check {} +
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The complete workspace matrix requires an exact candidate bundle and runs only through the closed
proof entrypoint described below. After the prerequisite job checks formatting on the real checkout,
the proof executes the equivalent of the following inside its temporary snapshot:

```text
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

GitHub Actions runs the policy, formatting, check, test, documentation, and lint gates for the
regular workspace on every pull request and push to `main`. The three Platform candidate packages
are intentionally absent from crates.io, so those events must not resolve
`platform-authoring-smoke`. A manual candidate run uses the exact immutable RSS bundle, activates
that excluded member only in its temporary snapshot, and delegates the complete workspace metadata,
build, test, and lint execution to the isolated candidate-proof job.

## Candidate artifact proof

RSS owns candidate archive correctness and exports a short-lived bundle only after its existing
Release Surface `package-proof` succeeds. This repository consumes that bundle with one closed
entrypoint:

```sh
python3 scripts/candidate-proof.py --bundle /absolute/path/to/rss-candidate-bundle
```

The bundle carries the complete RSS Release Surface exact-set. Before Cargo resolution, the proof
statically discovers the subset directly consumed by this workspace, rewrites only a committed-HEAD
temporary snapshot, and then runs Cargo metadata, check, test, and clippy with `--locked --offline`.
It rejects checksum or
archive-VCS drift, missing or extra registry entries, path/Git/workspace RSS dependencies, internal
RSS packages, and any change to the real checkout. The committed root `Cargo.lock` remains the
released baseline; the candidate lock exists only for the proof lifetime.

On a fresh runner, the proof starts from the committed baseline lock and preserves every existing
non-RSS registry identity. Any newly required non-RSS identity must be proven reachable from an RSS
candidate package in Cargo's resolved dependency graph; unrelated lock additions fail closed. A
stable logical candidate source is mapped to the already-validated local registry, so temporary
filesystem paths never enter the candidate lock. The candidate metadata/build/test/lint matrix is
explicitly locked and offline; the real checkout and committed baseline lock remain unchanged.

Maintainers trigger the `CI` workflow manually with the exact successful RSS candidate-bundle run
ID. `RSS_ARTIFACTS_READ_TOKEN` is a fine-grained Actions secret with read-only access to the RSS
repository's workflow artifacts. The workflow derives the RSS revision, run attempt, artifact name,
and digest from that immutable run. The job summary publishes both canonical run URLs, both commits,
artifact identity and digest, the dynamic package exact-set with checksums and verified archive VCS,
the consumed set, candidate-lock digest, registry-only result, and locked/offline matrix result.

A green candidate proof establishes only this repository's product-consumption seam. It does not
establish RSS release correctness, RC status, package maturity, publish approval, an official
profile, production acceptance, or T3 evidence. Results are linked from the owning issue or pull
request; they are not committed as receipts or copied into a second registry.
