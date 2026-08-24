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

The non-publishable `crates/rss-device-security-client` package is the minimal external T2 mapping
seam for the canonical device-security contract candidate. It owns no network, authentication,
authorization, retry, readiness, or device-state behavior.

## Incubating products

The [Secure Device Credential Rotation](docs/secure-device-credential-rotation.md) product is an
accepted incubation scope. Its `rotation-model` package contains transport-neutral product
correlation and observation facts. Its non-publishable
[`rotation-control`](apps/rotation-control/README.md) binary provides the PKCE/HTTP policy and
status control surface. The product-specific
[`reference-device-agent`](apps/reference-device-agent/README.md) implements the narrow mTLS MQTT
device boundary; the public mapping client, control CLI, reference deployment, and external T2
journey retain separate implementation owners.

The rotation product does not absorb `rss-consumer-smoke`. The observability smoke remains an
independent compatibility proof and supplies no identity, authorization, or device-state authority.

`fixtures/rss-conformance-consumer` is a non-publishable workspace member with one exact
`rss-candidate` registry dependency. Its tests run all five provider-neutral LocalTx behaviors
through the same root lock and canonical candidate-consumption job as every other product consumer.

## Ownership

| Boundary | Owner responsibilities |
| --- | --- |
| RSS | Release Surface and API, SemVer, package metadata and artifact correctness, plus fix, yank, and release approval |
| `rss-incubator` | Workspace, source, root lockfile, product build and CI, dependency upgrades and candidate pins, rollback, and product security response |

## Dependency boundary

Products may consume RSS only through immutable released artifacts, or through an exact candidate
version whose producer run, digest, checksum, and source revision are pinned by incubator CI. RSS dependencies
must not use path, Git, workspace, submodule, vendored, internal, generated, provider-catalog, runtime
plan, test-fixture, or governance surfaces.

A candidate-consumption result establishes only this repository's product seam. RSS alone owns
Release Surface selection, `.crate`/index/checksum/VCS correctness, and package proof. Incubator
binds that immutable producer result and lets Cargo validate the packages it actually resolves; it
does not reopen archives or implement a second package-format validator.

## Local policy verification

The committed root `Cargo.lock` is the single dependency resolution for every normal and candidate
workspace member. Cargo resolves that workspace as one graph, so Rust build and test commands require
the exact pinned candidate transport; only the canonical CI job materializes it. There is no smaller
fallback graph or local source path.

The disposable Secure Device Rotation provider environment has one lifecycle entrypoint. It creates
all credentials under the ignored `deploy/.state/<project>` directory and binds published ports to
loopback only:

```sh
python3 scripts/reference-environment.py smoke
```

See [`deploy/README.md`](deploy/README.md) for individual lifecycle commands, failure diagnosis, and
the environment's External/T2-only acceptance boundary.

```sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
cargo fmt --all -- --check
```

The complete workspace matrix requires the exact pinned candidate bundle and runs only in the
canonical GitHub Actions candidate-consumption job:

```text
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

GitHub Actions first runs repository policy and formatting gates. It then downloads the configured
immutable RSS candidate artifact, materializes only its runner-local Cargo transport, and runs
metadata, build, test, lint, coverage, journey, and release-binary gates over the complete workspace.

## Candidate artifact consumption

RSS exports a short-lived bundle only after its Release Surface `package-proof` succeeds. Incubator
reads the producer manifest to bind the successful run, revision, artifact identity, digest, and
package coordinates. It does not inspect `.crate` contents, reconstruct registry index entries,
recompute archive checksums, or read archive VCS metadata.

Every RSS dependency is declared with an exact version and the stable `rss-candidate` registry.
The CI job maps that logical source to the downloaded runner-local registry, executes
`cargo fetch --locked`, and then runs metadata, check, test, doctest, clippy, and coverage locked and
offline. Cargo's resolved graph must show every non-workspace `rss-*` package at the producer-declared
version and the one logical registry source. The committed root lock and checkout must remain byte
unchanged throughout the job.

The `CI` workflow reads its successful RSS candidate-bundle identity from the reviewed
`.github/rss-candidate.json` pin on pull requests and pushes. A manual dispatch may repeat that exact
run ID but cannot select another run; the workflow never resolves a mutable latest-successful run.
`RSS_ARTIFACTS_READ_TOKEN` is a fine-grained Actions secret with read-only access to the RSS
repository's workflow artifacts. The workflow derives the RSS revision, run attempt, artifact name,
and digest from that immutable run. After all gates pass, the job summary publishes one breaking
schema-v2 receipt containing both canonical run URLs and commits, artifact identity, producer-proven
package coordinates and archive VCS revision, the Cargo-consumed exact-set, root-lock digest,
registry-only result, locked/offline matrix, and release-binary checksums.

A green candidate-consumption job also runs the
[Secure Device Rotation external T2 journey](journeys/secure-device-rotation/README.md) against the
exact public contracts candidate and builds both consumer binaries. The binaries, candidate
registry, manifest, logs, and test state remain runner-temporary and are not uploaded or committed.

A green candidate-consumption job establishes only this repository's product seam. It does not
establish RSS release correctness, RC status, package maturity, publish approval, an official
profile, production acceptance, or T3 evidence. Results are linked from the owning issue or pull
request; they are not committed as receipts or copied into a second registry.
