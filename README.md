# RSS standalone consumer

First-party Plain Rust consumer for the experimental `rss-diag-context` and
`rss-trace-context` candidates. It proves their joint Tokio/Tower/tracing seam without RSS
Platform, runtime, providers, workspace paths, or publication automation.

The canonical verification owner is the RSS repository's `cargo xtask package-proof`. That command
injects same-revision `.crate` artifacts through an ephemeral local registry, calls
`scripts/upgrade-candidates.sh`, generates this repository's independent lockfile, and then runs all
checks with `--locked --offline`. A successful proof means candidate consumption works; it is not an
RC, registry upload, or release approval.

## Ownership

Repository custody: `ghbvf`. Maintenance: `github:shengming0817:rss-maintainers`.
Security reports follow the private channel documented by the canonical RSS repository.
