#!/usr/bin/env bash
set -euo pipefail

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rss-candidate-manifest.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

manifest="$test_root/candidate-bundle.json"
policy=".github/candidate-manifest-policy.jq"
revision='0123456789abcdef0123456789abcdef01234567'

write_valid() {
  jq -n --arg revision "$revision" '{
    schemaVersion: 2,
    rssRevision: $revision,
    artifactSelector: {
      workflow: "candidate-bundle.yml",
      runId: 42,
      runAttempt: 1,
      artifactName: ("rss-candidate-bundle-" + $revision + "-42-1")
    },
    packages: [{
      name: "rss-contract",
      version: "0.1.0",
      checksum: ("a" * 64)
    }],
    profiles: [{
      state: "candidate",
      profile: "core",
      assembly: "runtime",
      configDigest: ("sha256:" + ("b" * 64)),
      assemblyLockDigest: ("sha256:" + ("c" * 64)),
      runtimePlanFingerprint: ("sha256:" + ("d" * 64)),
      image: {
        archive: "profiles/core/server.oci",
        archiveSha256: ("sha256:" + ("e" * 64)),
        imageDigest: ("sha256:" + ("f" * 64)),
        migrationArchive: "profiles/core/migrator.oci",
        migrationArchiveSha256: ("sha256:" + ("1" * 64)),
        migrationImageDigest: ("sha256:" + ("2" * 64))
      },
      closure: {
        listeners: ["admin-main", "health-main"],
        routes: ["audit.list-tenant-entries", "runtime.inventory"],
        providers: ["auth-audit-sink", "listener-pdp", "listener-rate-limiter"],
        workers: ["audit-localtx"],
        probes: ["rls_ready"],
        forbiddenProviders: ["dlx-archive-store", "event-publisher", "event-subscriber"]
      }
    }]
  }' > "$manifest"
}

assert_rejected() {
  if jq -e --arg revision "$revision" -f "$policy" "$manifest" >/dev/null 2>&1; then
    echo "candidate manifest policy accepted invalid case: $1" >&2
    exit 1
  fi
}

write_valid
jq -e --arg revision "$revision" -f "$policy" "$manifest" >/dev/null

write_valid
jq '.schemaVersion = 1' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'legacy v1 bundle'

write_valid
jq '.profiles[0].state = "active"' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'active profile is not candidate evidence'

write_valid
jq '.artifactSelector.artifactName = "mutable"' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'selector identity mismatch'

write_valid
jq '.profiles[0].closure.providers += ["event-publisher"] | .profiles[0].closure.providers |= sort' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'Core Eventing extra'

write_valid
jq '.profiles[0].closure.probes = []' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'vacuous Core probe set'

for collection in listeners routes providers workers probes forbiddenProviders; do
  write_valid
  jq --arg collection "$collection" \
    '.profiles[0].closure[$collection] += [.profiles[0].closure[$collection][0]]' \
    "$manifest" > "$manifest.tmp"
  mv "$manifest.tmp" "$manifest"
  assert_rejected "duplicate Core $collection"

  write_valid
  jq --arg collection "$collection" \
    '.profiles[0].closure[$collection] += ["zz-test"] |
     .profiles[0].closure[$collection] |= (sort | reverse)' \
    "$manifest" > "$manifest.tmp"
  mv "$manifest.tmp" "$manifest"
  assert_rejected "unsorted Core $collection"
done
