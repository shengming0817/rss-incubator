#!/usr/bin/env bash
set -euo pipefail

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rss-candidate-manifest.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

manifest="$test_root/candidate-bundle.json"
policy=".github/candidate-manifest-policy.jq"
revision='0123456789abcdef0123456789abcdef01234567'

write_valid() {
  jq -n --arg revision "$revision" '{
    schemaVersion: 1,
    rssRevision: $revision,
    packages: [{
      name: "rss-contract",
      version: "0.1.0",
      checksum: ("a" * 64)
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

jq '.unexpectedTopLevel = true' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'unknown top-level field'

write_valid
jq '.packages[0].unexpectedPackageField = true' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'unknown package field'

write_valid
jq 'del(.packages[0].checksum)' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'missing package field'

write_valid
jq '.packages = []' "$manifest" > "$manifest.tmp"
mv "$manifest.tmp" "$manifest"
assert_rejected 'empty package set'
