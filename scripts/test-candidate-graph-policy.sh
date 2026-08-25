#!/usr/bin/env bash
set -euo pipefail

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rss-candidate-graph.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

manifest="$test_root/candidate-bundle.json"
metadata="$test_root/metadata.json"
policy=".github/candidate-graph-policy.jq"
candidate_source='registry+https://rss-candidate.invalid/index'

jq -n '{packages: [
  {name: "rss-contract", version: "0.1.0"},
  {name: "rss-platform", version: "0.1.0"}
]}' > "$manifest"

write_metadata() {
  jq -n --arg source "$candidate_source" '{
    workspace_members: [
      "path+file:///workspace#rotation-model@0.0.0",
      "path+file:///workspace#rss-device-security-client@0.1.0"
    ],
    packages: [
      {id: "registry+contract", name: "rss-contract", version: "0.1.0", source: $source},
      {id: "registry+platform", name: "rss-platform", version: "0.1.0", source: $source},
      {
        id: "path+file:///workspace#rotation-model@0.0.0",
        name: "rotation-model",
        version: "0.0.0",
        source: null,
        publish: [],
        dependencies: [{name: "uuid", source: "registry+https://github.com/rust-lang/crates.io-index", path: null}]
      },
      {id: "path+file:///workspace#rss-device-security-client@0.1.0", name: "rss-device-security-client", version: "0.1.0", source: null}
    ]
  }' > "$metadata"
}

assert_rejected() {
  if jq -e --slurpfile bundle "$manifest" -f "$policy" "$metadata" >/dev/null 2>&1; then
    echo "candidate graph policy accepted invalid case: $1" >&2
    exit 1
  fi
}

write_metadata
jq -e --slurpfile bundle "$manifest" -f "$policy" "$metadata" >/dev/null

jq 'del(.packages[] | select(.name == "rss-platform"))' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'missing producer package'

write_metadata
jq '(.packages[] | select(.name == "rss-contract")) |=
  (.id = "path+file:///workspace#rss-contract@0.1.0" | .source = null) |
  .workspace_members += ["path+file:///workspace#rss-contract@0.1.0"]' \
  "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'workspace shadow of producer package'

write_metadata
jq '.packages += [{
  id: "git+https://invalid/rss-rogue",
  name: "rss-rogue",
  version: "0.1.0",
  source: "git+https://invalid/rss-rogue"
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'undeclared external RSS package'

write_metadata
jq '.packages += [{
  id: "git+https://invalid/rss_rogue",
  name: "rss_rogue",
  version: "0.1.0",
  source: "git+https://invalid/rss_rogue"
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'underscore undeclared external RSS package'

write_metadata
jq '.packages += [{
  id: "git+https://invalid/rss_platform",
  name: "rss_platform",
  version: "0.1.0",
  source: "git+https://invalid/rss_platform"
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'underscore alias of declared RSS package'

write_metadata
jq '(.packages[] | select(.name == "rss-platform")).source =
  "registry+https://index.crates.io/"' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'wrong registry source'

write_metadata
jq 'del(.packages[] | select(.name == "rotation-model"))' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'missing rotation-model workspace package'

write_metadata
jq '(.packages[] | select(.name == "rotation-model")).publish = null' \
  "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'publishable rotation-model package'

write_metadata
jq '(.packages[] | select(.name == "rotation-model")).dependencies += [{
  name: "rss_contract",
  source: "registry+https://rss-candidate.invalid/index",
  path: null
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'rotation-model RSS coupling'

write_metadata
jq '(.packages[] | select(.name == "rotation-model")).dependencies += [{
  name: "reqwest",
  source: "registry+https://github.com/rust-lang/crates.io-index",
  path: null
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'rotation-model transport coupling'

write_metadata
jq '(.packages[] | select(.name == "rotation-model")).dependencies += [{
  name: "helper",
  source: null,
  path: "/workspace/helper"
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'rotation-model path coupling'

write_metadata
jq '(.packages[] | select(.name == "rotation-model")).dependencies += [{
  name: "helper",
  source: "git+https://example.invalid/helper#deadbeef",
  path: null
}]' "$metadata" > "$metadata.tmp"
mv "$metadata.tmp" "$metadata"
assert_rejected 'rotation-model Git coupling'
