#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <candidate-bundle-dir> <rss-revision> <transport-root>" >&2
  exit 64
fi

bundle="$1"
revision="$2"
transport_root="$3"
repository="$(/usr/bin/git rev-parse --show-toplevel)"
manifest="$bundle/candidate-bundle.json"

[[ "$bundle" = /* && -d "$bundle" && ! -L "$bundle" ]] || {
  echo "candidate bundle must be an absolute real directory" >&2
  exit 1
}
[[ "$transport_root" = /* && ! -e "$transport_root" ]] || {
  echo "candidate transport root must be an unused absolute path" >&2
  exit 1
}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || {
  echo "candidate RSS revision is malformed" >&2
  exit 1
}

jq -e --arg revision "$revision" \
  -f "$repository/.github/candidate-manifest-policy.jq" \
  "$manifest" >/dev/null

mkdir -p "$transport_root"
registry="$transport_root/registry"
cp -R "$bundle/registry" "$registry"
jq -cn --arg dl "file://$registry/crates/{crate}/{version}/download" \
  '{dl: $dl}' > "$registry/index/config.json"
env \
  GIT_AUTHOR_NAME='RSS candidate transport' \
  GIT_AUTHOR_EMAIL='candidate@invalid' \
  GIT_COMMITTER_NAME='RSS candidate transport' \
  GIT_COMMITTER_EMAIL='candidate@invalid' \
  /usr/bin/git -C "$registry/index" init -q
/usr/bin/git -C "$registry/index" add .
env \
  GIT_AUTHOR_NAME='RSS candidate transport' \
  GIT_AUTHOR_EMAIL='candidate@invalid' \
  GIT_COMMITTER_NAME='RSS candidate transport' \
  GIT_COMMITTER_EMAIL='candidate@invalid' \
  /usr/bin/git -C "$registry/index" commit -qm 'candidate registry transport'

cargo_home="$transport_root/cargo-home"
mkdir -p "$cargo_home"
printf '%s\n' \
  '[source.rss-candidate]' \
  'registry = "https://rss-candidate.invalid/index"' \
  'replace-with = "rss-candidate-local"' \
  '' \
  '[source.rss-candidate-local]' \
  "registry = \"file://$registry/index\"" \
  > "$cargo_home/config.toml"

env_file="$transport_root/environment"
printf '%s\n' \
  "CARGO_HOME=$cargo_home" \
  "CARGO_TARGET_DIR=$transport_root/target" \
  "ROOT_LOCK_SHA256=$(sha256sum "$repository/Cargo.lock" | awk '{print $1}')" \
  "BUNDLE_MANIFEST=$manifest" \
  > "$env_file"
printf '%s\n' "$env_file"
