#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 <bundle> <archive-field> <archive-digest-field> <image-digest-field> <expected-path> <entrypoint>" >&2
  exit 64
fi

bundle="$1"
archive_field="$2"
archive_digest_field="$3"
image_digest_field="$4"
expected_path="$5"
entrypoint="$6"
manifest="$bundle/candidate-bundle.json"

fail() {
  echo "Core candidate OCI verification failed: $1" >&2
  exit 1
}

[[ "$bundle" = /* && -d "$bundle" && ! -L "$bundle" && -f "$manifest" && ! -L "$manifest" ]] ||
  fail "bundle must be an absolute real directory with a plain manifest"

archive_relative="$(jq -er --arg field "$archive_field" '.profiles[0].image[$field]' "$manifest")" ||
  fail "archive field is missing"
[[ "$archive_relative" == "$expected_path" ]] || fail "archive path is not canonical"
archive="$bundle/$archive_relative"
[[ -f "$archive" && ! -L "$archive" ]] || fail "archive is missing or not a plain file"

expected_archive="$(jq -er --arg field "$archive_digest_field" '.profiles[0].image[$field]' "$manifest")" ||
  fail "archive digest field is missing"
actual_archive="sha256:$(sha256sum "$archive" | awk '{print $1}')"
[[ "$actual_archive" == "$expected_archive" ]] || fail "archive digest differs"

layout="$(mktemp -d "${TMPDIR:-/tmp}/rss-core-oci.XXXXXX")"
trap 'rm -rf "$layout"' EXIT
python3 - "$archive" "$layout" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
layout = pathlib.Path(sys.argv[2])
seen = set()
with tarfile.open(archive, "r:*") as source:
    members = source.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (not member.name or path.is_absolute() or ".." in path.parts or
                member.name in seen or not (member.isfile() or member.isdir())):
            raise SystemExit("Core candidate OCI archive contains an unsafe member")
        seen.add(member.name)
    source.extractall(layout, members=members, filter="data")
PY

[[ -f "$layout/oci-layout" && ! -L "$layout/oci-layout" ]] || fail "oci-layout is missing"
[[ -f "$layout/index.json" && ! -L "$layout/index.json" ]] || fail "index.json is missing"
jq -e '.imageLayoutVersion == "1.0.0" and (keys | sort) == ["imageLayoutVersion"]' \
  "$layout/oci-layout" >/dev/null || fail "OCI layout version is invalid"

expected_image="$(jq -er --arg field "$image_digest_field" '.profiles[0].image[$field]' "$manifest")" ||
  fail "image digest field is missing"
descriptor="$(jq -ce '
  if .schemaVersion == 2 and
     (.manifests | type == "array" and length == 1) and
     .manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json" and
     (.manifests[0].digest | test("^sha256:[0-9a-f]{64}$"))
  then .manifests[0] else error("invalid OCI index") end
' "$layout/index.json")" || fail "OCI index is invalid"
manifest_digest="$(jq -er '.digest' <<< "$descriptor")"
[[ "$manifest_digest" == "$expected_image" ]] || fail "image digest differs from bundle binding"
manifest_hex="${manifest_digest#sha256:}"
image_manifest="$layout/blobs/sha256/$manifest_hex"
[[ -f "$image_manifest" && ! -L "$image_manifest" ]] || fail "image manifest blob is missing"
[[ "$(sha256sum "$image_manifest" | awk '{print $1}')" == "$manifest_hex" ]] ||
  fail "image manifest blob digest differs"

config_digest="$(jq -er '
  if .schemaVersion == 2 and
     .mediaType == "application/vnd.oci.image.manifest.v1+json" and
     .config.mediaType == "application/vnd.oci.image.config.v1+json" and
     (.config.digest | test("^sha256:[0-9a-f]{64}$"))
  then .config.digest else error("invalid OCI manifest") end
' "$image_manifest")" || fail "OCI image manifest is invalid"
config_hex="${config_digest#sha256:}"
config="$layout/blobs/sha256/$config_hex"
[[ -f "$config" && ! -L "$config" ]] || fail "image config blob is missing"
[[ "$(sha256sum "$config" | awk '{print $1}')" == "$config_hex" ]] ||
  fail "image config blob digest differs"

jq -e --arg entrypoint "$entrypoint" '
  (.config.User | type == "string" and length > 0) and
  ((.config.User | split(":")) as $identity |
    ($identity | length) >= 1 and ($identity | length) <= 2 and
    all($identity[]; test("^[1-9][0-9]*$"))) and
  .config.Entrypoint == [$entrypoint]
' "$config" >/dev/null || fail "image config must use the exact non-root entrypoint"

docker image load --input "$archive" >/dev/null
image_id="sha256:$config_hex"
docker image inspect "$image_id" >/dev/null || fail "loaded image identity is unavailable"
docker image inspect "$image_id" | jq -e --arg entrypoint "$entrypoint" '
  .[0].Config.User as $raw |
  ($raw | type == "string" and length > 0) and
  (($raw | split(":")) as $identity |
    ($identity | length) >= 1 and ($identity | length) <= 2 and
    all($identity[]; test("^[1-9][0-9]*$"))) and
  .[0].Config.Entrypoint == [$entrypoint]
' >/dev/null || fail "loaded image must retain the exact non-root entrypoint"

printf '%s\n' "$image_id"
