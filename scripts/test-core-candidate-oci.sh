#!/usr/bin/env bash
set -euo pipefail

test_root="$(mktemp -d "${TMPDIR:-/tmp}/rss-core-oci-test.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/bin" "$test_root/bundle/profiles/core"

cat > "$test_root/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "image load" ]]; then
  exit 0
fi
if [[ "$1 $2" == "image inspect" ]]; then
  printf '[{"Config":{"User":"%s","Entrypoint":["%s"]}}]\n' \
    "${RSS_TEST_DOCKER_USER:?}" "${RSS_TEST_DOCKER_ENTRYPOINT:?}"
  exit 0
fi
exit 64
SH
chmod +x "$test_root/bin/docker"

cat > "$test_root/bin/skopeo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 3 && "$1" == copy && "$2" == oci-archive:* && "$3" == docker-archive:* ]]
archive="${3#docker-archive:}"
: > "$archive"
SH
chmod +x "$test_root/bin/skopeo"

make_fixture() {
  local user="$1"
  local unsafe_kind="${2:-plain}"
  local image_entrypoint="${3:-/usr/local/bin/server}"
  python3 - "$test_root/bundle" "$user" "$unsafe_kind" "$image_entrypoint" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

bundle = pathlib.Path(sys.argv[1])
user = sys.argv[2]
unsafe_kind = sys.argv[3]
image_entrypoint = sys.argv[4]
layout = bundle.parent / "layout"
if layout.exists():
    for path in sorted(layout.rglob("*"), reverse=True):
        path.unlink() if path.is_file() or path.is_symlink() else path.rmdir()
else:
    layout.mkdir()
(layout / "blobs/sha256").mkdir(parents=True)

def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

config = encoded({"config": {"User": user, "Entrypoint": [image_entrypoint]}})
config_hex = hashlib.sha256(config).hexdigest()
(layout / "blobs/sha256" / config_hex).write_bytes(config)
manifest = encoded({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": f"sha256:{config_hex}",
    },
    "layers": [],
})
manifest_hex = hashlib.sha256(manifest).hexdigest()
(layout / "blobs/sha256" / manifest_hex).write_bytes(manifest)
(layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
(layout / "index.json").write_bytes(encoded({
    "schemaVersion": 2,
    "manifests": [{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": f"sha256:{manifest_hex}",
    }],
}))

archive = bundle / "profiles/core/server.oci"
with tarfile.open(archive, "w") as target:
    for path in sorted(layout.rglob("*")):
        target.add(path, arcname=path.relative_to(layout), recursive=False)
    if unsafe_kind == "symlink":
        member = tarfile.TarInfo("unsafe-link")
        member.type = tarfile.SYMTYPE
        member.linkname = "index.json"
        target.addfile(member)
    elif unsafe_kind == "hardlink":
        member = tarfile.TarInfo("unsafe-hardlink")
        member.type = tarfile.LNKTYPE
        member.linkname = "index.json"
        target.addfile(member)
    elif unsafe_kind == "fifo":
        member = tarfile.TarInfo("unsafe-fifo")
        member.type = tarfile.FIFOTYPE
        target.addfile(member)

archive_hex = hashlib.sha256(archive.read_bytes()).hexdigest()
(archive.parent / "migrator.oci").write_bytes(archive.read_bytes())
(bundle / "candidate-bundle.json").write_bytes(encoded({
    "profiles": [{"image": {
        "archive": "profiles/core/server.oci",
        "archiveSha256": f"sha256:{archive_hex}",
        "imageDigest": f"sha256:{manifest_hex}",
        "migrationArchive": "profiles/core/migrator.oci",
        "migrationArchiveSha256": f"sha256:{archive_hex}",
        "migrationImageDigest": f"sha256:{manifest_hex}",
    }}],
}))
PY
}

verify() {
  local expected_entrypoint="${2:-/usr/local/bin/server}"
  PATH="$test_root/bin:$PATH" RSS_TEST_DOCKER_USER="$1" \
    RSS_TEST_DOCKER_ENTRYPOINT="$expected_entrypoint" \
    scripts/verify-core-candidate-oci.sh \
      "$test_root/bundle" archive archiveSha256 imageDigest \
      profiles/core/server.oci "$expected_entrypoint" >/dev/null
}

tamper_blob() {
  python3 - "$test_root/bundle" "$1" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile
import tempfile

bundle = pathlib.Path(sys.argv[1])
kind = sys.argv[2]
archive = bundle / "profiles/core/server.oci"
with tempfile.TemporaryDirectory() as temporary:
    layout = pathlib.Path(temporary)
    with tarfile.open(archive) as source:
        source.extractall(layout, filter="data")
    index = json.loads((layout / "index.json").read_text())
    manifest_hex = index["manifests"][0]["digest"].removeprefix("sha256:")
    target = layout / "blobs/sha256" / manifest_hex
    if kind == "config":
        image_manifest = json.loads(target.read_text())
        config_hex = image_manifest["config"]["digest"].removeprefix("sha256:")
        target = layout / "blobs/sha256" / config_hex
    target.write_bytes(target.read_bytes() + b"tamper")
    with tarfile.open(archive, "w") as output:
        for path in sorted(layout.rglob("*")):
            output.add(path, arcname=path.relative_to(layout), recursive=False)
archive_digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
manifest = json.loads((bundle / "candidate-bundle.json").read_text())
manifest["profiles"][0]["image"]["archiveSha256"] = archive_digest
(bundle / "candidate-bundle.json").write_text(
    json.dumps(manifest, separators=(",", ":"), sort_keys=True)
)
PY
}

make_distinct_wrapper_fixture() {
  make_fixture '10001:10001'
  cp "$test_root/bundle/profiles/core/server.oci" "$test_root/server-distinct.oci"
  local server_archive_digest server_image_digest
  server_archive_digest="$(jq -er '.profiles[0].image.archiveSha256' \
    "$test_root/bundle/candidate-bundle.json")"
  server_image_digest="$(jq -er '.profiles[0].image.imageDigest' \
    "$test_root/bundle/candidate-bundle.json")"

  make_fixture '10001:10001' plain /usr/local/bin/rss
  cp "$test_root/server-distinct.oci" "$test_root/bundle/profiles/core/server.oci"
  jq --arg archive "$server_archive_digest" --arg image "$server_image_digest" '
    .profiles[0].image.archiveSha256 = $archive |
    .profiles[0].image.imageDigest = $image
  ' "$test_root/bundle/candidate-bundle.json" > "$test_root/bundle/manifest.tmp"
  mv "$test_root/bundle/manifest.tmp" "$test_root/bundle/candidate-bundle.json"
}

verify_migration() {
  PATH="$test_root/bin:$PATH" RSS_TEST_DOCKER_USER='10001:10001' \
    RSS_TEST_DOCKER_ENTRYPOINT=/usr/local/bin/rss \
    scripts/verify-core-candidate-migration-image.sh "$test_root/bundle" >/dev/null
}

make_fixture '10001:10001'
verify '10001:10001'

for user in root root:root toor daemon 0 0:0 000:000 10001:root; do
  make_fixture "$user"
  if verify "$user" 2>/dev/null; then
    echo "OCI verifier accepted root-equivalent user: $user" >&2
    exit 1
  fi
done

for kind in symlink hardlink fifo; do
  make_fixture '10001:10001' "$kind"
  if verify '10001:10001' 2>/dev/null; then
    echo "OCI verifier accepted unsafe tar member: $kind" >&2
    exit 1
  fi
done

make_fixture '10001:10001'
jq '.profiles[0].image.archiveSha256 = ("sha256:" + ("0" * 64))' \
  "$test_root/bundle/candidate-bundle.json" > "$test_root/bundle/manifest.tmp"
mv "$test_root/bundle/manifest.tmp" "$test_root/bundle/candidate-bundle.json"
if verify '10001:10001' 2>/dev/null; then
  echo "OCI verifier accepted an archive digest mismatch" >&2
  exit 1
fi

make_fixture '10001:10001'
jq '.profiles[0].image.imageDigest = ("sha256:" + ("0" * 64))' \
  "$test_root/bundle/candidate-bundle.json" > "$test_root/bundle/manifest.tmp"
mv "$test_root/bundle/manifest.tmp" "$test_root/bundle/candidate-bundle.json"
if verify '10001:10001' 2>/dev/null; then
  echo "OCI verifier accepted an image digest mismatch" >&2
  exit 1
fi

for blob in manifest config; do
  make_fixture '10001:10001'
  tamper_blob "$blob"
  if verify '10001:10001' 2>/dev/null; then
    echo "OCI verifier accepted a tampered $blob blob" >&2
    exit 1
  fi
done

make_fixture '10001:10001' plain /usr/local/bin/wrong
if verify '10001:10001' 2>/dev/null; then
  echo "OCI verifier accepted a wrong entrypoint" >&2
  exit 1
fi

make_distinct_wrapper_fixture
verify '10001:10001'
verify_migration

for field in migrationArchiveSha256 migrationImageDigest; do
  make_distinct_wrapper_fixture
  jq --arg field "$field" '.profiles[0].image[$field] = ("sha256:" + ("0" * 64))' \
    "$test_root/bundle/candidate-bundle.json" > "$test_root/bundle/manifest.tmp"
  mv "$test_root/bundle/manifest.tmp" "$test_root/bundle/candidate-bundle.json"
  verify '10001:10001'
  if verify_migration 2>/dev/null; then
    echo "migration wrapper accepted a mismatched $field" >&2
    exit 1
  fi
done
