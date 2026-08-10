#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

registry_index=""
diag_version=""
trace_version=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --registry-index) registry_index=${2:?missing registry index}; shift 2 ;;
        --diag-version) diag_version=${2:?missing diag version}; shift 2 ;;
        --trace-version) trace_version=${2:?missing trace version}; shift 2 ;;
        *) echo "unknown argument" >&2; exit 64 ;;
    esac
done

case "$registry_index" in
    /*) ;;
    *) echo "registry index must be absolute" >&2; exit 64 ;;
esac
[ -f "$registry_index/config.json" ] || {
    echo "registry index is missing config.json" >&2
    exit 64
}
registry_index=$(CDPATH= cd -- "$registry_index" && pwd -P)
case "$registry_index" in
    *[!A-Za-z0-9/._-]*) echo "registry index contains unsupported URL characters" >&2; exit 64 ;;
esac
for version in "$diag_version" "$trace_version"; do
    printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' || {
        echo "candidate version must be exact SemVer" >&2
        exit 64
    }
done

transaction_root=$(mktemp -d "${TMPDIR:-/tmp}/rss-standalone-upgrade.XXXXXX")
trap 'rm -rf "$transaction_root"' EXIT HUP INT TERM
transaction_repo="$transaction_root/repository"
mkdir -p "$transaction_repo/src" "$transaction_repo/tests" "$transaction_repo/.cargo"
cp Cargo.toml "$transaction_repo/Cargo.toml"
cp -R src/. "$transaction_repo/src/"
cp -R tests/. "$transaction_repo/tests/"
manifest_tmp="$transaction_repo/Cargo.toml.next"
awk -v diag="$diag_version" -v trace="$trace_version" '
    BEGIN { diag_count = 0; trace_count = 0 }
    /^rss_diag_context = / {
        print "rss_diag_context = { package = \"rss-diag-context\", version = \"=" diag "\", registry = \"rss-candidate\" }"
        diag_count++
        next
    }
    /^rss_trace_context = / {
        print "rss_trace_context = { package = \"rss-trace-context\", version = \"=" trace "\", registry = \"rss-candidate\" }"
        trace_count++
        next
    }
    { print }
    END {
        if (diag_count != 1 || trace_count != 1) exit 65
    }
' "$transaction_repo/Cargo.toml" > "$manifest_tmp" || {
    echo "candidate dependency anchors are not exact" >&2
    exit 65
}
mv "$manifest_tmp" "$transaction_repo/Cargo.toml"

printf '[registries.rss-candidate]\nindex = "file://%s"\n' "$registry_index" > "$transaction_repo/.cargo/config.toml"
(
    cd "$transaction_repo"
    cargo generate-lockfile --offline
    cargo fetch --locked --offline
)

mkdir -p .cargo
mv "$transaction_repo/Cargo.toml" Cargo.toml
mv "$transaction_repo/Cargo.lock" Cargo.lock
mv "$transaction_repo/.cargo/config.toml" .cargo/config.toml
