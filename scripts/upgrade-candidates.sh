#!/bin/sh
set -eu

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
case "$registry_index" in
    *[\ \"\\]*) echo "registry index contains unsupported URL characters" >&2; exit 64 ;;
esac
[ -f "$registry_index/config.json" ] || {
    echo "registry index is missing config.json" >&2
    exit 64
}
for version in "$diag_version" "$trace_version"; do
    printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' || {
        echo "candidate version must be exact SemVer" >&2
        exit 64
    }
done

manifest_tmp="Cargo.toml.tmp.$$"
trap 'rm -f "$manifest_tmp"' EXIT HUP INT TERM
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
' Cargo.toml > "$manifest_tmp" || {
    echo "candidate dependency anchors are not exact" >&2
    exit 65
}
mv "$manifest_tmp" Cargo.toml
trap - EXIT HUP INT TERM

mkdir -p .cargo
printf '[registries.rss-candidate]\nindex = "file://%s"\n' "$registry_index" > .cargo/config.toml
rm -f Cargo.lock
cargo generate-lockfile
cargo fetch --locked
