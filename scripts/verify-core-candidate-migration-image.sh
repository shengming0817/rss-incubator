#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <candidate-bundle-dir>" >&2
  exit 64
fi

exec "$(dirname "$0")/verify-core-candidate-oci.sh" \
  "$1" migrationArchive migrationArchiveSha256 migrationImageDigest \
  profiles/core/migrator.oci /usr/local/bin/rss
