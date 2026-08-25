#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <candidate-bundle-dir>" >&2
  exit 64
fi

exec "$(dirname "$0")/verify-core-candidate-oci.sh" \
  "$1" archive archiveSha256 imageDigest profiles/core/server.oci /usr/local/bin/server
