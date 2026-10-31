#!/bin/bash
# images/build.sh — golden image assembly (manifest + hashes).
#
# The real kernel/rootfs build (pinned version, minimal config, measured)
# produces the artifacts; this script assembles the MANIFEST the runtime
# actually consumes: ImageManifest (crates/backend-fc), whose fields carry
# the sha256 of every artifact. GoldenImage::load() verifies those hashes
# and the Ed25519 signature over the manifest — the signature comes from
# `toolcage-cli image sign` (this script cannot hold a signing key).
#
# Usage: build.sh <outdir> <kernel> <rootfs> <snapshot> <mem-file> [vcpu] [mem-mib]
set -euo pipefail

if [ "$#" -lt 5 ]; then
  echo "usage: $0 <outdir> <kernel> <rootfs> <snapshot> <mem-file> [vcpu] [mem-mib]" >&2
  exit 2
fi
OUT=$1
KERNEL=$2
ROOTFS=$3
SNAPSHOT=$4
MEM=$5
VCPU=${6:-1}
MEM_MIB=${7:-512}

for f in "$KERNEL" "$ROOTFS" "$SNAPSHOT" "$MEM"; do
  [ -f "$f" ] || { echo "missing artifact: $f" >&2; exit 1; }
done

mkdir -p "$OUT"
sha() { sha256sum "$1" | awk '{print $1}'; }
# Host class: snapshots are host-specific (the runtime refuses to load one
# on a different class), so record what built it.
HOST_CLASS=$( (lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}') || true )
HOST_CLASS=${HOST_CLASS:-$(uname -m)}
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION=$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.1.0")

cat > "$OUT/manifest.json" <<EOF
{
  "version": "$VERSION",
  "host_class": "$HOST_CLASS",
  "kernel": "$KERNEL",
  "kernel_hash": "$(sha "$KERNEL")",
  "rootfs": "$ROOTFS",
  "rootfs_hash": "$(sha "$ROOTFS")",
  "snapshot_path": "$SNAPSHOT",
  "snapshot_hash": "$(sha "$SNAPSHOT")",
  "mem_file_path": "$MEM",
  "mem_file_hash": "$(sha "$MEM")",
  "vcpu_count": $VCPU,
  "mem_size_mib": $MEM_MIB,
  "created_at": "$CREATED"
}
EOF
echo "wrote $OUT/manifest.json"
echo "sign it with: toolcage-cli image sign --dir $OUT --key-hex <key>"
