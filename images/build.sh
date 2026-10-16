#!/bin/bash
# images/build.sh v0: reproducible guest kernel+rootfs skeleton.
# Real kernel build: pinned version, minimal config, measured + signed.
set -e
OUT=${1:-images/out}
mkdir -p "$OUT"
echo "== toolcage image skeleton v0 =="
KERNEL_VER="6.8-toolcage"
ROOTFS="alpine-minimal-3.20"
cat > "$OUT/manifest.json" <<EOF
{
  "kernel": "$KERNEL_VER",
  "rootfs": "$ROOTFS",
  "guest_agent": "static-musl",
  "vsock_only": true,
  "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
sha256sum "$OUT/manifest.json" | awk '{print $1}' > "$OUT/manifest.sha256"
echo "manifest: $OUT/manifest.json"
cat "$OUT/manifest.json"
echo "hash: $(cat $OUT/manifest.sha256)"
echo "NOTE: golden snapshots are built per host class, signed, verified before load."
