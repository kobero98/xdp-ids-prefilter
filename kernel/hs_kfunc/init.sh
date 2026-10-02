#!/bin/bash
# init.sh — compile a Hyperscan pattern file (block mode) with hscollider and
# upload it to xdp_regex_module as policy "cattivi" (id 4321, the blocklist
# ID used by xdp_prog_kern_test.c / xdp_prog_kern_timing.c).
# Requires: xdp_regex_module.ko already inserted.
#
# Usage: bash init.sh <patterns.hs> [policy=cattivi] [id=4321]
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/env.sh"

PATTERNS="${1:?usage: $0 <patterns.hs> [policy] [id]}"
POLICY="${2:-cattivi}"
ID="${3:-4321}"
OUT="$BUILD_DIR/hs/$(basename "${PATTERNS%.*}")"

rm -rf "$OUT" && mkdir -p "$OUT"
"$HSCOLLIDER" -e "$PATTERNS" -ao "$OUT/" -n1
DB=$(ls "$OUT"/*.db | head -1)

sudo mkdir -p "/sys/kernel/config/rex/$POLICY"
echo "$ID" | sudo tee "/sys/kernel/config/rex/$POLICY/id" > /dev/null
sudo dd if="$DB" of="/sys/kernel/config/rex/$POLICY/database" status=none
echo "[+] $POLICY (id $ID) <- $DB"
cat "/sys/kernel/config/rex/$POLICY/info"
