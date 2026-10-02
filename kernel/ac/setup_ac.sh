#!/bin/bash
# setup_ac.sh — deploy the XDP Aho-Corasick prefilter on $DUT_IFACE.
#
#   1. insmod xdp_ac_module.ko
#   2. create configfs policy "cattivi" (blocklist) with id $AC_ID
#   3. upload the .acdb into /sys/kernel/config/ac/cattivi/database
#   4. load xdp_prog_ac.o, pin program + maps under /sys/fs/bpf
#   5. attach to $DUT_IFACE and insert {proto, port} into app_map
#
# Usage:  bash setup_ac.sh <db.acdb> [proto=6] [port=80]
# Same sequence as eval/run_experiment.py (phase "ac_filter").
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/env.sh"

ACDB="${1:?usage: $0 <db.acdb> [proto] [port]}"
PROTO="${2:-6}"
PORT="${3:-80}"
AC_ID="${AC_ID:-9999}"            # must match ID_AC_CATTIVI in xdp_prog_ac.c
CONFIGFS="/sys/kernel/config/ac/cattivi"
PROG_PIN="/sys/fs/bpf/xdp_prog_ac"
MAPS_DIR="/sys/fs/bpf/ac_maps"

[[ -f "$ACDB" ]] || { echo "ACDB not found: $ACDB (build with: ./ac_build -n 262144 -t 12 -o db.acdb patterns.hs)"; exit 1; }

echo "[AC] insmod xdp_ac_module"
lsmod | grep -q '^xdp_ac_module' || sudo insmod "$SCRIPT_DIR/xdp_ac_module.ko"
sleep 0.3

echo "[AC] configfs policy cattivi id=$AC_ID"
sudo mkdir -p "$CONFIGFS"
echo "$AC_ID" | sudo tee "$CONFIGFS/id" > /dev/null
sudo dd if="$ACDB" of="$CONFIGFS/database" bs=1M status=none
echo "[AC] DFA states: $(cat $CONFIGFS/state_count)"
sleep 1.5      # let the module map the DB and allocate per-CPU state

echo "[AC] load + pin BPF program"
sudo rm -rf "$PROG_PIN" "$MAPS_DIR"
sudo mkdir -p "$MAPS_DIR"
sudo bpftool prog load "$SCRIPT_DIR/xdp_prog_ac.o" "$PROG_PIN" pinmaps "$MAPS_DIR"

echo "[AC] attach to $DUT_IFACE"
sudo ip addr add "$DUT_DATA_IP" dev "$DUT_IFACE" 2>/dev/null || true
sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
sudo ip link set dev "$DUT_IFACE" xdp pinned "$PROG_PIN"

# app_map key: struct { u8 proto; u16 port (host order); u8 pad } packed
KEY=$(printf '%02x %02x %02x 00' "$PROTO" $((PORT & 0xff)) $((PORT >> 8)))
sudo bpftool map update pinned "$MAPS_DIR/app_map" key hex $KEY value hex 01 00 00 00
echo "[AC] ready: $DUT_IFACE proto=$PROTO port=$PORT db=$ACDB"
