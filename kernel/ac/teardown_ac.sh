#!/bin/bash
# teardown_ac.sh — detach the AC prefilter and unload xdp_ac_module.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/env.sh"

sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/xdp_prog_ac /sys/fs/bpf/ac_maps
sudo rmdir /sys/kernel/config/ac/cattivi 2>/dev/null || true
sudo rmmod xdp_ac_module 2>/dev/null || true
echo "[AC] removed"
