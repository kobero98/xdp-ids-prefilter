#!/bin/bash
# teardown_all.sh — detach any XDP program and unload both kernel modules.
. "$(dirname "$0")/env.sh"

sudo ip link set dev "$DUT_IFACE" xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/xdp_prog_ac /sys/fs/bpf/ac_maps \
            /sys/fs/bpf/xdp_prog /sys/fs/bpf/xdp_prog_timing /sys/fs/bpf/app_map
for pol in /sys/kernel/config/ac/*/ /sys/kernel/config/rex/*/; do
    [ -d "$pol" ] && sudo rmdir "$pol" 2>/dev/null
done
sudo rmmod xdp_ac_module 2>/dev/null || true
sudo rmmod xdp_regex_module 2>/dev/null || true
lsmod | grep -E 'xdp_ac_module|xdp_regex_module' || echo "[+] modules unloaded"
