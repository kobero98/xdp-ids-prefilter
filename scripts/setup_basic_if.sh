#!/bin/bash
# setup_basic_if.sh — bring up the DUT data/management NICs (no XDP attached).
# Used before every "plain" (baseline) run.
. "$(dirname "$0")/env.sh"

sudo ip addr add "$DUT_DATA_IP" dev "$DUT_IFACE" 2>/dev/null || true
sudo ip link set "$DUT_IFACE" up

# management NIC (master<->slave control socket, SSH)
sudo ip addr add "$DUT_MGMT_IP" dev "$DUT_MGMT_IFACE" 2>/dev/null || true
sudo ip link set "$DUT_MGMT_IFACE" up

# restore IRQ affinity of every data-NIC queue to all CPUs
SYSFS_IRQS="/sys/class/net/$DUT_IFACE/device/msi_irqs"
NCPU=$(nproc)
MASK=$(printf '%x' $(( (1 << NCPU) - 1 )))
if [ -d "$SYSFS_IRQS" ]; then
    for IRQ in $(ls "$SYSFS_IRQS"); do
        echo "$MASK" | sudo tee /proc/irq/$IRQ/smp_affinity > /dev/null 2>&1 || true
    done
fi
