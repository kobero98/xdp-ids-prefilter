#!/bin/bash

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/env.sh"

IF="$DUT_IFACE"
IP="$DUT_DATA_IP"


XDP_OBJ="${XDP_OBJ:-$SCRIPT_DIR/xdp_prog.o}"   # or xdp_prog_timing.o
PROG_PIN="/sys/fs/bpf/xdp_prog"
MAP_PIN="/sys/fs/bpf/app_map"

echo "[+] Configurazione interfaccia: $IF"

# =========================================
# 1. mount bpffs se non montato
# =========================================
if ! mountpoint -q /sys/fs/bpf; then
    echo "[+] Mount bpffs..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# =========================================
# 2. assegna IP
# =========================================
echo "[+] Assegno IP $IP a $IF"
sudo ip addr add $IP dev $IF || true

# =========================================
# 3. carica XDP + pin programma e mappe
# =========================================
echo "[+] Stacco XDP dall'interfaccia (se presente)"
sudo ip link set dev $IF xdp off || true

echo "[+] Rimuovo pin vecchi se esistono"
sudo rm -f $PROG_PIN $MAP_PIN

echo "[+] Carico XDP program"
sudo bpftool prog load $XDP_OBJ $PROG_PIN

echo "[+] Searching app_map id..."

MAP_ID=$(bpftool map show | awk '/app_map/ {print $1}' | cut -d: -f1 | head -n1)

if [ -z "$MAP_ID" ]; then
    echo "[-] ERROR: app_map not found"
    exit 1
fi

echo "[+] Found app_map ID: $MAP_ID"

sudo bpftool map pin id $MAP_ID $MAP_PIN


echo "[+] Programma e mappa caricati"

# =========================================
# 4. attacca XDP
# =========================================
echo "[+] Attacco XDP su $IF"

sudo ip link set dev $IF xdp pinned $PROG_PIN

# =========================================
# 5. attiva interfaccia
# =========================================
echo "[+] Metto interfaccia UP"

sudo ip link set $IF up

# =========================================
# DONE
# =========================================
echo "[✔] XDP setup completato!"
echo "    IF: $IF"
echo "    IP: $IP"
echo "    PROG: $PROG_PIN"
echo "    MAP: $MAP_PIN"
