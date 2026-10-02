#!/bin/bash

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../../scripts/env.sh"

IF="$DUT_IFACE"

PROG_PIN="/sys/fs/bpf/xdp_prog"
MAP_PIN="/sys/fs/bpf/app_map"

echo "[+] Inizio unsetup XDP su $IF"

# =========================================
# 1. Rimuove XDP dall'interfaccia
# =========================================
echo "[+] Rimuovo XDP da $IF"
sudo ip link set dev $IF xdp off || true

# =========================================
# 2. Rimuove programma pinned
# =========================================
if [ -e "$PROG_PIN" ]; then
    echo "[+] Rimuovo programma pinned"
    sudo rm -f $PROG_PIN
else
    echo "[-] Programma XDP non trovato in bpffs"
fi

# =========================================
# 3. Rimuove mappa pinned
# =========================================
if [ -e "$MAP_PIN" ]; then
    echo "[+] Rimuovo mappa pinned"
    sudo rm -f $MAP_PIN
else
    echo "[-] Mappa app_map non trovata in bpffs"
fi

# =========================================
# 4. (opzionale) rimuove IP dall'interfaccia
# =========================================
echo "[+] Rimuovo IP da $IF (se presente)"
#sudo ip addr flush dev $IF || true

# =========================================
# 5. verifica finale
# =========================================
echo "[+] Stato interfaccia:"
ip link show dev $IF | grep -i xdp || echo "Nessun XDP attivo"

echo "[✔] Unsetup completato"
