#!/usr/bin/env python3

import sys
import subprocess

MAP_PATH = "/sys/fs/bpf/app_map"

def usage():
    print(f"Uso: {sys.argv[0]} <tcp|udp> <porta>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()

proto_str = sys.argv[1].lower()
port = int(sys.argv[2])

# ===== protocollo =====
if proto_str == "tcp":
    proto = 6
elif proto_str == "udp":
    proto = 17
else:
    print("Errore: protocollo deve essere tcp o udp")
    sys.exit(1)

# ===== validazione porta =====
if port < 1 or port > 65535:
    print("Errore: porta non valida")
    sys.exit(1)

# ===== conversione big endian =====
port_be = port.to_bytes(2, byteorder="little")
proto_byte = proto.to_bytes(1, byteorder="little")

# padding (per allineamento struct: 1 byte proto + 1 padding + 2 port)
key = proto_byte +port_be +b'\x00' 

# value = enabled = 1
value = (1).to_bytes(4, byteorder="little")

# ===== comando bpftool =====
cmd = [
    "bpftool", "map", "update", "pinned", MAP_PATH,
    "key", "hex"
] + [f"{b:02x}" for b in key] + [
    "value", "hex"
] + [f"{b:02x}" for b in value]

print("Eseguo:", " ".join(cmd))

try:
    subprocess.run(cmd, check=True)
    print(f"✔ Inserito: {proto_str.upper()} porta {port}")
except subprocess.CalledProcessError:
    print("❌ Errore nell'aggiornamento della mappa")
    sys.exit(1)
