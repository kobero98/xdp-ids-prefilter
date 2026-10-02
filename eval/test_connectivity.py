#!/usr/bin/env python3
"""
test_connectivity.py — Sanity check veloce master↔slave.

Verifica che:
  1. Il master riesce a connettersi allo slave
  2. Lo slave esegue pcap_replay e riporta packets_send > 0
  3. I pacchetti arrivano realmente sull'interfaccia (NIC rx_packets aumenta)

Usa la stessa config YAML dei test reali ma forza rate e duration piccoli
in modo che il check finisca in pochi secondi.

Uso:
    python3 eval/test_connectivity.py eval/test_case/highrate_mixed_dpdk.yaml
    python3 eval/test_connectivity.py eval/test_case/highrate_mixed_dpdk.yaml --rate 200 --duration 5
"""

import socket
import json
import sys
import time
import argparse
import yaml
from pathlib import Path

import settings

# ── helpers (stessa logica di master.py) ─────────────────────────────────────

def send_msg(sock, msg):
    sock.sendall((json.dumps(msg) + "\n").encode())


def recv_msg(sock, timeout=120):
    sock.settimeout(timeout)
    buf = ""
    while True:
        chunk = sock.recv(4096).decode()
        if not chunk:
            raise ConnectionError("Slave ha chiuso la connessione inaspettatamente")
        buf += chunk
        if "\n" in buf:
            line, _ = buf.split("\n", 1)
            return json.loads(line.strip())


def read_nic_rx(iface):
    path = f"/sys/class/net/{iface}/statistics/rx_packets"
    try:
        return int(Path(path).read_text().strip())
    except Exception:
        return None


# ── check steps ──────────────────────────────────────────────────────────────

OK   = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"
INFO = "\033[34m[INFO]\033[0m"


def check(label, passed, detail=""):
    status = OK if passed else FAIL
    line = f"  {status} {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", help="File YAML di configurazione (es. eval/test_case/highrate_mixed_dpdk.yaml)")
    parser.add_argument("--rate",     type=int, default=200,
                        help="Rate Mbps per il test (default: 200)")
    parser.add_argument("--duration", type=int, default=15,
                        help="Durata in secondi (default: 5)")
    args = parser.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    slave_ip   = cfg.get("slave_ip", settings.SLAVE_MGMT_IP)
    slave_port = cfg.get("slave_port", settings.SLAVE_PORT)
    pcap       = cfg["pcap"]
    iface      = cfg.get("iface", settings.DUT_IFACE)   # data NIC: where test traffic arrives

    print(f"\n{INFO} Parametri test")
    print(f"         slave  : {slave_ip}:{slave_port}")
    print(f"         pcap   : {pcap}")
    print(f"         iface  : {iface}")
    print(f"         rate   : {args.rate} Mbps  per {args.duration}s")
    print()

    all_ok = True

    # ── Step 1: connessione TCP ───────────────────────────────────────────────
    print("1. Connessione TCP allo slave")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((slave_ip, slave_port))
        all_ok &= check("Connessione stabilita", True, f"{slave_ip}:{slave_port}")
    except Exception as e:
        check("Connessione stabilita", False, str(e))
        print(f"\n  Impossibile proseguire senza connessione.")
        sys.exit(1)

    # ── Step 2: NIC rx_packets prima ─────────────────────────────────────────
    print("\n2. Contatori NIC pre-test")
    rx_before = read_nic_rx(iface)
    if rx_before is None:
        check(f"Lettura /sys/class/net/{iface}/statistics/rx_packets", False,
              "interfaccia non trovata o permessi mancanti")
    else:
        check(f"rx_packets prima: {rx_before:,}", True)

    # ── Step 3: invia comando start_test ─────────────────────────────────────
    print("\n3. Invio start_test allo slave")
    t_send = time.monotonic()
    try:
        send_msg(sock, {
            "cmd":      "start_test",
            "rate":     args.rate,
            "duration": args.duration,
            "pcap":     pcap,
        })
        check("Comando inviato", True)
    except Exception as e:
        check("Comando inviato", False, str(e))
        sock.close()
        sys.exit(1)

    # ── Step 4: attendi risposta ──────────────────────────────────────────────
    print("\n4. Attendo risposta dallo slave ...")
    try:
        resp = recv_msg(sock, timeout=args.duration + 30)
        elapsed = time.monotonic() - t_send
        all_ok &= check("Risposta ricevuta", True, f"in {elapsed:.1f}s")
    except Exception as e:
        check("Risposta ricevuta", False, str(e))
        sock.close()
        sys.exit(1)

    sock.close()

    # ── Step 5: analisi risposta ──────────────────────────────────────────────
    print("\n5. Analisi risposta slave")
    print(f"   Risposta raw: {resp}")

    status_ok = resp.get("status") == "done"
    all_ok &= check('status == "done"', status_ok, repr(resp.get("status")))

    packets_send = resp.get("packets_send", 0)
    pkts_ok = packets_send > 0
    all_ok &= check(f"packets_send > 0", pkts_ok, f"packets_send={packets_send:,}")

    # ── Step 6: NIC rx_packets dopo ──────────────────────────────────────────
    print("\n6. Contatori NIC post-test")
    if rx_before is not None:
        rx_after = read_nic_rx(iface)
        if rx_after is not None:
            delta = rx_after - rx_before
            nic_ok = delta > 0
            all_ok &= check(f"Pacchetti ricevuti sulla NIC", nic_ok,
                            f"Δrx_packets={delta:,}")
            if nic_ok and packets_send > 0:
                ratio = 100.0 * delta / packets_send
                print(f"         → NIC ha visto {ratio:.1f}% dei pacchetti inviati dallo slave")
        else:
            check("Lettura rx_packets post-test", False)
    else:
        print(f"   (skippato — lettura pre-test fallita)")

    # ── Risultato finale ──────────────────────────────────────────────────────
    print()
    print("=" * 50)
    if all_ok:
        print(f"{OK} Tutto ok — master e slave comunicano correttamente")
    else:
        print(f"{FAIL} Alcuni check falliti — vedi sopra")
    print("=" * 50)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
