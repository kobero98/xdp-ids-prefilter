import socket
import json
import subprocess
import time
import re
import os
import sys

from settings import CFG, repo_path

BUFFER_SIZE = 4096

# Management network: control socket between master and slave.
# Test traffic (pcap_replay via DPDK / tcpreplay) leaves on the slave data NIC.
DEFAULT_BIND_IP   = CFG["SLAVE_MGMT_IP"]
DEFAULT_BIND_PORT = int(CFG["SLAVE_PORT"])
DPDK_PCI          = CFG["SLAVE_DPDK_PCI"]
PCAP_REPLAY       = repo_path(CFG.get("SLAVE_PCAP_REPLAY", "eval/traffic/build/pcap_replay"))
PCAP_DIR          = repo_path(CFG.get("SLAVE_PCAP_DIR", "."))


def pcap_path(name):
    return name if os.path.isabs(name) else os.path.join(PCAP_DIR, name)


def send_msg(conn, msg):
    conn.sendall((json.dumps(msg) + "\n").encode())


def recv_msg(conn):
    data = conn.recv(BUFFER_SIZE).decode()
    return json.loads(data.strip())


def run_replay(pcap, rate, mode="time", duration=None, packet_count=None,
               pps=None, lcores="0-3"):
    # pps: se valorizzato usa il pacing a pacchetti (-P) invece dei Mbps (-R)
    rate_args = ["-P", str(pps)] if pps else ["-R", str(rate)]
    if mode == "packets":
        print(f"[SLAVE] Running replay {rate_args} packet_count={packet_count} lcores={lcores}")
        cmd = [
            PCAP_REPLAY,
            "-l", lcores,
            "-m", "1024",
            "-a", DPDK_PCI,
            "--",
            "-p", pcap_path(pcap),
            "-s",
            *rate_args,
            "-c", str(packet_count),
        ]
    else:
        print(f"[SLAVE] Running replay {rate_args} duration={duration} lcores={lcores}")
        cmd = [
            "timeout", str(duration),
            PCAP_REPLAY,
            "-l", lcores,
            "-m", "1024",
            "-a", DPDK_PCI,
            "--",
            "-p", pcap_path(pcap),
            "-s",
            *rate_args,
        ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    packets = 0
    final_re = re.compile(r"FINAL STATS: packets (\d+)")
    for line in proc.stdout:
        m = final_re.search(line)
        if m:
            packets = int(m.group(1))
            print("packet", packets)
    proc.wait()
    return packets


def run_tcpreplay(pcap, iface, mbps=None, pps=None, loop=1):
    """Invia il pcap via tcpreplay (single-thread, rate controllato)."""
    cmd = ["tcpreplay", f"--intf1={iface}"]
    if mbps is not None:
        cmd += [f"--mbps={mbps}"]
    elif pps is not None:
        cmd += [f"--pps={pps}"]
    if loop != 1:
        cmd += [f"--loop={loop}"]
    cmd.append(pcap_path(pcap))

    print(f"[SLAVE] tcpreplay: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    packets = 0
    # "Successful packets:        1000"
    ok_re = re.compile(r"Successful packets:\s+(\d+)")
    for line in proc.stdout:
        print(f"[SLAVE] tcpreplay: {line}", end="")
        m = ok_re.search(line)
        if m:
            packets = int(m.group(1))
    proc.wait()
    return packets


def main():
    bind_ip   = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BIND_IP
    bind_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_BIND_PORT

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, bind_port))
    server.listen(1)

    print(f"[SLAVE] Listening on {bind_ip}:{bind_port} (management network)")
    print(f"[SLAVE] test traffic: DPDK port {DPDK_PCI} / tcpreplay, pcaps in {PCAP_DIR}")

    while True:
        conn, addr = server.accept()
        print(f"[SLAVE] Connected from {addr}")

        while True:
            try:
                msg = recv_msg(conn)
            except Exception:
                print("[SLAVE] Connection lost")
                break

            if msg.get("cmd") == "start_test":
                mode = msg.get("mode", "time")
                try:
                    if mode == "tcpreplay":
                        packets = run_tcpreplay(
                            pcap=msg["pcap"],
                            iface=msg["iface"],
                            mbps=msg.get("mbps"),
                            pps=msg.get("pps"),
                            loop=msg.get("loop", 1),
                        )
                    else:
                        packets = run_replay(
                            pcap=msg["pcap"],
                            rate=msg["rate"],
                            mode=mode,
                            duration=msg.get("duration"),
                            packet_count=msg.get("packet_count"),
                            pps=msg.get("pps"),
                            lcores=msg.get("lcores", "0-3"),
                        )
                except Exception as e:
                    print(f"[SLAVE] Errore replay: {e}")
                    packets = -1
                time.sleep(3)
                try:
                    send_msg(conn, {"status": "done", "packets_send": packets})
                except Exception as e:
                    print(f"[SLAVE] Errore invio risposta (client disconnesso?): {e}")
                    break
            else:
                print("[SLAVE] Unknown message:", msg)

        conn.close()
        print("[SLAVE] Waiting for next connection...")


if __name__ == "__main__":
    main()
