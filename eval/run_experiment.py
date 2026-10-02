#!/usr/bin/env python3
"""run_experiment.py — master side of the testbed (runs on the DUT).

For every (rate, repetition) in the test YAML it:
  1. starts Suricata on the data NIC (AF_PACKET) and waits for "Engine started";
  2. asks the slave (eval/slave.py) to replay the pcap at that rate;
  3. stops Suricata and appends a key:value trailer with NIC / XDP counters;
  4. copies the run's fast.log next to the output.

Phases (run_phases in the YAML):
  plain      Suricata alone (baseline)
  ac_filter  Suricata + XDP Aho-Corasick prefilter (kernel/ac)

Output: results/raw/<test_name>/suricata-<plain|ac>_<rate>_<rep>.txt
        -> summarise with results/extract.py

Usage:  python3 eval/run_experiment.py eval/test_case/<config>.yaml [slave_ip]
Run ONE test at a time, in the foreground: background/orphaned masters
interleave runs on the slave.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import yaml

from settings import (REPO_ROOT, DUT_IFACE, DUT_RX_RING, SLAVE_MGMT_IP,
                      SLAVE_PORT, SLAVE_IFACE, SURICATA_BIN, repo_path)

AC_DIR = os.path.join(REPO_ROOT, "kernel", "ac")
AC_MODULE_KO = os.path.join(AC_DIR, "xdp_ac_module.ko")
AC_BPF_OBJ = os.path.join(AC_DIR, "xdp_prog_ac.o")
AC_PROG_PIN = "/sys/fs/bpf/xdp_prog_ac"
AC_MAPS_DIR = "/sys/fs/bpf/ac_maps"
AC_CONFIGFS = "/sys/kernel/config/ac/cattivi"
RAW_DIR = os.path.join(REPO_ROOT, "results", "raw")

# Fixed "random" RSS key: the mlx5 default hash maps the few concurrent tuples
# of a sequential replay onto one queue. Kept constant for reproducibility and
# re-applied at start-up because ethtool -X does not survive a reboot.
RSS_KEY = ("d0:4b:33:8a:2e:ca:1c:be:05:7d:0a:da:1b:57:87:c9:6a:97:6c:bc:"
           "e9:1e:b6:6d:03:86:93:8b:9d:67:c3:75:f5:a5:8f:d0:34:d7:4d:e0")


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, **kw)


def sudo_out(cmd):
    return subprocess.run(["sudo"] + cmd, capture_output=True, text=True)


# ── control channel ──────────────────────────────────────────────────────────

def send_msg(sock, msg):
    sock.sendall((json.dumps(msg) + "\n").encode())


def recv_msg(sock):
    return json.loads(sock.recv(4096).decode().strip())


# ── NIC preparation ──────────────────────────────────────────────────────────

def setup_plain():
    sh(["sudo", "pkill", "-f", "suricata"], check=False, capture_output=True)
    sh(["bash", os.path.join(REPO_ROOT, "scripts", "setup_basic_if.sh")])


def ensure_nic_ring(iface, rx_size):
    """Grow the RX ring to rx_size (ethtool -G flaps the link: only if needed)."""
    out = subprocess.run(["ethtool", "-g", iface], capture_output=True, text=True).stdout
    cur = pre = section = None
    for line in out.splitlines():
        if line.startswith("Pre-set maximums"):
            section = "max"
        elif line.startswith("Current hardware settings"):
            section = "cur"
        elif line.startswith("RX:") and section:
            val = int(line.split(":")[1])
            pre, cur = (val, cur) if section == "max" else (pre, val)
    if cur is None:
        print(f"[MASTER] WARNING: cannot read RX ring of {iface}")
        return
    target = min(rx_size, pre or rx_size)
    if cur < target:
        print(f"[MASTER] RX ring {iface}: {cur} -> {target}")
        sh(["sudo", "ethtool", "-G", iface, "rx", str(target)], check=False)
        time.sleep(1)


def ensure_rss_key(iface, key=RSS_KEY):
    out = subprocess.run(["ethtool", "-x", iface], capture_output=True, text=True).stdout
    lines = out.splitlines()
    cur = next((lines[i + 1].strip() for i, l in enumerate(lines[:-1])
                if l.startswith("RSS hash key")), None)
    if cur != key:
        print(f"[MASTER] setting RSS key on {iface}")
        sh(["sudo", "ethtool", "-X", iface, "hkey", key], check=False)


def read_nic_stats(iface):
    stats = {}
    for c in ("rx_packets", "rx_dropped", "rx_missed_errors"):
        try:
            with open(f"/sys/class/net/{iface}/statistics/{c}") as f:
                stats[c] = int(f.read())
        except OSError:
            stats[c] = 0
    return stats


# ── XDP AC filter ────────────────────────────────────────────────────────────

def _decode_int(v):
    if isinstance(v, dict):
        v = next(iter(v.values()))
    if isinstance(v, list):
        return int.from_bytes(bytes(x if isinstance(x, int) else int(x, 16) for x in v), "little")
    return int(v)


def read_ac_drop_cnt():
    """Sum of the per-CPU xdp_drop_cnt map (packets diverted by the filter)."""
    r = sudo_out(["bpftool", "map", "dump", "pinned",
                  os.path.join(AC_MAPS_DIR, "xdp_drop_cnt"), "-j"])
    if r.returncode != 0:
        return 0
    return sum(_decode_int(c.get("value", 0))
               for e in json.loads(r.stdout) for c in e.get("values", []))


def reset_ac_drop_cnt():
    sudo_out(["bpftool", "map", "update", "pinned",
              os.path.join(AC_MAPS_DIR, "xdp_drop_cnt"),
              "key", "00", "00", "00", "00", "value"] + ["00"] * 8)


def setup_ac_filter(acdb, iface, proto, port, ac_id=9999):
    print(f"[MASTER] AC filter: iface={iface} proto={proto} port={port} db={acdb}")
    if not os.path.exists(acdb):
        raise FileNotFoundError(f"ACDB not found: {acdb}")
    lsmod = subprocess.run(["lsmod"], capture_output=True, text=True).stdout
    if not any(l.split()[0] == "xdp_ac_module" for l in lsmod.splitlines()[1:]):
        sh(["sudo", "insmod", AC_MODULE_KO])
        time.sleep(0.3)
    sh(["sudo", "mkdir", "-p", AC_CONFIGFS])
    sh(f"echo {ac_id} | sudo tee {AC_CONFIGFS}/id > /dev/null", shell=True)
    sh(["sudo", "dd", f"if={acdb}", f"of={AC_CONFIGFS}/database", "bs=1M"],
       capture_output=True)
    # Give the module time to map the DB and allocate per-CPU state: traffic
    # arriving earlier is scanned fail-open (PASS) and the filter looks idle.
    time.sleep(1.5)

    sh(["sudo", "rm", "-rf", AC_PROG_PIN, AC_MAPS_DIR], check=False)
    sh(["sudo", "mkdir", "-p", AC_MAPS_DIR])
    sh(["sudo", "bpftool", "prog", "load", AC_BPF_OBJ, AC_PROG_PIN, "pinmaps", AC_MAPS_DIR])
    sh(["sudo", "ip", "link", "set", "dev", iface, "xdp", "off"], check=False, capture_output=True)
    sh(["sudo", "ip", "link", "set", "dev", iface, "xdp", "pinned", AC_PROG_PIN])

    key = struct.pack("<BHB", proto, port, 0)        # {u8 proto, u16 port, u8 pad}
    sh(["sudo", "bpftool", "map", "update", "pinned", os.path.join(AC_MAPS_DIR, "app_map"),
        "key", "hex"] + [f"{b:02x}" for b in key] + ["value", "hex", "01", "00", "00", "00"])

    am = sudo_out(["bpftool", "map", "dump", "pinned", os.path.join(AC_MAPS_DIR, "app_map"), "-j"])
    if am.returncode != 0 or not json.loads(am.stdout or "[]"):
        raise RuntimeError("app_map empty after setup: filter not engaged")
    if "xdp" not in subprocess.run(["ip", "link", "show", iface],
                                   capture_output=True, text=True).stdout:
        raise RuntimeError(f"no XDP program attached on {iface}")


def teardown_ac_filter(iface):
    sh(["bash", os.path.join(AC_DIR, "teardown_ac.sh")], check=False)


# ── Suricata ─────────────────────────────────────────────────────────────────

def start_suricata(output_file, suricata_conf, rules_file, iface):
    f = open(output_file, "w")
    cmd = ["stdbuf", "-oL", "sudo", SURICATA_BIN, "-c", suricata_conf,
           "-i", iface, "--af-packet", "-v"]
    if rules_file:
        cmd += ["-S", rules_file]          # load exclusively this rule file
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    ready = threading.Event()

    def reader():
        for line in proc.stdout:
            f.write(line)
            f.flush()
            if "Engine started" in line:
                ready.set()

    threading.Thread(target=reader, daemon=True).start()
    return proc, f, ready


def log_dir_of(suricata_conf):
    try:
        with open(suricata_conf) as f:
            return yaml.safe_load(f).get("default-log-dir", "/var/log/suricata/")
    except Exception:
        return "/var/log/suricata/"


def stop_suricata(proc, fh, sent, nic_before, iface, ac_drops, log_dir, output_file):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(0.5)   # let the reader thread flush the shutdown counters
    nic = read_nic_stats(iface)
    fh.write(f"\nPacket:{sent}\n")
    fh.write(f"NicRxPackets:{nic['rx_packets'] - nic_before['rx_packets']}\n")
    fh.write(f"NicRxDropped:{nic['rx_dropped'] - nic_before['rx_dropped']}\n")
    fh.write(f"NicRxMissed:{nic['rx_missed_errors'] - nic_before['rx_missed_errors']}\n")
    if ac_drops is not None:
        fh.write(f"AcXdpDropped:{ac_drops}\n")
    fh.close()
    dst = output_file[:-4] + ".fast.log"
    sh(["sudo", "cp", os.path.join(log_dir, "fast.log"), dst], check=False)
    sh(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", dst], check=False)


# ── test loop ────────────────────────────────────────────────────────────────

def run_tests(sock, cfg, prefix, with_ac=False):
    suricata_conf = repo_path(cfg.get("suricata_conf", "suricata/suricata-eval.yaml"))
    rules_file = repo_path(cfg["rules_file"]) if cfg.get("rules_file") else None
    iface = cfg.get("iface", DUT_IFACE)
    mode = cfg.get("test_mode", "time")
    log_dir = log_dir_of(suricata_conf)

    for entry in cfg["rates"]:
        rate = entry["rate"]
        for rep in range(entry["rep"]):
            out = f"{prefix}_{rate}_{rep}.txt"
            if cfg.get("skip_existing") and os.path.exists(out):
                print(f"[MASTER] skip (exists): {out}")
                continue
            print(f"\n[MASTER] rate={rate} rep={rep}")
            sh(["sudo", "truncate", "-s", "0", os.path.join(log_dir, "fast.log")], check=False)
            proc, fh, ready = start_suricata(out, suricata_conf, rules_file, iface)
            if not ready.wait(timeout=180):
                print("[ERROR] Suricata not ready")
                proc.kill()
                fh.close()
                return False

            nic_before = read_nic_stats(iface)
            if with_ac:
                reset_ac_drop_cnt()

            msg = {"cmd": "start_test", "rate": rate, "pcap": cfg["pcap"], "mode": mode}
            if mode == "tcpreplay":
                # the rate of the list is a pps value for tcpreplay --pps
                msg["pps"] = rate
                msg["iface"] = cfg.get("tcpreplay_iface", SLAVE_IFACE)
                msg["loop"] = entry.get("loop", cfg.get("tcpreplay_loop", 1))
            else:
                msg["duration"] = cfg["duration"]
                if cfg.get("replay_pps"):
                    msg["pps"] = rate            # pcap_replay -P (pps pacing)
                if cfg.get("replay_lcores") is not None:
                    msg["lcores"] = str(cfg["replay_lcores"])
            send_msg(sock, msg)
            resp = recv_msg(sock)
            sent = resp.get("packets_send", 0)
            ac_drops = read_ac_drop_cnt() if with_ac else None
            stop_suricata(proc, fh, sent, nic_before, iface, ac_drops, log_dir, out)
            print(f"[MASTER] sent={sent} xdp_dropped={ac_drops} -> {out}")

            # Guard: an engaged filter always diverts something on the first run.
            if with_ac and ac_drops == 0 and not cfg.get("allow_zero_acdrop", False):
                print("[ERROR] AC filter active but dropped=0: filter not engaged, abort")
                return False
    return True


def main(conf_file, slave_ip=None):
    with open(conf_file) as f:
        cfg = yaml.safe_load(f)
    if "rates" not in cfg:                       # legacy key of the original configs
        cfg["rates"] = cfg.pop("rates_mbps")
    iface = cfg.get("iface", DUT_IFACE)

    setup_plain()
    ensure_nic_ring(iface, cfg.get("nic_rx_ring", DUT_RX_RING))
    ensure_rss_key(iface)

    addr = (slave_ip or cfg.get("slave_ip", SLAVE_MGMT_IP), cfg.get("slave_port", SLAVE_PORT))
    print(f"[MASTER] connecting to slave {addr[0]}:{addr[1]}")
    sock = socket.create_connection(addr)

    outdir = os.path.join(RAW_DIR, cfg["test_name"])
    os.makedirs(outdir, exist_ok=True)
    phases = cfg.get("run_phases", ["plain", "ac_filter"])

    if "plain" in phases:
        print("\n[MASTER] ===== phase plain: Suricata baseline =====")
        run_tests(sock, cfg, os.path.join(outdir, "suricata-plain"))

    if "ac_filter" in phases:
        print("\n[MASTER] ===== phase ac_filter: Suricata + XDP AC =====")
        try:
            setup_ac_filter(repo_path(cfg["acdb_file"]), iface,
                            cfg.get("filter_proto", 6), cfg.get("filter_port", 80),
                            cfg.get("ac_id", 9999))
            run_tests(sock, cfg, os.path.join(outdir, "suricata-ac"), with_ac=True)
        finally:
            teardown_ac_filter(iface)

    sock.close()
    print("\n[MASTER] all tests completed")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(f"usage: {sys.argv[0]} <config.yaml> [slave_ip]")
    main(*sys.argv[1:])
