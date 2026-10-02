#!/usr/bin/env python3
"""
hs_timing_test.py — Microbenchmark Hyperscan in-kernel (bpf_xdp_scan_bytes).

Misura il costo per-fase di uno scan Hyperscan block-mode nel kernel:
  lookup    = idr_find + rcu_dereference + fetch scratch per-CPU
  fpu_begin = irq_fpu_usable + kernel_fpu_begin (XSAVE)
  scan      = hs_scan
  fpu_end   = kernel_fpu_end (XRSTOR)
  kfunc     = (totale visto dal BPF) - (totale visto dal modulo)
              → overhead trampolino kfunc + bpf_xdp_pointer + rcu

Protocollo: traffico inviato LENTO via tcpreplay --pps dallo slave, così ogni
pacchetto viene scansionato in isolamento (niente code, niente contesa).
Le statistiche del modulo (debugfs rex_bench) sono per-CPU e bucketizzate per
lunghezza payload; vengono AZZERATE prima di ogni run (bug del test 25/6).

Uso:  python3 hs_timing_test.py [--quick]
  --quick: un solo run breve (loop parziale) per smoke-test della pipeline.
"""

import socket, json, subprocess, os, sys, time, struct, datetime, glob

# ─── configurazione ───────────────────────────────────────────────────────────
from settings import CFG, REPO_ROOT, BUILD_DIR

PCAP        = "mixed_output.pcap"
SLAVE_IP    = CFG["SLAVE_MGMT_IP"]
SLAVE_PORT  = int(CFG["SLAVE_PORT"])
SLAVE_IFACE = CFG["SLAVE_IFACE"]
PROTO       = 6
PORT        = 80
IFACE       = CFG["DUT_IFACE"]
DATA_IP     = CFG["DUT_DATA_IP"]
HS_ID       = 4321          # DB "cattivi" block-mode
PCAP_NPKTS  = 1437980

# (pps, loop) — lenti: inter-packet >> tempo di scan
RUNS        = [(5000, 1), (5000, 1), (20000, 1)]

HS_DIR     = os.path.join(REPO_ROOT, "kernel", "hs_kfunc")
MODULE_KO  = os.path.join(HS_DIR, "xdp_regex_module.ko")
XDP_OBJ    = os.path.join(HS_DIR, "xdp_prog_timing.o")
# block-mode DB compiled by kernel/hs_kfunc/init.sh from patterns/mixed.hs
HS_DB      = os.environ.get("HS_DB") or next(iter(sorted(
    glob.glob(os.path.join(BUILD_DIR, "hs", "mixed", "*.db")))), "")
OUT_DIR    = os.path.join(REPO_ROOT, "results", "raw", "hs_microbench")

BPF_PIN    = "/sys/fs/bpf/xdp_prog_timing"
CONFIGFS   = "/sys/kernel/config/rex"
DEBUGFS    = "/sys/kernel/debug/rex_bench"

BUCKET_LO  = [0, 64, 128, 256, 512, 1024, 1536]
# ─────────────────────────────────────────────────────────────────────────────


def _run(args, check=True):
    r = subprocess.run(["sudo"] + args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} fallito:\n{r.stderr.strip()}")
    return r.stdout


def send_msg(sock, msg):
    sock.sendall((json.dumps(msg) + "\n").encode())


def recv_msg(sock):
    data = sock.recv(4096).decode()
    return json.loads(data.strip())


# ─── setup / teardown ─────────────────────────────────────────────────────────

def teardown(quiet=True):
    cmds = [
        ["ip", "link", "set", "dev", IFACE, "xdp", "off"],
        ["rm", "-f", BPF_PIN],
        ["rmdir", f"{CONFIGFS}/cattivi"],
        ["rmdir", f"{CONFIGFS}/cattivi_stream"],
        ["rmmod", "xdp_regex_module"],
        ["rmmod", "xdp_ac_module"],
    ]
    for c in cmds:
        subprocess.run(["sudo"] + c, capture_output=True, text=True)
    if not quiet:
        print("  [teardown] OK")


def _find_map_id(map_ids, name):
    for mid in map_ids:
        r = subprocess.run(["sudo", "bpftool", "map", "show", "id", str(mid), "-j"],
                           capture_output=True, text=True)
        if r.returncode == 0 and json.loads(r.stdout).get("name") == name:
            return mid
    return None


def setup():
    # 1. modulo con bench attivo
    _run(["insmod", MODULE_KO, "bench=1"])
    time.sleep(0.3)
    bench = _run(["cat", "/sys/module/xdp_regex_module/parameters/bench"]).strip()
    if bench != "Y":
        raise RuntimeError(f"bench param = {bench!r}, atteso Y")

    # 2. policy configfs + DB
    _run(["mkdir", "-p", f"{CONFIGFS}/cattivi"])
    _run(["bash", "-c", f"echo {HS_ID} > {CONFIGFS}/cattivi/id"])
    _run(["dd", f"if={HS_DB}", f"of={CONFIGFS}/cattivi/database"])
    info = _run(["cat", f"{CONFIGFS}/cattivi/info"]).strip()
    print(f"  [setup] DB caricato: {info}")

    # 3. programma XDP
    _run(["bpftool", "prog", "load", XDP_OBJ, BPF_PIN])
    subprocess.run(["sudo", "ip", "addr", "add", DATA_IP, "dev", IFACE],
                   capture_output=True, text=True)
    _run(["ip", "link", "set", "dev", IFACE, "xdp", "pinned", BPF_PIN])

    # 4. map ids
    prog = json.loads(_run(["bpftool", "prog", "show", "pinned", BPF_PIN, "-j"]))
    maps = {}
    for name in ("app_map", "hs_timing", "counters"):
        mid = _find_map_id(prog.get("map_ids", []), name)
        if mid is None:
            raise RuntimeError(f"mappa '{name}' non trovata")
        maps[name] = mid

    # 5. app_map: struct app_key packed {u8 proto, u16 port LE, u8 pad}
    key = [PROTO, PORT & 0xff, (PORT >> 8) & 0xff, 0]
    _run(["bpftool", "map", "update", "id", str(maps["app_map"]),
          "key", "hex"] + [f"{b:02x}" for b in key] +
         ["value", "hex", "01", "00", "00", "00"])
    print(f"  [setup] XDP su {IFACE}, app_map tcp/{PORT}, maps={maps}")
    return maps


def reset_stats():
    _run(["bash", "-c", f"echo 0 > {DEBUGFS}"])


# ─── lettura statistiche ──────────────────────────────────────────────────────

def read_bench_raw():
    return _run(["cat", DEBUGFS])


def parse_bench(raw):
    """Aggrega i bucket su tutte le CPU.
    Ritorna (clock_x1000, busy_tot, {lo: {campi sommati}}, {cpu: hist})"""
    clock = 0
    busy = 0
    buckets = {}
    hists = {}
    for line in raw.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "clock_ns_x1000":
            clock = int(f[1])
        elif f[0] == "cpu" and len(f) >= 4 and f[2] == "busy":
            busy += int(f[3])
        elif f[0] == "cpu" and len(f) >= 4 and f[2] == "hist":
            hists[int(f[1])] = [int(x) for x in f[3:]]
        elif f[0] == "cpu" and len(f) >= 4 and f[2] == "bucket":
            d = dict(zip(f[4::2], (int(x) for x in f[5::2])))
            lo = int(f[3])
            b = buckets.setdefault(lo, dict.fromkeys(
                ("count", "bytes", "matches", "lookup", "fpu_begin",
                 "scan", "scan_matched", "fpu_end", "total"), 0))
            for k in b:
                b[k] += d[k]
            b.setdefault("min", d["min"])
            b["min"] = min(b["min"], d["min"])
            b["max"] = max(b.get("max", 0), d["max"])
    return clock, busy, buckets, hists


def decode_u64(v):
    if isinstance(v, list):
        return int.from_bytes(bytes(int(x, 16) if isinstance(x, str) else x
                                    for x in v), "little")
    if isinstance(v, dict):
        return decode_u64(next(iter(v.values())))
    return int(v)


def read_percpu_map(map_id, nkeys):
    """PERCPU_ARRAY → {key: somma su CPU}"""
    raw = json.loads(_run(["bpftool", "map", "dump", "id", str(map_id), "-j"]))
    out = {k: 0 for k in range(nkeys)}
    maxes = {}
    def process(entries):
        for e in entries:
            k = e.get("key")
            k = decode_u64(k) if isinstance(k, list) else int(k)
            for ce in e.get("values", []):
                v = decode_u64(ce.get("value", 0))
                out[k] = out.get(k, 0) + v
                maxes[k] = max(maxes.get(k, 0), v)
    for entry in raw:
        process(entry["elements"] if "elements" in entry else [entry])
    return out, maxes


def read_nic_missed():
    try:
        with open(f"/sys/class/net/{IFACE}/statistics/rx_missed_errors") as f:
            return int(f.read().strip())
    except Exception:
        return 0


# ─── report ───────────────────────────────────────────────────────────────────

def print_report(label, clock, busy, buckets, bpf, bpf_max, counters, nic_miss, pkts):
    clock_1 = clock / 1000.0
    print(f"\n  ══ {label} ══")
    print(f"  ktime_get_ns overhead : {clock_1:.1f} ns/chiamata (calibrato a insmod)")
    print(f"  Pacchetti inviati     : {pkts:,}   NIC rx_missed: {nic_miss:,}   FPU busy: {busy:,}")
    cnt_names = {0: "cond", 1: "error", 2: "match(bad)", 3: "clean(drop)", 4: "pkt_tot", 5: "tcp_syn/fin/rst"}
    print("  Contatori XDP         : " +
          "  ".join(f"{cnt_names.get(k,k)}={v:,}" for k, v in sorted(counters.items()) if v))

    tot_cnt = sum(b["count"] for b in buckets.values())
    tot_mod = sum(b["total"] for b in buckets.values())
    bpf_cnt, bpf_sum, bpf_bytes = bpf.get(1, 0), bpf.get(0, 0), bpf.get(3, 0)
    print(f"\n  Scan totali (modulo)  : {tot_cnt:,}   (BPF: {bpf_cnt:,})")
    if bpf_cnt and tot_cnt:
        avg_bpf = bpf_sum / bpf_cnt
        avg_mod = tot_mod / tot_cnt
        print(f"  Media BPF-side        : {avg_bpf:,.0f} ns  (max {bpf_max.get(0,0)/1e3:,.1f} µs*)")
        print(f"  Media modulo          : {avg_mod:,.0f} ns")
        print(f"  Overhead kfunc+ptr    : {avg_bpf - avg_mod:,.0f} ns  "
              f"(al netto di ~{2*clock_1:.0f} ns di strumentazione BPF)")
        print("  *max per-CPU della somma, indicativo")

    hdr = (f"  {'payload':>9} {'scan#':>8} {'B/scan':>7} {'match%':>6} "
           f"{'lookup':>7} {'fpu_beg':>8} {'hs_scan':>8} {'sc_clean':>8} "
           f"{'sc_match':>8} {'fpu_end':>8} {'totale':>8} {'ns/B':>6} "
           f"{'min':>6} {'max':>9}")
    print("\n" + hdr)
    print("  " + "-" * (len(hdr) - 2))
    for i, lo in enumerate(BUCKET_LO):
        if lo not in buckets:
            continue
        b = buckets[lo]
        n = b["count"]
        hi = BUCKET_LO[i + 1] - 1 if i + 1 < len(BUCKET_LO) else 9999
        rng = f"{lo}-{hi}"
        avg_bytes = b["bytes"] / n
        scan_ns = b["scan"] / n
        nm, ncl = b["matches"], n - b["matches"]
        sc_match = b["scan_matched"] / nm if nm else 0
        sc_clean = (b["scan"] - b["scan_matched"]) / ncl if ncl else 0
        print(f"  {rng:>9} {n:>8,} {avg_bytes:>7.0f} {100*nm/n:>5.1f}% "
              f"{b['lookup']/n:>7.0f} {b['fpu_begin']/n:>8.0f} {scan_ns:>8.0f} "
              f"{sc_clean:>8.0f} {sc_match:>8.0f} "
              f"{b['fpu_end']/n:>8.0f} {b['total']/n:>8.0f} "
              f"{scan_ns/avg_bytes:>6.2f} {b['min']:>6} {b['max']:>9,}")
    if tot_cnt:
        w = {k: sum(b[k] for b in buckets.values()) / tot_cnt
             for k in ("lookup", "fpu_begin", "scan", "fpu_end", "total")}
        tot_bytes = sum(b["bytes"] for b in buckets.values())
        print("  " + "-" * (len(hdr) - 2))
        print(f"  {'TOTALE':>9} {tot_cnt:>8,} {tot_bytes/tot_cnt:>7.0f} {'':>6} "
              f"{w['lookup']:>7.0f} {w['fpu_begin']:>8.0f} {w['scan']:>8.0f} "
              f"{w['fpu_end']:>8.0f} {w['total']:>8.0f}")
        fixed = w["lookup"] + w["fpu_begin"] + w["fpu_end"]
        print(f"\n  Costo fisso per scan (lookup+FPU save/restore): {fixed:,.0f} ns "
              f"({100*fixed/w['total']:.1f}% del totale medio)")


def print_hist(hists):
    agg = {}
    for cpu, h in hists.items():
        for i, v in enumerate(h):
            agg[i] = agg.get(i, 0) + v
    tot = sum(agg.values())
    if not tot:
        return
    print("\n  Istogramma log2(totale ns) aggregato:")
    for i, v in sorted(agg.items()):
        if not v:
            continue
        lo, hi = 1 << max(i - 1, 0), (1 << i) - 1
        bar = "#" * max(1, int(60 * v / tot))
        print(f"    {lo:>8}-{hi:<8} ns {v:>9,}  {bar}")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    quick = "--quick" in sys.argv
    runs = [(20000, 1)] if quick else RUNS
    os.makedirs(OUT_DIR, exist_ok=True)

    print("[*] Teardown preventivo")
    teardown()
    time.sleep(0.5)

    print("[*] Setup modulo HS + XDP timing")
    maps = setup()

    print(f"[*] Connessione slave {SLAVE_IP}:{SLAVE_PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SLAVE_IP, SLAVE_PORT))

    try:
        for run_idx, (pps, loop) in enumerate(runs):
            est = PCAP_NPKTS * loop / pps
            label = f"run{run_idx} {pps}pps loop{loop}"
            print(f"\n{'='*70}\n  {label} — durata stimata {est:.0f}s\n{'='*70}")

            reset_stats()
            # azzera anche le mappe BPF: per le PERCPU_ARRAY bpftool replica
            # il singolo valore da 8 byte su tutte le CPU
            zero8 = ["00"] * 8
            for mname, nkeys in (("hs_timing", 4), ("counters", 8)):
                for k in range(nkeys):
                    key = [f"{b:02x}" for b in struct.pack("<I", k)]
                    _run(["bpftool", "map", "update", "id", str(maps[mname]),
                          "key"] + key + ["value"] + zero8)

            nic_before = read_nic_missed()
            sock.settimeout(est + 300)
            send_msg(sock, {"cmd": "start_test", "rate": pps, "pcap": PCAP,
                            "mode": "tcpreplay", "iface": SLAVE_IFACE,
                            "pps": pps, "loop": loop})
            resp = recv_msg(sock)
            pkts = resp.get("packets_send", 0)
            nic_miss = read_nic_missed() - nic_before

            raw = read_bench_raw()
            clock, busy, buckets, hists = parse_bench(raw)
            bpf, bpf_max = read_percpu_map(maps["hs_timing"], 4)
            counters, _ = read_percpu_map(maps["counters"], 8)

            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = os.path.join(OUT_DIR, f"hs_{pps}pps_loop{loop}_{ts}.txt")
            with open(out, "w") as f:
                f.write(f"# {label} pcap={PCAP} sent={pkts} nic_missed={nic_miss}\n")
                f.write(f"# bpf_map hs_timing (somme su CPU): {json.dumps(bpf)}\n")
                f.write(f"# counters: {json.dumps(counters)}\n")
                f.write(raw)
            print(f"  [saved] {out}")

            print_report(label, clock, busy, buckets, bpf, bpf_max,
                         counters, nic_miss, pkts)
            print_hist(hists)
    finally:
        sock.close()
        print("\n[*] Teardown finale")
        teardown(quiet=False)


if __name__ == "__main__":
    main()
