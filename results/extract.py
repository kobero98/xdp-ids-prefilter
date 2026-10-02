#!/usr/bin/env python3
"""Extract per-run metrics from raw orchestrator output into CSV files.

Each run of eval/run_experiment.py writes  <raw>/<test>/suricata-<variant>_<rate>_<rep>.txt
(Suricata stdout + a key:value trailer) and a matching .fast.log.  This script
turns them into:

  data/runs.csv     one row per run
  data/summary.csv  mean/min/max over repetitions, per (test, variant, rate)

Usage:
  python3 results/extract.py [RAW_DIR] [--tests t1,t2,...]

RAW_DIR defaults to results/raw.  Without --tests every sub-directory is used.

Metric definitions (as in the paper):
  afp_drops        Suricata "device: <if>: packets: N, drops: D" -> D
                   (packets dropped on the AF_PACKET ring: worker too slow)
  nic_rx_missed    delta of /sys/class/net/<if>/statistics/rx_missed_errors
                   (frames lost because the hardware RX ring overflowed)
  system_loss_pct  100 * (nic_rx_missed + afp_drops) / sent
  alerts           Suricata "counters: Alerts: N" (per run, reliable).
                   The orchestrator's own "Alerts:" trailer field is NOT used:
                   it was read from a stats.log shared across runs and can be stale.
  alerts_fastlog   number of lines in the run's .fast.log (cross-check)
"""
import argparse
import csv
import glob
import os
import re
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))

FNAME_RE = re.compile(r"^suricata-(?P<variant>.+)_(?P<rate>\d+)_(?P<rep>\d+)\.txt$")
DEVICE_RE = re.compile(r"device: \S+: packets: (\d+), drops: (\d+)")
ALERTS_RE = re.compile(r"counters: Alerts: (\d+)")
TRAILER = {"Packet": "sent", "NicRxPackets": "nic_rx_packets",
           "NicRxDropped": "nic_rx_dropped", "NicRxMissed": "nic_rx_missed",
           "AcXdpDropped": "ac_xdp_dropped"}

RUN_FIELDS = ["test", "variant", "rate_pps", "rep", "sent",
              "suricata_kernel_packets", "afp_drops", "nic_rx_packets",
              "nic_rx_dropped", "nic_rx_missed", "ac_xdp_dropped",
              "alerts", "alerts_fastlog", "system_loss_pct", "xdp_offload_pct"]


def parse_run(path):
    d = {k: "" for k in RUN_FIELDS}
    with open(path, errors="ignore") as f:
        for line in f:
            m = DEVICE_RE.search(line)
            if m:
                d["suricata_kernel_packets"] = int(m.group(1))
                d["afp_drops"] = int(m.group(2))
            m = ALERTS_RE.search(line)
            if m:
                d["alerts"] = int(m.group(1))
            key, sep, val = line.strip().partition(":")
            if sep and key in TRAILER and val.strip().lstrip("-").isdigit():
                d[TRAILER[key]] = int(val)
    fast = path[:-4] + ".fast.log"
    if os.path.exists(fast):
        with open(fast, errors="ignore") as f:
            d["alerts_fastlog"] = sum(1 for _ in f)
    sent = d["sent"] or 0
    if sent > 0 and d["afp_drops"] != "":
        d["system_loss_pct"] = round(
            100.0 * ((d["nic_rx_missed"] or 0) + d["afp_drops"]) / sent, 4)
        if d["ac_xdp_dropped"] != "":
            d["xdp_offload_pct"] = round(100.0 * d["ac_xdp_dropped"] / sent, 4)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw", nargs="?", default=os.path.join(HERE, "raw"))
    ap.add_argument("--tests", default="")
    ap.add_argument("--out", default=os.path.join(HERE, "data"))
    args = ap.parse_args()

    tests = [t for t in args.tests.split(",") if t] or sorted(
        d for d in os.listdir(args.raw) if os.path.isdir(os.path.join(args.raw, d)))

    rows = []
    for test in tests:
        for path in glob.glob(os.path.join(args.raw, test, "suricata-*.txt")):
            m = FNAME_RE.match(os.path.basename(path))
            if not m:
                continue
            d = parse_run(path)
            d.update(test=test, variant=m["variant"],
                     rate_pps=int(m["rate"]), rep=int(m["rep"]))
            rows.append(d)
    rows.sort(key=lambda r: (r["test"], r["variant"], r["rate_pps"], r["rep"]))

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "runs.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=RUN_FIELDS)
        w.writeheader()
        w.writerows(rows)

    groups = {}
    for r in rows:
        groups.setdefault((r["test"], r["variant"], r["rate_pps"]), []).append(r)
    metrics = ["system_loss_pct", "afp_drops", "nic_rx_missed",
               "xdp_offload_pct", "alerts"]
    fields = ["test", "variant", "rate_pps", "reps"] + [
        f"{m}_{s}" for m in metrics for s in ("mean", "min", "max")]
    with open(os.path.join(args.out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for (test, variant, rate), rs in sorted(groups.items()):
            out = {"test": test, "variant": variant, "rate_pps": rate, "reps": len(rs)}
            for m in metrics:
                vals = [r[m] for r in rs if r[m] != ""]
                if vals:
                    out[f"{m}_mean"] = round(statistics.mean(vals), 4)
                    out[f"{m}_min"] = min(vals)
                    out[f"{m}_max"] = max(vals)
            w.writerow(out)
    print(f"{len(rows)} runs, {len(groups)} points -> {args.out}/runs.csv, summary.csv")


if __name__ == "__main__":
    main()
