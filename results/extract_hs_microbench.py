#!/usr/bin/env python3
"""Summarise the in-kernel Hyperscan microbenchmark (eval/hs_timing_test.py).

Input : results/raw/hs_microbench/hs_<pps>pps_loop<n>_<ts>.txt
        (dump of /sys/kernel/debug/rex_bench written by xdp_regex_module bench=1)
Output: data/hs_microbench.csv, one row per (run, payload-length bucket),
        counters summed over CPUs, per-scan averages in ns.

Clock correction: each phase is delimited by one ktime_get_ns() call, whose
cost is calibrated at insmod (clock_ns_x1000). It is subtracted once per phase
and four times from the total, as in the original analysis.
"""
import csv
import glob
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw", "hs_microbench")
OUT = os.path.join(HERE, "data", "hs_microbench.csv")

PHASES = ["lookup", "fpu_begin", "scan", "fpu_end"]
FIELDS = ["run", "pps", "bucket_lo", "count", "bytes", "matches",
          "avg_bytes"] + [f"{p}_ns" for p in PHASES] + [
          "total_ns", "scan_matched_share", "clock_ns"]


def main():
    rows = []
    for path in sorted(glob.glob(os.path.join(RAW, "hs_*pps_*.txt"))):
        name = os.path.basename(path)[:-4]
        pps = int(re.search(r"hs_(\d+)pps", name).group(1))
        clock = 0.0
        agg = {}
        with open(path) as f:
            for line in f:
                tok = line.split()
                if tok[:1] == ["clock_ns_x1000"]:
                    clock = int(tok[1]) / 1000.0
                elif len(tok) > 4 and tok[0] == "cpu" and tok[2] == "bucket":
                    kv = dict(zip(tok[4::2], map(int, tok[5::2])))
                    a = agg.setdefault(int(tok[3]), {})
                    for k, v in kv.items():
                        a[k] = a.get(k, 0) + v
        for lo, a in sorted(agg.items()):
            n = a["count"]
            if not n:
                continue
            r = {"run": name, "pps": pps, "bucket_lo": lo, "count": n,
                 "bytes": a["bytes"], "matches": a["matches"],
                 "avg_bytes": round(a["bytes"] / n, 1), "clock_ns": clock}
            for p in PHASES:
                r[f"{p}_ns"] = round(a[p] / n - clock, 1)
            r["total_ns"] = round(a["total"] / n - 4 * clock, 1)
            r["scan_matched_share"] = round(a["scan_matched"] / a["scan"], 4) if a["scan"] else 0
            rows.append(r)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
