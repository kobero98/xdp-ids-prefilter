# Results

All numbers in the paper come from the files in this directory.

```
raw/<test>/suricata-<variant>_<rate>_<rep>.txt   one run: Suricata stdout + key:value trailer
raw/hs_microbench/hs_<pps>pps_*.txt             dump of /sys/kernel/debug/rex_bench (bench=1)
data/runs.csv            one row per run          (extract.py)
data/summary.csv         mean/min/max over reps   (extract.py)
data/hs_microbench.csv   per-bucket HS scan cost  (extract_hs_microbench.py)
figures/                 paper figures            (plot_figures.py)
```

`variant` is `plain` (Suricata alone) or `ac` (Suricata + XDP filter). `rate` is the
offered load in packets/s.

## Experiments

| Test | Generator | Rates | Reps | Used for |
|---|---|---|---|---|
| `highrate_{NF,mixed,good}_dpdk` | DPDK `pcap_replay -P`, single core, 45 s | 20k–500k pps | 3 | Fig. system loss (plotted up to 400k) |
| `mispredict_good_on_mixed_dpdk` | same | 20k–500k pps | 3 | Fig. misprediction |
| `lowrate4_{NF,mixed,good}` | `tcpreplay --pps`, whole passes | 10k–250k pps | 1 | Table alerts + offload (10k point) |
| `mispredict_good_on_mixed` | same | 10k–250k pps | 1 | misprediction, alert equality |

## Columns of `runs.csv`

| Column | Source | Meaning |
|---|---|---|
| `sent` | slave | packets sent by the generator |
| `suricata_kernel_packets`, `afp_drops` | Suricata `device: <if>: packets: N, drops: D` | packets seen / dropped on the AF_PACKET ring |
| `nic_rx_packets`, `nic_rx_dropped`, `nic_rx_missed` | `/sys/class/net/<if>/statistics` deltas | `rx_missed` = hardware RX ring overflow (before XDP) |
| `ac_xdp_dropped` | BPF map `xdp_drop_cnt` | packets diverted by the filter |
| `alerts` | Suricata `counters: Alerts: N` | alerts of that run |
| `alerts_fastlog` | lines in the run's `fast.log` | cross-check of `alerts` (identical on all 338 runs) |
| `system_loss_pct` | `100·(nic_rx_missed + afp_drops)/sent` | headline metric of the paper |
| `xdp_offload_pct` | `100·ac_xdp_dropped/sent` | share of traffic removed before Suricata |

Two caveats on the metrics:

- **Alert source.** The original raw files had an extra `Alerts:` trailer field, which
  the orchestrator read from a `stats.log` shared across runs, so it could be stale. It
  has been removed. Alerts always come from Suricata's own per-run counter.
- **NIC counters.** NIC `rx_packets` counts frames delivered to the stack *after* XDP.
  Packets the filter diverted show up only in `ac_xdp_dropped`.

In `time` mode a run is not a whole number of passes over the pcap. Alert counts are
therefore comparable only on the `tcpreplay` single-pass points.

## Reproducing the figures
```bash
python3 results/extract.py --tests highrate_NF_dpdk,highrate_mixed_dpdk,highrate_good_dpdk,mispredict_good_on_mixed_dpdk,lowrate4_NF,lowrate4_mixed,lowrate4_good,mispredict_good_on_mixed
python3 results/extract_hs_microbench.py
python3 results/plot_figures.py
```
The committed `runs.csv` was generated with the `fast.log` files present.
`.fast.log` files are not tracked (they hold alert payload metadata), so re-running
`extract.py` on this repo leaves `alerts_fastlog` empty. Every other column is reproduced.

## Hyperscan in-kernel microbenchmark
Measured with `xdp_regex_module bench=1`, in the same softirq context and on the same
pattern set (`patterns/mixed.hs`) and pcap as the AC filter. Traffic is sent slowly
(5k/20k pps) so that each scan is isolated. `raw/hs_microbench/NOTES_it.md` holds the
full analysis (in Italian). Main points:

- Total cost per scan: 5.9 µs (≥64 B payloads). 95 % of it is `hs_scan`. Clean
  packets cost 4.4 µs; matched packets cost 20 µs.
- `kernel_fpu_begin/end` costs 60–130 ns per side, about 2 % of the total.
- The AC engine scans a 1500 B payload in 4.7 µs and a 256 B payload in 1.0 µs, with no FPU use.
