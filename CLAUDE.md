# CLAUDE.md

Artifact of the IEEE CloudNet 2026 paper "Exploiting Rule Skewness: An eBPF/XDP
Prefilter for Signature-Based Intrusion Detection". See README.md for the full guide.

- Testbed-specific values (NICs, IPs, PCI, paths) live ONLY in `config.env`; shell
  scripts source `scripts/env.sh`, Python imports `eval/settings.py`. Never hardcode them.
- `bash scripts/build_paper_dbs.sh` rebuilds the paper's rule files and .acdb DBs and
  checks them against `rulesets/SHA256SUMS`: run it after touching `kernel/ac/ac_build.c`.
- Live tests: `python3 eval/run_experiment.py eval/test_case/<x>.yaml`, one at a time, in
  the foreground (background masters interleave runs on the slave).
- Metrics: alerts come from Suricata's `counters: Alerts:` line (per run); system loss
  = (rx_missed + AF_PACKET drops)/sent; NIC rx_packets is post-XDP.
- `results/data/*.csv` are derived from `results/raw/`; regenerate with `results/extract.py`.
- Generated files go to `build/` (git-ignored); pcaps and full rulesets are never committed.
