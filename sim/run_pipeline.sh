#!/bin/bash
# run_pipeline.sh — build the blocklist database for one capture.
#
# Usage: bash sim/run_pipeline.sh <name> <pcap> <suricata.rules> [max_pct=0.1]
#
#   1. analyzer/run_empirical.sh  dominant protocol/port, rules for it, and the
#                                 least-frequent content of each rule in the pcap
#   2. kernel/ac/ac_build         patterns -> Hopcroft-minimised AC DFA (.acdb),
#                                 16-bit states, patterns truncated to 12 bytes,
#                                 n-gram prefilter bitmaps
#   3. sim/sim_ac                 bit-exact offline replay of the XDP verdict
#
# Output in $BUILD_DIR/<name>/:
#   filtered.rules      rules loaded by Suricata (eval YAML: rules_file)
#   patterns.hs         selected filtering patterns
#   <name>.acdb         blocklist DB uploaded to xdp_ac_module (eval YAML: acdb_file)
#   proto_meta.txt      detected protocol / port (-> filter_port)
#   sim_report.txt      expected XDP verdicts (offload %) on the pcap
set -e
. "$(dirname "$0")/../scripts/env.sh"

NAME="${1:?usage: $0 <name> <pcap> <rules> [max_pct]}"
PCAP="$(realpath "${2:?pcap missing}")"
RULES="$(realpath "${3:?rules missing}")"
MAX_PCT="${4:-0.1}"
OUT="$BUILD_DIR/$NAME"
mkdir -p "$OUT"

make -s -C "$REPO_ROOT/analyzer" analyzer pcap_hs_scan
make -s -C "$REPO_ROOT/kernel/ac" ac_build
make -s -C "$REPO_ROOT/sim"

echo "[1/3] pattern selection ($NAME)"
( cd "$REPO_ROOT/analyzer" && bash run_empirical.sh "$PCAP" "$RULES" "$MAX_PCT" )
for f in patterns_empirical.hs proto_meta.txt filtered.rules selection_report.txt; do
    cp "$REPO_ROOT/analyzer/$f" "$OUT/" 2>/dev/null || true
done
mv "$OUT/patterns_empirical.hs" "$OUT/patterns.hs"
PORT=$(awk '/^PORT:/{print $2}' "$OUT/proto_meta.txt")
echo "    port=$PORT patterns=$(wc -l < "$OUT/patterns.hs")"

echo "[2/3] ac_build"
"$REPO_ROOT/kernel/ac/ac_build" -n 262144 -t 12 -o "$OUT/$NAME.acdb" "$OUT/patterns.hs"

echo "[3/3] offline XDP simulation"
"$REPO_ROOT/sim/sim_ac" -d "$OUT/$NAME.acdb" -r "$PCAP" -p "$PORT" -P "$OUT/patterns.hs" \
    2>&1 | tee "$OUT/sim_report.txt"
echo "[+] done: $OUT"
