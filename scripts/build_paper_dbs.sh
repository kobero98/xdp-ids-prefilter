#!/bin/bash
# build_paper_dbs.sh — rebuild the exact paper artefacts WITHOUT the pcaps:
#
#   build/<capture>/filtered.rules   rules loaded by Suricata
#                                    (snapshot rulesets/suricata-rules-2024-11-12 + sid list)
#   build/<capture>/<capture>.acdb   blocklist DB (byte-identical to the paper's)
#
# for capture in NF, mixed, good. To derive them from scratch from a pcap and
# a ruleset use sim/run_pipeline.sh instead.
set -e
. "$(dirname "$0")/env.sh"

make -s -C "$REPO_ROOT/kernel/ac" ac_build
SNAP="$REPO_ROOT/rulesets/suricata-rules-2024-11-12.rules.xz"
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
xz -dc "$SNAP" > "$TMP"

for c in NF mixed good; do
    mkdir -p "$BUILD_DIR/$c"
    python3 "$REPO_ROOT/scripts/rules_from_sids.py" "$TMP" \
        "$REPO_ROOT/rulesets/${c}_sids.txt" > "$BUILD_DIR/$c/filtered.rules"
    "$REPO_ROOT/kernel/ac/ac_build" -n 262144 -t 12 \
        -o "$BUILD_DIR/$c/$c.acdb" "$REPO_ROOT/patterns/$c.hs" > "$BUILD_DIR/$c/ac_build.log" 2>&1
    echo "[+] $c: $(grep -c . "$BUILD_DIR/$c/filtered.rules") rules, $(grep 'Stati totali' "$BUILD_DIR/$c/ac_build.log" | tail -1 | awk '{print $NF}') DFA states"
done
# checksums assume the default BUILD_DIR=build
(cd "$REPO_ROOT" && sha256sum -c rulesets/SHA256SUMS --quiet) && echo "[+] artefacts are byte-identical to the paper (rulesets/SHA256SUMS)"
