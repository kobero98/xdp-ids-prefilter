#!/bin/bash
# run_empirical.sh — Pipeline empirica completa
#
# Sostituisce la selezione euristica di main.c con una selezione basata su
# misurazioni reali: per ogni regola viene scelto il content che matchava
# MENO sul PCAP di riferimento (massima selettività).
#
# Uso:
#   bash run_empirical.sh input.pcap suricata.rules [max_pct]
#
#   max_pct  — soglia: scarta regole il cui miglior content supera X% del
#              traffico in-scope.  Default: 0.1
#
# Output:
#   filtered.rules        — regole filtrate per protocollo (da main.c)
#   proto_meta.txt        — protocollo e porta selezionati (da main.c)
#   all_contents.hs       — tutti i content estratti da filtered.rules
#   content_map.txt       — mapping SID → content IDs
#   match_counts.txt      — conteggi empirici per ogni content
#   patterns_empirical.hs — file pattern finale (input per hscollider)
#   selection_report.txt  — dettaglio delle scelte per ogni regola

set -e

PCAP="$1"
RULES="$2"
MAX_PCT="${3:-0.1}"

if [ -z "$PCAP" ] || [ -z "$RULES" ]; then
    echo "Uso: $0 input.pcap suricata.rules [max_pct]"
    echo ""
    echo "  max_pct: soglia massima match sul traffico benigno (default 0.1%)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================"
echo " Pipeline Empirica Hyperscan"
echo "========================================================"
echo "  PCAP    : $PCAP"
echo "  Regole  : $RULES"
echo "  Max-pct : $MAX_PCT%"
echo "========================================================"
echo ""

# ── STEP 1: analisi PCAP + filtro regole per protocollo ──────────────────────
echo "[1/4] Analisi PCAP e filtraggio regole per protocollo..."
./analyzer "$PCAP" "$RULES"

# Leggi porta dalla metadata scritta da analyzer
if [ ! -f proto_meta.txt ]; then
    echo "[!] proto_meta.txt non trovato — abort"
    exit 1
fi
PORT=$(awk '/^PORT:/{print $2}' proto_meta.txt)
PROTOS=$(awk '/^PROTOS:/{$1=""; print $0}' proto_meta.txt | xargs)
echo ""
echo "    Protocolli selezionati : $PROTOS"
echo "    Porta per la scansione : $PORT (0 = tutto)"
echo ""

# ── STEP 2: estrai TUTTI i content da dominant.rules ─────────────────────────
# dominant.rules contiene SOLO le regole del proto dominante che hanno passato
# l'estrazione del content — è il sottoinsieme che alimenta l'AC pre-filter.
echo "[2/4] Estrazione di tutti i content da dominant.rules..."
python3 extract_all_contents.py dominant.rules \
    -o all_contents.hs \
    -m content_map.txt
echo ""

# ── STEP 3: scansiona il PCAP per misurare frequenza di ogni content ─────────
echo "[3/4] Scansione PCAP (porta=$PORT) per misurare selettività dei content..."
./pcap_hs_scan \
    -p "$PORT" \
    -O match_counts.txt \
    -o /dev/null \
    "$PCAP" all_contents.hs
echo ""

# ── STEP 4: scegli il content migliore per ogni regola ───────────────────────
echo "[4/4] Selezione content ottimali (max-pct=$MAX_PCT%)..."
python3 select_best.py \
    -a all_contents.hs \
    -m content_map.txt \
    -c match_counts.txt \
    -r "$RULES" \
    -o patterns_empirical.hs \
    --max-pct "$MAX_PCT"

echo ""
echo "========================================================"
echo " Completato."
echo "  patterns_empirical.hs  →  input per hscollider / init.sh"
echo "  selection_report.txt   →  dettaglio scelte per regola"
echo "========================================================"
