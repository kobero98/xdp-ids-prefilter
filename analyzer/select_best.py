#!/usr/bin/env python3
"""
select_best.py — Sceglie il content più selettivo per ogni regola.

Per ogni regola in content_map.txt:
  - Recupera i conteggi di match empirici per tutti i suoi content
  - Sceglie quello con il match_count più basso (mai visto sul PCAP = ottimo)
  - Se il migliore supera --max-pct, la regola viene scartata

Output: patterns_empirical.hs  (stesso formato di patterns.hs, pronto per hscollider)
        selection_report.txt   (dettaglio delle scelte per ogni regola)

Uso:
  python3 select_best.py
          [-a all_contents.hs]
          [-m content_map.txt]
          [-c match_counts.txt]
          [-r suricata.rules]        (opzionale: per mostrare msg: della regola)
          [-o patterns_empirical.hs]
          [--max-pct 20.0]           (scarta se miglior content > X% del traffico)
          [--scope N]                (pacchetti in scope usati durante la scansione)
"""

import sys
import re
import os


def load_all_contents(path):
    """Ritorna dict: id → (hs_expr, flags)"""
    d = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.match(r'^(\d+):/(.*)/([^/]*)$', line)
            if not m:
                continue
            cid   = int(m.group(1))
            hs    = m.group(2)
            flags = m.group(3)
            d[cid] = (hs, flags)
    return d


def load_match_counts(path):
    """
    Ritorna (counts_dict, scope).
    counts_dict: id → count
    scope: pacchetti in scope (letti dalla prima riga # scope: N)
    """
    counts = {}
    scope  = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('# scope:'):
                try:
                    scope = int(line.split(':', 1)[1].strip())
                except ValueError:
                    pass
                continue
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                counts[int(parts[0])] = int(parts[1])
    return counts, scope


def load_content_map(path):
    """Ritorna dict: sid → [content_ids]"""
    d = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = list(map(int, line.split()))
            d[parts[0]] = parts[1:]
    return d


def load_rule_msgs(path):
    """Ritorna dict: sid → msg string (opzionale, per il report)"""
    d = {}
    if not path or not os.path.exists(path):
        return d
    with open(path) as f:
        for line in f:
            if line.startswith('#'):
                continue
            m_sid = re.search(r'\bsid:(\d+)', line)
            m_msg = re.search(r'msg:"([^"]*)"', line)
            if m_sid and m_msg:
                d[int(m_sid.group(1))] = m_msg.group(1)
    return d


def main():
    all_contents_file = 'all_contents.hs'
    content_map_file  = 'content_map.txt'
    match_counts_file = 'match_counts.txt'
    rules_file        = None
    output_file       = 'patterns_empirical.hs'
    report_file       = 'selection_report.txt'
    max_pct           = 100.0
    scope_override    = 0

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if   a == '-a' and i+1 < len(args): all_contents_file = args[i+1]; i += 2
        elif a == '-m' and i+1 < len(args): content_map_file  = args[i+1]; i += 2
        elif a == '-c' and i+1 < len(args): match_counts_file = args[i+1]; i += 2
        elif a == '-r' and i+1 < len(args): rules_file        = args[i+1]; i += 2
        elif a == '-o' and i+1 < len(args): output_file       = args[i+1]; i += 2
        elif a == '--max-pct'   and i+1 < len(args): max_pct        = float(args[i+1]); i += 2
        elif a == '--scope'     and i+1 < len(args): scope_override = int(args[i+1]);   i += 2
        else: i += 1

    print(f"[*] Carico {all_contents_file}...")
    id_to_pat = load_all_contents(all_contents_file)
    print(f"    {len(id_to_pat)} content unici")

    print(f"[*] Carico {match_counts_file}...")
    counts, scope = load_match_counts(match_counts_file)
    if scope_override:
        scope = scope_override
    print(f"    {len(counts)} content con match > 0  |  scope = {scope} pacchetti")

    print(f"[*] Carico {content_map_file}...")
    sid_to_ids = load_content_map(content_map_file)
    print(f"    {len(sid_to_ids)} regole")

    msgs = load_rule_msgs(rules_file)

    # soglia assoluta: max_count = scope * max_pct / 100
    max_count = scope * max_pct / 100.0 if scope > 0 else float('inf')

    # -----------------------------------------------------------------------
    # Selezione
    # -----------------------------------------------------------------------
    out_patterns = []   # list of (hs, flags) — deduplicate prima di scrivere
    seen_patterns = set()

    n_ok        = 0
    n_zero      = 0   # content mai visti sul PCAP → massima selettività
    n_filtered  = 0   # scartati per max_pct
    n_no_pat    = 0   # content_id non trovato in all_contents.hs

    report_lines = []
    report_lines.append(
        f"# REPORT SELEZIONE BEST CONTENT\n"
        f"# scope={scope}  max_pct={max_pct}%  max_count={int(max_count) if scope else 'inf'}\n"
        f"# formato: SID | best_count (%) | all_counts | hs_pattern | msg\n"
        f"#{'='*100}\n"
    )

    for sid in sorted(sid_to_ids.keys()):
        cids = sid_to_ids[sid]
        if not cids:
            continue

        # raccoglie (count, cid) per tutti i content della regola
        scored = []
        for cid in cids:
            cnt = counts.get(cid, 0)
            scored.append((cnt, cid))
        scored.sort()  # ascending: il primo è il meno frequente

        best_count, best_id = scored[0]

        # scarta se sopra soglia
        if best_count > max_count:
            n_filtered += 1
            pct = 100.0 * best_count / scope if scope else 0
            report_lines.append(
                f"SCARTATO  SID:{sid:8d}  best={best_count}({pct:.1f}%)  "
                f"[{msgs.get(sid, '')}]"
            )
            continue

        if best_id not in id_to_pat:
            n_no_pat += 1
            continue

        hs, flags = id_to_pat[best_id]

        # deduplica: non scrivere lo stesso pattern due volte
        key = (hs, flags)
        if key in seen_patterns:
            # pattern già usato da un'altra regola — includi comunque
            # (Hyperscan deduplica internamente, ma vogliamo ID distinti)
            pass
        seen_patterns.add(key)

        if best_count == 0:
            n_zero += 1
        n_ok += 1

        out_patterns.append((hs, flags))

        # riga di report
        all_counts_str = ' '.join(
            f"{counts.get(c,0)}" for _, c in scored
        )
        pct = 100.0 * best_count / scope if scope else 0
        report_lines.append(
            f"OK        SID:{sid:8d}  best={best_count}({pct:5.1f}%)  "
            f"all=[{all_counts_str}]  "
            f"/{hs[:60]}/  [{msgs.get(sid, '')}]"
        )

    # -----------------------------------------------------------------------
    # Scrivi patterns_empirical.hs
    # -----------------------------------------------------------------------
    print(f"[*] Scrivo {output_file}...")
    with open(output_file, 'w') as f:
        for pat_id, (hs, flags) in enumerate(out_patterns, start=1):
            f.write(f"{pat_id}:/{hs}/{flags}\n")
    print(f"    {len(out_patterns)} pattern scritti")

    # -----------------------------------------------------------------------
    # Scrivi report
    # -----------------------------------------------------------------------
    with open(report_file, 'w') as f:
        f.write('\n'.join(report_lines) + '\n')
    print(f"[*] Report dettagliato: {report_file}")

    # -----------------------------------------------------------------------
    # Statistiche finali
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"RIEPILOGO SELEZIONE")
    print(f"{'='*60}")
    print(f"  Regole totali in input:       {len(sid_to_ids)}")
    print(f"  Pattern accettati:            {n_ok}")
    print(f"    di cui mai visti (count=0): {n_zero}  "
          f"({100*n_zero/max(n_ok,1):.1f}%)")
    print(f"  Scartati (>= {max_pct:.0f}% traffico):   {n_filtered}")
    print(f"  Scartati (content non trovato): {n_no_pat}")
    print(f"{'='*60}")

    if scope > 0 and n_ok > 0:
        # distribuzione dei match count per i pattern accettati
        buckets = [(0, 0), (1, 10), (11, 100), (101, 1000), (1001, 10000),
                   (10001, 10**9)]
        print(f"\nDistribuzione match_count dei pattern scelti:")
        for lo, hi in buckets:
            nn = sum(1 for (hs, flags) in out_patterns
                     # need to look up counts — use a joined structure
                     # simplified: count from report
                     if True)  # placeholder
            # Actually let's compute from scored data properly
            pass

        # Proper distribution
        best_counts_list = []
        for sid in sorted(sid_to_ids.keys()):
            cids = sid_to_ids[sid]
            if not cids: continue
            scored = sorted((counts.get(c, 0), c) for c in cids)
            bc, bid = scored[0]
            if bc <= max_count and bid in id_to_pat:
                best_counts_list.append(bc)

        bkts = [(0,0,'mai visto'), (1,10,'1-10'), (11,100,'11-100'),
                (101,1000,'101-1K'), (1001,10000,'1K-10K'), (10001,10**9,'10K+')]
        for lo, hi, lbl in bkts:
            nn = sum(1 for c in best_counts_list if lo <= c <= hi)
            pct = 100.0 * nn / len(best_counts_list) if best_counts_list else 0
            bar = '|' * int(30 * pct / 100)
            print(f"  {lbl:12s}: {nn:6d}  ({pct:5.1f}%)  {bar}")


if __name__ == '__main__':
    main()
