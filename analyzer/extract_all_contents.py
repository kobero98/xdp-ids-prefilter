#!/usr/bin/env python3
"""
extract_all_contents.py — Estrae TUTTI i content keyword da ogni regola Suricata.

Per ogni stringa unica assegna un ID progressivo.

Output:
  all_contents.hs    — tutti i content in formato Hyperscan (ID:/regex/flags)
  content_map.txt    — SID ID1 ID2 ...  (una riga per regola)

Uso:
  python3 extract_all_contents.py <rules_file>
               [-o all_contents.hs]
               [-m content_map.txt]
               [--min-bytes 4]
"""

import re
import sys

MIN_BYTES_DEFAULT = 4  # scarta content con meno di N byte decodificati
REGEX_META = set(r'.*+?[](){}|^$\\')


# ---------------------------------------------------------------------------
# Conversione formato Suricata → Hyperscan regex
# ---------------------------------------------------------------------------

def pipe_to_hs(s):
    """
    Input:  stringa tra le virgolette di content:"...", es: "GET|20|/path"
    Output: (hs_regex: str, nbytes: int)

    Converte:
      - |xx yy zz| → \\xNN\\xNN\\xNN
      - caratteri ASCII che sono metacaratteri regex → escaped
    """
    result = []
    nbytes = 0
    i = 0
    n = len(s)

    while i < n:
        if s[i] == '|':
            # blocco hex: raccoglie coppie finché trova '|' di chiusura
            i += 1
            hex_chars = []
            while i < n and s[i] != '|':
                if s[i] == ' ':
                    i += 1
                    continue
                hex_chars.append(s[i])
                i += 1
            if i < n:
                i += 1  # salta '|' di chiusura
            # processa coppie
            j = 0
            while j + 1 < len(hex_chars):
                hi, lo = hex_chars[j], hex_chars[j + 1]
                if (hi in '0123456789abcdefABCDEF' and
                        lo in '0123456789abcdefABCDEF'):
                    result.append(f'\\x{hi.lower()}{lo.lower()}')
                    nbytes += 1
                j += 2
        else:
            c = s[i]
            if c in REGEX_META:
                result.append('\\' + c)
            else:
                result.append(c)
            nbytes += 1
            i += 1

    return ''.join(result), nbytes


# ---------------------------------------------------------------------------
# Estrazione di tutti i content da una riga di regola
# ---------------------------------------------------------------------------

def extract_contents(rule_line, min_bytes):
    """
    Ritorna lista di (hs_expr: str, nocase: bool, nbytes: int)
    per tutti i content non-negati della regola.
    """
    results = []
    n = len(rule_line)
    p = 0

    while p < n:
        idx = rule_line.find('content:', p)
        if idx < 0:
            break

        pos = idx + 8  # subito dopo 'content:'

        # salta spazi
        while pos < n and rule_line[pos] == ' ':
            pos += 1

        # negazione?
        negated = False
        if pos < n and rule_line[pos] == '!':
            negated = True
            pos += 1

        # salta spazi
        while pos < n and rule_line[pos] == ' ':
            pos += 1

        # deve seguire la virgoletta aperta
        if pos >= n or rule_line[pos] != '"':
            p = idx + 8
            continue
        pos += 1  # salta "

        # trova la " di chiusura
        start = pos
        while pos < n and rule_line[pos] != '"':
            pos += 1
        if pos >= n:
            break

        content_str = rule_line[start:pos]
        pos += 1  # salta "

        if negated:
            p = pos
            continue

        hs, nbytes = pipe_to_hs(content_str)
        if nbytes >= min_bytes and hs:
            # nocase: cerca nella porzione fino al prossimo 'content:' o ')'
            rest_start = pos
            next_c = rule_line.find('content:', pos)
            next_p = rule_line.find(')', pos)
            if next_c < 0:
                rest_end = next_p if next_p >= 0 else n
            elif next_p < 0:
                rest_end = next_c
            else:
                rest_end = min(next_c, next_p)

            rest = rule_line[rest_start:rest_end]
            nocase = 'nocase' in rest

            results.append((hs, nocase, nbytes))

        p = pos

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if not args or args[0].startswith('-'):
        print(f"Uso: {sys.argv[0]} <rules_file> [-o all_contents.hs] "
              f"[-m content_map.txt] [--min-bytes N]")
        sys.exit(1)

    rules_file = args[0]
    hs_out     = 'all_contents.hs'
    map_out    = 'content_map.txt'
    min_bytes  = MIN_BYTES_DEFAULT

    i = 1
    while i < len(args):
        if args[i] == '-o'         and i+1 < len(args): hs_out    = args[i+1]; i += 2
        elif args[i] == '-m'       and i+1 < len(args): map_out   = args[i+1]; i += 2
        elif args[i] == '--min-bytes' and i+1 < len(args): min_bytes = int(args[i+1]); i += 2
        else: i += 1

    # content_table: (hs_expr, nocase) → content_ID
    content_table  = {}
    next_id        = [1]
    # id_to_content: id → (hs_expr, nocase)
    id_to_content  = {}

    def intern(hs, nocase):
        key = (hs, nocase)
        if key not in content_table:
            cid = next_id[0]
            next_id[0] += 1
            content_table[key] = cid
            id_to_content[cid] = (hs, nocase)
        return content_table[key]

    rule_entries = []  # list of (sid, [content_ids])
    total_rules  = 0
    total_conts  = 0
    no_content   = 0

    print(f"[*] Leggo {rules_file}...")
    with open(rules_file) as f:
        for line in f:
            line = line.rstrip('\n\r')
            if not line or line.startswith('#'):
                continue

            m = re.search(r'\bsid:(\d+)', line)
            if not m:
                continue
            sid = int(m.group(1))
            total_rules += 1

            contents = extract_contents(line, min_bytes)
            if not contents:
                no_content += 1
                continue

            ids = []
            for (hs, nocase, _nbytes) in contents:
                cid = intern(hs, nocase)
                ids.append(cid)
                total_conts += 1

            rule_entries.append((sid, ids))

    unique = len(content_table)
    print(f"    Regole lette:             {total_rules}")
    print(f"    Regole con content:       {len(rule_entries)}")
    print(f"    Regole senza content:     {no_content}")
    print(f"    Content totali estratti:  {total_conts}")
    print(f"    Content unici:            {unique}")

    # Scrivi all_contents.hs
    print(f"[*] Scrivo {hs_out}...")
    with open(hs_out, 'w') as f:
        for cid in sorted(id_to_content):
            hs, nocase = id_to_content[cid]
            flag = 'i' if nocase else ''
            f.write(f"{cid}:/{hs}/{flag}\n")
    print(f"    {unique} pattern scritti")

    # Scrivi content_map.txt
    print(f"[*] Scrivo {map_out}...")
    with open(map_out, 'w') as f:
        for sid, ids in rule_entries:
            # deduplica mantenendo ordine
            seen = set()
            uniq_ids = []
            for cid in ids:
                if cid not in seen:
                    seen.add(cid)
                    uniq_ids.append(cid)
            f.write(str(sid) + ' ' + ' '.join(map(str, uniq_ids)) + '\n')
    print(f"    {len(rule_entries)} regole scritte")


if __name__ == '__main__':
    main()
