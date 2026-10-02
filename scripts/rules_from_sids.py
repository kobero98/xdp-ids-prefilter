#!/usr/bin/env python3
"""Rebuild a per-capture rule file from a full ruleset and a sid:rev list.

The paper's Suricata runs loaded build/<capture>/filtered.rules, produced by the
analyzer from a snapshot of `suricata-update` (ET Open + Suricata built-ins).
rulesets/<capture>_sids.txt records exactly which sid:rev were loaded, so the
same rule set can be rebuilt without the training pcap:

  python3 scripts/rules_from_sids.py suricata.rules rulesets/NF_sids.txt > build/NF/filtered.rules

Rules missing from the given ruleset, or present with a different rev, are
reported on stderr (newer ET snapshots change revisions).
"""
import re
import sys

SID_RE = re.compile(r"sid:\s*(\d+);.*rev:\s*(\d+)")


def main(rules_path, sids_path):
    want = dict(line.strip().split(":") for line in open(sids_path) if line.strip())
    found, mismatched = set(), 0
    with open(rules_path, errors="replace") as f:
        for line in f:
            m = SID_RE.search(line)
            if not m or line.lstrip().startswith("#") or m.group(1) not in want:
                continue
            sid, rev = m.groups()
            if sid in found:
                continue
            if want[sid] != rev:
                mismatched += 1
            found.add(sid)
            sys.stdout.write(line)
    missing = len(want) - len(found)
    print(f"[rules_from_sids] {len(found)}/{len(want)} rules written, "
          f"{missing} missing, {mismatched} with a different rev", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
