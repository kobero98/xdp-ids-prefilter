# Datasets

The captures are public but large (0.8–1.5 GB each), so they are not redistributed.
Place them in `datasets/pcap/` (DUT, for the Analyzer) and in `SLAVE_PCAP_DIR` on the
traffic generator. Both locations are git-ignored.

| Name in the paper | File used | Packets | Source | SHA-256 (original file) |
|---|---|---|---|---|
| NF | `output_NF_2015_03.pcap` | 2 033 806 | Netresec public PCAP repository: the `snort.log.*` captures of 2015-03-05 … 2015-03-10, merged in time order | `fd3209fdaf68ac54eaf55debdfe6e9af1a301a77430431bcb4429c44ca8dabc3` (merged file) |
| mixed | `mixed_output.pcap` | 1 437 980 | Stratosphere IPS, `mixed_capture`, `2015-07-28_mixed.pcap` | `30b8bf1c330825222b118205f73ecc8041ed305bfc82aed52781d998591665dd` |
| good | `output_good.pcap` | 863 371 | Stratosphere IPS, `normal_capture` | `b7c33b7131058b61469d65d182e947a1676297160d7997debfa527bd290428b4` |

- Netresec: https://www.netresec.com/?page=PcapFiles
- Stratosphere IPS: https://www.stratosphereips.org/datasets-overview

<!-- TODO(author): exact download URLs of the three captures -->

## Preparing the pcaps for replay
For the replay, only the Ethernet addresses were rewritten, towards the DUT data NIC
(dst) and the generator NIC (src). The payload and IP headers are unchanged. The
Analyzer reads the same packets either way.

```bash
tcprewrite --enet-dmac=<DUT data NIC MAC> --enet-smac=<slave NIC MAC> \
           --infile=2015-07-28_mixed.pcap --outfile=mixed_output.pcap
```

To merge the NF captures:
```bash
mergecap -w output_NF_2015_03.pcap <netresec dir>/2015-03-0{5..9}/snort.log.* ...
```
Check the result with `capinfos -c` (2 033 806 packets).

## Rulesets
The paper used the `suricata-update` snapshot of 2024-11-12 (ET Open + Suricata
built-ins), stored in `rulesets/suricata-rules-2024-11-12.rules.xz`.
`scripts/build_paper_dbs.sh` rebuilds the exact rule files Suricata loaded from it.
For new experiments use a current snapshot (`sudo suricata-update`) with `sim/run_pipeline.sh`.
