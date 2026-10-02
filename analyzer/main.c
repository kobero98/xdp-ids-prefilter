#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap_analyzer.h"
#include "protocol_detector.h"
#include "rules_parser.h"
#include "pattern_extractor.h"
#include "hyperscan_formatter.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s input.pcap suricata.rules\n", argv[0]);
        return 1;
    }

    const char *pcap_file  = argv[1];
    const char *rules_file = argv[2];

    /* ── FASE 1: analisi PCAP ── */
    printf("[*] Analyzing PCAP: %s\n", pcap_file);
    PcapStats stats;
    if (pcap_analyze(pcap_file, &stats) != 0) return 1;

    printf("\n=== Network Statistics ===\n");
    printf("  Total IPv4 packets : %ld\n", stats.total_ip);
    printf("  TCP flows          : %ld\n", stats.tcp_flows);
    printf("  UDP packets        : %ld\n", stats.udp_packets);

    /* ── FASE 2: selezione protocolli ── */
    ProtoSelection sel;
    detect_protocols(&stats, &sel);
    print_proto_stats(&sel);
    write_proto_meta(&sel, pcap_file);

    /* ── FASE 3: caricamento regole ── */
    printf("\n[*] Loading rules: %s\n", rules_file);
    RuleSet rs;
    if (rules_load(rules_file, &rs) != 0) return 1;
    printf("    Loaded %d rules.\n", rs.count);

    /* ── FASE 4 + 5 + 6: estrazione pattern e generazione output ── */
    FILE *fp_hs      = fopen("patterns.hs", "w");
    FILE *fp_rules   = fopen("filtered.rules", "w");
    FILE *fp_rules2  = fopen("filtered2.rules", "w");
    FILE *fp_dominant = fopen("dominant.rules", "w");  /* solo proto dominante */

    if (!fp_hs)       { perror("patterns.hs");     return 1; }
    if (!fp_rules)    { perror("filtered.rules");  return 1; }
    if (!fp_rules2)   { perror("filtered2.rules"); return 1; }
    if (!fp_dominant) { perror("dominant.rules");  return 1; }

    int id            = 1;
    int used          = 0;
    int proto_only    = 0;   /* rules in filtered2 but not in filtered (proto mismatch) */
    int discarded     = 0;
    FilterStats fstats;
    memset(&fstats, 0, sizeof(fstats));

    for (int i = 0; i < rs.count; i++) {
        SuricataRule *r = &rs.rules[i];
        Pattern pat;
        FilterReason reason = extract_pattern(r, &sel, &pat, &fstats);

        if (reason == FILTER_PROTO_MISMATCH) {
            /* Protocollo non dominante: Suricata vede tutto il traffico di
             * questo tipo senza pre-filtro AC/XDP, quindi la regola va in
             * filtered.rules intatta — nessuna ulteriore analisi. */
            fprintf(fp_rules,  "%s\n", r->raw);
            fprintf(fp_rules2, "%s\n", r->raw);
            proto_only++;
            continue;
        }
        if (reason != FILTER_OK) {
            /* Protocollo dominante ma regola non estraibile (stateful, no
             * content, troppo generica…): il pre-filtro XDP non può coprirla
             * e il pacchetto verrebbe droppato prima di Suricata — scarta. */
            discarded++;
            continue;
        }

        if (hs_write_pattern(fp_hs, id, &pat) != 0) { discarded++; continue; }
        fprintf(fp_rules,    "%s\n", r->raw);
        fprintf(fp_rules2,   "%s\n", r->raw);
        fprintf(fp_dominant, "%s\n", r->raw);
        id++;
        used++;
    }

    fclose(fp_hs);
    fclose(fp_rules);
    fclose(fp_rules2);
    fclose(fp_dominant);

    print_filter_stats(&fstats, rs.count);
    rules_free(&rs);

    printf("\n=== Results ===\n");
    printf("  Patterns written (dominant proto) : %d  →  patterns.hs\n", used);
    printf("  filtered.rules                    : %d  (dominant-proto OK + all others)\n",
           used + proto_only);
    printf("  filtered2.rules                   : %d  (= filtered.rules)\n", used + proto_only);
    printf("  Discarded (dominant proto, no pattern extractable) : %d\n", discarded);

    return 0;
}
