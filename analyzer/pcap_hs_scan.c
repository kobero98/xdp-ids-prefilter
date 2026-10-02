/*
 * pcap_hs_scan.c — Simula Hyperscan XDP su un PCAP usando patterns.hs
 *
 * Uso:
 *   ./pcap_hs_scan [opzioni] <file.pcap> <patterns.hs>
 *
 * Opzioni:
 *   -r rules.file  Suricata rules (correla pattern -> regole originali via grep)
 *   -o out.txt     File di output (default: hs_report.txt)
 *   -p PORT        Filtra per porta (default 80, 0=tutto)
 *   -n N           Max pacchetti (0=tutti)
 *   -t N           Top N pattern nel report (default 60)
 *   -g PCT         Soglia "generico" % (default 5.0)
 *
 * Build:
 *   gcc -O2 -o pcap_hs_scan pcap_hs_scan.c -lpcap -lhs -lstdc++ -lm
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>

#include <pcap.h>
#include <hs/hs.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/* -------------------------------------------------------------------------
 * Costanti
 * ------------------------------------------------------------------------- */
#define MAX_PATTERNS      60000
#define MAX_EXPR_LEN       4096
#define MAX_PAYLOAD_SCAN   2048
#define MAX_HIST_BUCKETS    200
#define MAX_EXAMPLES          3
#define EXAMPLE_LEN         160
#define MAX_RULE_TEXT       600
#define MAX_RULES_PER_PAT    10   /* max regole mostrate per pattern */

/* -------------------------------------------------------------------------
 * PatInfo
 * ------------------------------------------------------------------------- */
typedef struct {
    unsigned int id;
    char         raw[MAX_EXPR_LEN];
    uint64_t     pkt_count;
    char         examples[MAX_EXAMPLES][EXAMPLE_LEN];
    int          n_examples;
} PatInfo;

/* -------------------------------------------------------------------------
 * RuleEntry — una regola Suricata caricata in memoria
 * ------------------------------------------------------------------------- */
typedef struct {
    char text[MAX_RULE_TEXT];  /* riga completa (troncata) */
    char msg[256];
} RuleEntry;

/* -------------------------------------------------------------------------
 * Stato globale
 * ------------------------------------------------------------------------- */
static PatInfo   *g_pats      = NULL;
static int        g_n_pats    = 0;
static int        g_max_id    = 0;
static int       *g_id2idx    = NULL;
static uint8_t   *g_pkt_hit   = NULL;
static int        g_pkt_n_hits = 0;
static const char *g_pkt_payload = NULL;
static int         g_pkt_plen    = 0;

static RuleEntry  *g_rules    = NULL;
static int         g_n_rules  = 0;

static uint64_t  g_pkt_total   = 0;
static uint64_t  g_pkt_scope   = 0;
static uint64_t  g_pkt_matched = 0;
static uint64_t  g_hist[MAX_HIST_BUCKETS + 1] = {0};

static volatile int g_stop = 0;

/* -------------------------------------------------------------------------
 * Match callback Hyperscan
 * ------------------------------------------------------------------------- */
static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *ctx)
{
    (void)from; (void)to; (void)flags; (void)ctx;
    if ((int)id > g_max_id || g_pkt_hit[id]) return 0;
    g_pkt_hit[id] = 1;
    g_pkt_n_hits++;

    int idx = g_id2idx[id];
    if (idx < 0) return 0;
    g_pats[idx].pkt_count++;

    if (g_pats[idx].n_examples < MAX_EXAMPLES && g_pkt_payload) {
        int len = g_pkt_plen < EXAMPLE_LEN - 1 ? g_pkt_plen : EXAMPLE_LEN - 1;
        char *dst = g_pats[idx].examples[g_pats[idx].n_examples];
        for (int i = 0; i < len; i++) {
            unsigned char c = (unsigned char)g_pkt_payload[i];
            dst[i] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        dst[len] = '\0';
        g_pats[idx].n_examples++;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Carica rules Suricata
 * ------------------------------------------------------------------------- */
static void extract_msg(const char *line, char *out, int outsz)
{
    const char *p = strstr(line, "msg:\"");
    if (!p) { snprintf(out, outsz, "(no msg)"); return; }
    p += 5;
    const char *e = strchr(p, '"');
    if (!e) e = p + outsz - 1;
    int len = (int)(e - p);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, len); out[len] = '\0';
}

static int load_rules(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    int alloc = 50000;
    g_rules = malloc(alloc * sizeof(RuleEntry));
    if (!g_rules) { fclose(f); return -1; }
    g_n_rules = 0;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (!strstr(line, "sid:")) continue;

        if (g_n_rules >= alloc) {
            alloc *= 2;
            g_rules = realloc(g_rules, alloc * sizeof(RuleEntry));
            if (!g_rules) { fclose(f); return -1; }
        }
        RuleEntry *r = &g_rules[g_n_rules++];
        strncpy(r->text, line, sizeof(r->text) - 1);
        r->text[sizeof(r->text) - 1] = '\0';
        char *nl = strchr(r->text, '\n'); if (nl) *nl = '\0';
        extract_msg(r->text, r->msg, sizeof(r->msg));
    }
    fclose(f);
    return g_n_rules;
}

/* -------------------------------------------------------------------------
 * Estrai dal pattern Hyperscan le chiavi di ricerca per il grep:
 *
 *  key_literal : più lunga sottostringa ASCII letterale (escaping rimosso)
 *  key_hex     : se il pattern è puro hex, stringa tipo "ff ff ff ff"
 *                in modo da matchare la notazione Suricata |ff ff ff ff|
 * ------------------------------------------------------------------------- */
static void pattern_search_keys(const char *raw,
                                 char *key_lit,  int lit_sz,
                                 char *key_hex,  int hex_sz)
{
    key_lit[0] = '\0';
    key_hex[0] = '\0';

    /* --- chiave letterale --- */
    /* Scorro il pattern; \xNN e metacaratteri diventano separatori. */
    char tmp[MAX_EXPR_LEN];
    int  ti = 0;
    const char *p = raw;

    while (*p && ti < (int)sizeof(tmp) - 2) {
        if (p[0] == '\\' && p[1] == 'x' &&
            isxdigit((unsigned char)p[2]) && isxdigit((unsigned char)p[3])) {
            /* escape hex: separatore */
            if (ti > 0 && tmp[ti-1] != '\0') tmp[ti++] = '\0';
            p += 4;
        } else if (p[0] == '\\' && p[1]) {
            /* \/ \. \- \( ecc → carattere letterale se non metacaratteri puri */
            char c = p[1];
            if (c == '/' || c == '-' || c == ':' || c == '.' || c == ' ') {
                tmp[ti++] = c;
            } else {
                if (ti > 0 && tmp[ti-1] != '\0') tmp[ti++] = '\0';
            }
            p += 2;
        } else if (strchr(".*+?[](){}|^$", *p)) {
            if (ti > 0 && tmp[ti-1] != '\0') tmp[ti++] = '\0';
            p++;
        } else {
            tmp[ti++] = *p++;
        }
    }
    tmp[ti++] = '\0'; tmp[ti] = '\0'; /* doppio terminatore per scansione "word" */

    /* Trova la sottostringa più lunga separata da \0 */
    int best_start = 0, best_len = 0;
    int si = 0;
    while (si < ti) {
        int wlen = (int)strlen(tmp + si);
        if (wlen > best_len) { best_len = wlen; best_start = si; }
        si += wlen + 1;
    }
    if (best_len >= 5 && best_len < lit_sz) {
        memcpy(key_lit, tmp + best_start, best_len);
        key_lit[best_len] = '\0';
    }

    /* --- chiave hex --- */
    /* Se il pattern è fatto SOLO da \xNN (nessun carattere ASCII), costruiamo
     * la stringa "NN NN NN ..." per matchare la notazione Suricata |...|      */
    char hbuf[MAX_EXPR_LEN] = {0};
    int  hi = 0;
    int  has_ascii = 0;
    int  hex_count = 0;
    p = raw;

    while (*p) {
        if (p[0] == '\\' && p[1] == 'x' &&
            isxdigit((unsigned char)p[2]) && isxdigit((unsigned char)p[3])) {
            if (hi > 0 && hi < (int)sizeof(hbuf) - 4) hbuf[hi++] = ' ';
            hbuf[hi++] = tolower((unsigned char)p[2]);
            hbuf[hi++] = tolower((unsigned char)p[3]);
            hex_count++;
            p += 4;
        } else if (p[0] == '\\' && p[1]) {
            has_ascii = 1; p += 2;
        } else if (strchr(".*+?[](){}|^$", *p)) {
            p++;
        } else {
            has_ascii = 1; p++;
        }
    }
    hbuf[hi] = '\0';

    /* Usa la chiave hex solo se il pattern non ha parti ASCII (troppo breve
     * la chiave letterale) e la sequenza è abbastanza lunga (>=3 byte = 6 hex car) */
    if (!has_ascii && hex_count >= 3 && hi < hex_sz) {
        memcpy(key_hex, hbuf, hi + 1);
    }
}

/* -------------------------------------------------------------------------
 * Cerca regole per grep del contenuto
 * Ritorna il numero di regole trovate, scrive i puntatori in results[].
 * ------------------------------------------------------------------------- */
static int grep_rules(const char *key_lit, const char *key_hex,
                       const RuleEntry **results, int max_r)
{
    int found = 0;
    int use_lit = (key_lit && key_lit[0]);
    int use_hex = (key_hex && key_hex[0]);
    if (!use_lit && !use_hex) return 0;

    for (int i = 0; i < g_n_rules && found < max_r; i++) {
        int match = 0;
        if (use_lit && strcasestr(g_rules[i].text, key_lit)) match = 1;
        if (!match && use_hex && strcasestr(g_rules[i].text, key_hex)) match = 1;
        if (match) results[found++] = &g_rules[i];
    }
    return found;
}

/* -------------------------------------------------------------------------
 * Parser patterns.hs
 * ------------------------------------------------------------------------- */
static int parse_patterns(const char *path,
                           char **exprs, unsigned int *hs_flags,
                           unsigned int *ids, int max_n)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[MAX_EXPR_LEN + 64];
    int  n = 0;

    while (n < max_n && fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *cr = strchr(line, '\r'); if (cr) *cr = '\0';
        if (!line[0]) continue;

        char *p = line;
        unsigned int id = (unsigned int)strtoul(p, &p, 10);
        if (*p != ':' || *(p+1) != '/') continue;
        p += 2;

        char *rs = p, *re = NULL;
        while (*p) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '/')  { re = p; break; }
            p++;
        }
        if (!re) continue;

        int rlen = (int)(re - rs);
        if (rlen <= 0 || rlen >= MAX_EXPR_LEN) continue;
        char *expr = malloc(rlen + 1);
        if (!expr) continue;
        memcpy(expr, rs, rlen); expr[rlen] = '\0';

        char *fp = re + 1;
        unsigned int hf = HS_FLAG_DOTALL;
        while (*fp && *fp != '{' && *fp != '\n') {
            if (*fp == 'i') hf |= HS_FLAG_CASELESS;
            if (*fp == 'm') hf |= HS_FLAG_MULTILINE;
            fp++;
        }

        exprs[n] = expr; hs_flags[n] = hf; ids[n] = id;
        n++;
    }
    fclose(f);
    return n;
}

/* -------------------------------------------------------------------------
 * Compila DB Hyperscan (riprova rimuovendo pattern problematici)
 * ------------------------------------------------------------------------- */
static hs_database_t *build_database(char **exprs, unsigned int *hs_flags,
                                      unsigned int *ids, int n, int *n_out)
{
    const char  **ep = malloc(n * sizeof(char *));
    unsigned int *fp = malloc(n * sizeof(unsigned int));
    unsigned int *ip = malloc(n * sizeof(unsigned int));
    int np = 0;
    for (int i = 0; i < n; i++) { ep[np]=exprs[i]; fp[np]=hs_flags[i]; ip[np]=ids[i]; np++; }

    hs_database_t     *db  = NULL;
    hs_compile_error_t *err = NULL;
    int skipped = 0;
    for (;;) {
        if (db)  { hs_free_database(db);  db=NULL; }
        if (err) { hs_free_compile_error(err); err=NULL; }
        hs_error_t rc = hs_compile_multi((const char **)ep, fp, ip, (unsigned)np,
                                          HS_MODE_BLOCK, NULL, &db, &err);
        if (rc == HS_SUCCESS) break;
        if (err->expression < 0 || err->expression >= np) {
            fprintf(stderr, "[!] Errore compilazione: %s\n", err->message);
            hs_free_compile_error(err); free(ep); free(fp); free(ip); return NULL;
        }
        int bad = err->expression; skipped++;
        for (int j = bad; j < np-1; j++) { ep[j]=ep[j+1]; fp[j]=fp[j+1]; ip[j]=ip[j+1]; }
        np--;
    }
    if (skipped) fprintf(stderr, "[!] %d pattern saltati\n", skipped);
    *n_out = np;
    free(ep); free(fp); free(ip);
    return db;
}

/* -------------------------------------------------------------------------
 * Estrai payload TCP/UDP
 * ------------------------------------------------------------------------- */
static const uint8_t *extract_payload(const uint8_t *pkt, int caplen,
                                       uint16_t fport, int *plen)
{
    if (caplen < (int)sizeof(struct ether_header)) return NULL;
    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return NULL;

    int ip_off = sizeof(struct ether_header);
    if (caplen < ip_off + (int)sizeof(struct ip)) return NULL;
    const struct ip *iph = (const struct ip *)(pkt + ip_off);
    int ip_hl = iph->ip_hl * 4;
    if (ip_hl < 20) return NULL;

    int t_off = ip_off + ip_hl;
    uint16_t sp = 0, dp = 0;
    const uint8_t *payload = NULL;
    int plen_ = 0;

    if (iph->ip_p == IPPROTO_TCP) {
        if (caplen < t_off + (int)sizeof(struct tcphdr)) return NULL;
        const struct tcphdr *th = (const struct tcphdr *)(pkt + t_off);
        sp = ntohs(th->th_sport); dp = ntohs(th->th_dport);
        int ps = t_off + th->th_off * 4;
        plen_ = caplen - ps;
        if (plen_ > 0) payload = pkt + ps;
    } else if (iph->ip_p == IPPROTO_UDP) {
        if (caplen < t_off + (int)sizeof(struct udphdr)) return NULL;
        const struct udphdr *uh = (const struct udphdr *)(pkt + t_off);
        sp = ntohs(uh->uh_sport); dp = ntohs(uh->uh_dport);
        int ps = t_off + sizeof(struct udphdr);
        plen_ = caplen - ps;
        if (plen_ > 0) payload = pkt + ps;
    } else return NULL;

    if (!payload || plen_ <= 0) return NULL;
    if (fport && dp != fport && sp != fport) return NULL;
    *plen = plen_;
    return payload;
}

/* -------------------------------------------------------------------------
 * Sort decrescente per pkt_count
 * ------------------------------------------------------------------------- */
static int cmp_pat(const void *a, const void *b)
{
    const PatInfo *pa = (const PatInfo *)a;
    const PatInfo *pb = (const PatInfo *)b;
    if (pb->pkt_count > pa->pkt_count) return  1;
    if (pb->pkt_count < pa->pkt_count) return -1;
    return 0;
}

static void signal_handler(int sig) { (void)sig; g_stop = 1; }

/* -------------------------------------------------------------------------
 * Scrivi report su FILE*
 * ------------------------------------------------------------------------- */
static void write_report(FILE *out,
                          const char *pcap_path, const char *pat_path,
                          const char *rules_path, uint16_t fport,
                          int top_n, double generic_thresh)
{
    fprintf(out,
        "================================================================================\n"
        "REPORT SIMULAZIONE HYPERSCAN\n"
        "================================================================================\n"
        "  PCAP:     %s\n"
        "  Pattern:  %s\n"
        "  Regole:   %s\n"
        "  Porta:    %u\n"
        "--------------------------------------------------------------------------------\n"
        "  Pacchetti totali letti:                %12llu\n"
        "  Pacchetti in scope (porta %u):         %12llu\n",
        pcap_path, pat_path,
        rules_path ? rules_path : "(non fornito)",
        fport,
        (unsigned long long)g_pkt_total, fport,
        (unsigned long long)g_pkt_scope);

    if (!g_pkt_scope) { fprintf(out, "  Nessun pacchetto in scope.\n"); return; }

    fprintf(out,
        "  Pacchetti con >=1 match:               %12llu  (%.1f%%)\n"
        "  Pacchetti senza match (bypassabili):   %12llu  (%.1f%%)\n",
        (unsigned long long)g_pkt_matched,
        100.0 * g_pkt_matched / g_pkt_scope,
        (unsigned long long)g_hist[0],
        100.0 * g_hist[0] / g_pkt_scope);

    /* Distribuzione */
    fprintf(out, "\nDistribuzione match per pacchetto:\n");
    struct { int lo, hi; const char *lbl; } bkts[] = {
        {0,0,"0"},{1,1,"1"},{2,5,"2-5"},{6,20,"6-20"},{21,100,"21-100"},{101,MAX_HIST_BUCKETS,"101+"}
    };
    for (int b = 0; b < 6; b++) {
        uint64_t n = 0;
        for (int k = bkts[b].lo; k <= bkts[b].hi && k <= MAX_HIST_BUCKETS; k++) n += g_hist[k];
        double pct = 100.0 * n / g_pkt_scope;
        fprintf(out, "  %8s pattern: %8llu pkt  (%5.1f%%)  ", bkts[b].lbl, (unsigned long long)n, pct);
        for (int i = 0; i < (int)(40.0*pct/100.0); i++) fputc('|', out);
        fputc('\n', out);
    }

    /* ---- TOP N pattern con regole correlate ---- */
    fprintf(out,
        "\n================================================================================\n"
        "TOP %d PATTERN PER FREQUENZA DI MATCH\n"
        "================================================================================\n",
        top_n);

    char key_lit[MAX_EXPR_LEN];
    char key_hex[MAX_EXPR_LEN];
    const RuleEntry *results[MAX_RULES_PER_PAT];

    int shown = 0;
    for (int i = 0; i < g_n_pats && shown < top_n; i++) {
        if (!g_pats[i].pkt_count) break;
        double pct = 100.0 * g_pats[i].pkt_count / g_pkt_scope;

        fprintf(out,
            "\n--- #%d ---\n"
            "  PATTERN ID: %u\n"
            "  MATCH:      %llu pacchetti  (%.1f%%)\n"
            "  REGEX:      /%s/\n",
            shown + 1,
            g_pats[i].id,
            (unsigned long long)g_pats[i].pkt_count, pct,
            g_pats[i].raw);

        /* Snippet payload */
        if (g_pats[i].n_examples > 0) {
            fprintf(out, "  PAYLOAD (esempi):\n");
            for (int e = 0; e < g_pats[i].n_examples; e++)
                fprintf(out, "    [%d] %s\n", e+1, g_pats[i].examples[e]);
        }

        /* Grep regole */
        pattern_search_keys(g_pats[i].raw, key_lit, sizeof(key_lit), key_hex, sizeof(key_hex));

        if (g_n_rules > 0) {
            int nr = grep_rules(key_lit, key_hex, results, MAX_RULES_PER_PAT);
            if (nr > 0) {
                fprintf(out, "  REGOLE SURICATA (%d trovate", nr);
                if (nr == MAX_RULES_PER_PAT) fprintf(out, ", troncate a %d", MAX_RULES_PER_PAT);
                fprintf(out, "):\n");
                for (int j = 0; j < nr; j++) {
                    fprintf(out, "    [%d] MSG:   %s\n", j+1, results[j]->msg);
                    fprintf(out, "        RULE:  %.300s\n", results[j]->text);
                }
            } else {
                /* Mostra le chiavi usate per il grep */
                fprintf(out, "  REGOLE SURICATA: nessuna trovata");
                if (key_lit[0])
                    fprintf(out, " (cerca_letterale=\"%s\")", key_lit);
                if (key_hex[0])
                    fprintf(out, " (cerca_hex=\"%s\")", key_hex);
                fprintf(out, "\n");
            }
        }
        shown++;
    }

    /* ---- PATTERN GENERICI ---- */
    fprintf(out,
        "\n================================================================================\n"
        "PATTERN GENERICI (>= %.0f%% del traffico — candidati alla blacklist)\n"
        "================================================================================\n",
        generic_thresh);

    int found_generic = 0;
    for (int i = 0; i < g_n_pats; i++) {
        double pct = 100.0 * g_pats[i].pkt_count / g_pkt_scope;
        if (pct < generic_thresh) break;
        found_generic++;
        pattern_search_keys(g_pats[i].raw, key_lit, sizeof(key_lit), key_hex, sizeof(key_hex));
        int nr = grep_rules(key_lit, key_hex, results, 3);
        fprintf(out, "\n  [%.1f%%]  ID:%u  /%s/\n", pct, g_pats[i].id, g_pats[i].raw);
        for (int j = 0; j < nr; j++)
            fprintf(out, "           %s\n", results[j]->msg);
    }
    if (!found_generic) fprintf(out, "  Nessuno sopra la soglia.\n");

    /* ---- Riepilogo finale ---- */
    uint64_t zero = 0;
    for (int i = 0; i < g_n_pats; i++) if (!g_pats[i].pkt_count) zero++;
    fprintf(out,
        "\n================================================================================\n"
        "RIEPILOGO\n"
        "================================================================================\n"
        "  Pattern totali:             %d\n"
        "  Pattern che hanno matchato: %llu  (%.1f%%)\n"
        "  Pattern mai matchati:       %llu  (%.1f%%)\n"
        "================================================================================\n",
        g_n_pats,
        (unsigned long long)(g_n_pats - zero), 100.0*(g_n_pats-zero)/g_n_pats,
        (unsigned long long)zero, 100.0*zero/g_n_pats);
}

/* -------------------------------------------------------------------------
 * Uso
 * ------------------------------------------------------------------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s [opzioni] <file.pcap> <patterns.hs>\n"
        "  -r FILE  Suricata rules (grep pattern -> regole originali)\n"
        "  -o FILE  Output report (default: hs_report.txt)\n"
        "  -O FILE  Scrivi conteggi grezzi id:count (per select_best.py)\n"
        "  -p PORT  Filtra porta (default 80, 0=tutto)\n"
        "  -n N     Max pacchetti (0=tutti)\n"
        "  -t N     Top N pattern (default 60)\n"
        "  -g PCT   Soglia generico %% (default 5.0)\n", prog);
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    uint16_t    fport    = 80;
    uint64_t    max_pkts = 0;
    int         top_n    = 60;
    double      gthresh  = 5.0;
    const char *rules_path  = NULL;
    const char *out_path    = "hs_report.txt";
    const char *counts_path = NULL;   /* -O: raw match counts per select_best.py */

    int opt;
    while ((opt = getopt(argc, argv, "r:o:O:p:n:t:g:h")) != -1) {
        switch (opt) {
            case 'r': rules_path  = optarg; break;
            case 'o': out_path    = optarg; break;
            case 'O': counts_path = optarg; break;
            case 'p': fport       = (uint16_t)atoi(optarg); break;
            case 'n': max_pkts    = (uint64_t)strtoull(optarg, NULL, 10); break;
            case 't': top_n       = atoi(optarg); break;
            case 'g': gthresh     = atof(optarg); break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }
    if (optind + 2 > argc) { usage(argv[0]); return 1; }
    const char *pcap_path = argv[optind];
    const char *pat_path  = argv[optind + 1];

    signal(SIGINT, signal_handler);

    /* Carica regole */
    if (rules_path) {
        fprintf(stderr, "[*] Carico regole da %s...\n", rules_path);
        int nr = load_rules(rules_path);
        if (nr < 0) return 1;
        fprintf(stderr, "    %d regole caricate\n", nr);
    }

    /* Carica pattern */
    fprintf(stderr, "[*] Parsing %s...\n", pat_path);
    char         **exprs    = malloc(MAX_PATTERNS * sizeof(char *));
    unsigned int  *hs_flags = malloc(MAX_PATTERNS * sizeof(unsigned int));
    unsigned int  *ids      = malloc(MAX_PATTERNS * sizeof(unsigned int));
    if (!exprs || !hs_flags || !ids) { perror("malloc"); return 1; }

    int n_pats = parse_patterns(pat_path, exprs, hs_flags, ids, MAX_PATTERNS);
    if (n_pats <= 0) { fprintf(stderr, "[!] Nessun pattern\n"); return 1; }
    fprintf(stderr, "    %d pattern letti\n", n_pats);

    int max_id = 0;
    for (int i = 0; i < n_pats; i++) if ((int)ids[i] > max_id) max_id = (int)ids[i];

    g_n_pats  = n_pats; g_max_id = max_id;
    g_pats    = calloc(n_pats, sizeof(PatInfo));
    g_id2idx  = malloc((max_id + 1) * sizeof(int));
    g_pkt_hit = calloc(max_id + 1, 1);
    if (!g_pats || !g_id2idx || !g_pkt_hit) { perror("calloc"); return 1; }
    memset(g_id2idx, -1, (max_id + 1) * sizeof(int));
    for (int i = 0; i < n_pats; i++) {
        g_pats[i].id = ids[i];
        strncpy(g_pats[i].raw, exprs[i], MAX_EXPR_LEN - 1);
        g_id2idx[ids[i]] = i;
    }

    /* Compila DB */
    fprintf(stderr, "[*] Compilazione Hyperscan...\n");
    int n_compiled = 0;
    hs_database_t *db = build_database(exprs, hs_flags, ids, n_pats, &n_compiled);
    if (!db) return 1;
    fprintf(stderr, "    %d pattern compilati\n", n_compiled);

    for (int i = 0; i < n_pats; i++) free(exprs[i]);
    free(exprs); free(hs_flags); free(ids);

    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "[!] hs_alloc_scratch fallito\n"); return 1;
    }

    /* Apri PCAP */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) { fprintf(stderr, "[!] %s\n", errbuf); return 1; }
    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "[!] Link type non supportato\n"); return 1;
    }

    fprintf(stderr, "[*] Scansione %s (porta %u)...\n", pcap_path, fport);

    /* Loop pacchetti */
    struct pcap_pkthdr *pkthdr;
    const uint8_t      *pkt_data;
    int rc;

    while (!g_stop && (rc = pcap_next_ex(pcap, &pkthdr, &pkt_data)) == 1) {
        g_pkt_total++;
        if (max_pkts && g_pkt_total > max_pkts) break;
        if (g_pkt_total % 100000 == 0)
            fprintf(stderr, "    %llu pkt, %llu matchati...\r",
                    (unsigned long long)g_pkt_total, (unsigned long long)g_pkt_matched);

        int plen;
        const uint8_t *payload = extract_payload(pkt_data, (int)pkthdr->caplen, fport, &plen);
        if (!payload) continue;

        g_pkt_scope++;
        memset(g_pkt_hit, 0, (size_t)(max_id + 1));
        g_pkt_n_hits  = 0;
        g_pkt_payload = (const char *)payload;
        g_pkt_plen    = plen < EXAMPLE_LEN - 1 ? plen : EXAMPLE_LEN - 1;

        int scan_len = plen < MAX_PAYLOAD_SCAN ? plen : MAX_PAYLOAD_SCAN;
        hs_scan(db, (const char *)payload, (unsigned)scan_len, 0, scratch, on_match, NULL);

        int bkt = g_pkt_n_hits < MAX_HIST_BUCKETS ? g_pkt_n_hits : MAX_HIST_BUCKETS;
        g_hist[bkt]++;
        if (g_pkt_n_hits > 0) g_pkt_matched++;
    }
    fprintf(stderr, "\n");

    pcap_close(pcap);
    hs_free_scratch(scratch);
    hs_free_database(db);

    qsort(g_pats, g_n_pats, sizeof(PatInfo), cmp_pat);

    /* Scrivi conteggi grezzi per select_best.py */
    if (counts_path) {
        FILE *cf = fopen(counts_path, "w");
        if (!cf) { perror(counts_path); }
        else {
            fprintf(cf, "# scope: %llu\n", (unsigned long long)g_pkt_scope);
            for (int i = 0; i < g_n_pats; i++)
                fprintf(cf, "%u %llu\n",
                        g_pats[i].id,
                        (unsigned long long)g_pats[i].pkt_count);
            fclose(cf);
            fprintf(stderr, "[*] Match counts scritti in: %s\n", counts_path);
        }
    }

    /* Scrivi report */
    FILE *fout = fopen(out_path, "w");
    if (!fout) { perror(out_path); fout = stdout; out_path = "(stdout)"; }
    write_report(fout, pcap_path, pat_path, rules_path, fport, top_n, gthresh);
    if (fout != stdout) fclose(fout);

    fprintf(stderr,
        "--- RIEPILOGO ---\n"
        "  In scope:   %llu pkt\n"
        "  Hit rate:   %.1f%%\n"
        "  Bypass:     %.1f%%\n"
        "  Report:     %s\n",
        (unsigned long long)g_pkt_scope,
        g_pkt_scope ? 100.0*g_pkt_matched/g_pkt_scope : 0.0,
        g_pkt_scope ? 100.0*g_hist[0]/g_pkt_scope : 0.0,
        out_path);

    return 0;
}
