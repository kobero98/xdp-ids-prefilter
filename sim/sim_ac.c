/*
 * sim_ac.c — Simulatore userspace del filtro XDP Aho-Corasick
 *
 * Replica esattamente il comportamento di:
 *   xdp_prog_ac.c  — logica XDP (parser Ethernet/IP/TCP/UDP, app_map, decisione)
 *   xdp_ac_module.c — funzione ac_scan() (automa DFA, campo output degli stati)
 *
 * Compilazione:
 *   gcc -O2 -o sim_ac sim_ac.c -lpcap              (normale)
 *   gcc -O0 -g -DDEBUG_HEXDUMP -o sim_ac sim_ac.c -lpcap  (hexdump sempre attivo)
 *
 * Uso:
 *   ./sim_ac -d <acdb> -r <pcap> [opzioni]
 *
 * Opzioni:
 *   -d <acdb>     Database AC  (obbligatorio)
 *   -r <pcap>     File PCAP    (obbligatorio)
 *   -p <port>     Porta monitorata da app_map (default 80, 0 = tutte)
 *   -P <file.hs>  Pattern file per identificare i match
 *   -v            Verbose: stampa ogni pacchetto + decisione
 *   -s            Step: pausa (Enter) dopo ogni pacchetto (implica -v)
 *   -x            Hex dump del payload scansionato (implica -v)
 *   -m <bytes>    MAX_SCAN (default 1500, dimensione trama Ethernet)
 *   -n <top>      Numero di top pattern nel report finale (default 20)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

/* ── Costanti ──────────────────────────────────────────────────────────────── */
#define MAX_SCAN_DEFAULT    1500
#define AC_FLAG_LOWERCASE   0x01
#define ACDB_MAGIC          "ACDB"
#define ACDB_HEADER_SZ      64

#define MAX_PATTERNS        30000
#define MAX_PATTERN_BYTES   512
#define MAX_PATTERN_TEXT    512

#define FLOW_BUCKETS        131072          /* power of 2 per hash */
#define MAX_TOP_PORTS       20
#define MAX_MATCHES_PER_PKT 32

/* Linux cooked capture (DLT_LINUX_SLL) */
#define DLT_LINUX_SLL_PROTO_OFF 14
#define DLT_LINUX_SLL_HDR_LEN  16

/* ── Struct ACDB (identica al kernel module) ───────────────────────────────── */
typedef struct __attribute__((packed)) {
    char     magic[4];
    uint32_t version;
    uint32_t num_states;
    uint32_t flags;
    uint32_t state_size;   /* deve essere 1028 */
    uint32_t num_patterns;
    uint32_t num_skipped;
    uint32_t min_len;
    uint8_t  pad[32];
} acdb_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t next[256];    /* transizioni DFA per ogni byte */
    uint32_t output;       /* 0 = no match; altrimenti = ID/flag match */
} ac_state_t;

typedef struct {
    ac_state_t *states;
    uint32_t    num_states;
    uint32_t    num_patterns;
    int         lowercase;
} ac_db_t;

/* ── Pattern (da file .hs) ─────────────────────────────────────────────────── */
typedef struct {
    uint32_t id;
    char     text[MAX_PATTERN_TEXT];   /* regex grezza (es. /\.jpg/) */
    uint8_t  bytes[MAX_PATTERN_BYTES]; /* pattern decodificato */
    int      nbytes;                   /* lunghezza in byte */
    int      nocase;
    int      is_complex;               /* contiene regex reale → skip brute-force */
} pattern_t;

/* ── Flusso ────────────────────────────────────────────────────────────────── */
typedef struct flow_entry {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    uint64_t pkt_count;
    uint64_t byte_count;
    double   first_ts, last_ts;
    struct flow_entry *next;
} flow_entry_t;

/* ── Statistiche globali ───────────────────────────────────────────────────── */
typedef enum {
    DEC_PASS_NOT_IP = 0,
    DEC_PASS_NOT_TRANSPORT,
    DEC_PASS_NOT_MONITORED,
    DEC_PASS_SYN_FIN_RST,
    DEC_PASS_EMPTY,
    DEC_PASS_AC_MATCH,
    DEC_DROP_AC,
    DEC__COUNT
} decision_t;

static const char *dec_label[DEC__COUNT] = {
    "PASS (non IP)",
    "PASS (non TCP/UDP)",
    "PASS (porta non monitorata)",
    "PASS (SYN/FIN/RST)",
    "PASS (payload vuoto)",
    "PASS (AC match)",
    "DROP (AC no-match)",
};

typedef struct {
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t decisions[DEC__COUNT];

    /* protocolli */
    uint64_t n_tcp, n_udp, n_other_ip, n_non_ip;

    /* porte (src e dst combinate) */
    uint64_t port_counts[65536];

    /* pattern match counts (indice = output value dall'automa) */
    uint64_t *pat_counts;  /* allocato su MAX_PATTERNS */
    uint32_t  max_pat_id;

    /* flussi */
    uint64_t  n_flows;
    uint64_t  flow_pkts_min, flow_pkts_max;
    double    flow_dur_min, flow_dur_max;

    /* dimensioni payload */
    uint64_t payload_hist[9]; /* 0,1-63,64-127,128-255,256-511,512-1023,1024-1499,1500+ */
} stats_t;

/* ── Contesto per pcap_loop callback ──────────────────────────────────────── */
typedef struct {
    ac_db_t     *db;
    pattern_t   *patterns;
    int          npat;
    stats_t     *stats;
    flow_entry_t **flows;
    uint16_t     mon_port;   /* 0 = tutto */
    uint32_t     max_scan;
    int          verbose;
    int          step;
    int          hexdump;
    int          linktype;
    uint64_t     pkt_num;
} ctx_t;

/* ══════════════════════════════════════════════════════════════════════════════
 * CARICAMENTO ACDB
 * ══════════════════════════════════════════════════════════════════════════════ */

static ac_db_t *acdb_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    acdb_hdr_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fprintf(stderr, "acdb: header troppo corto\n"); fclose(f); return NULL;
    }
    if (memcmp(hdr.magic, ACDB_MAGIC, 4) != 0) {
        fprintf(stderr, "acdb: magic errato\n"); fclose(f); return NULL;
    }
    if (hdr.state_size != sizeof(ac_state_t)) {
        fprintf(stderr, "acdb: state_size=%u, atteso %zu\n",
                hdr.state_size, sizeof(ac_state_t));
        fclose(f); return NULL;
    }

    printf("[ACDB] version=%u  num_states=%u  num_patterns=%u  flags=0x%x  %s\n",
           hdr.version, hdr.num_states, hdr.num_patterns, hdr.flags,
           (hdr.flags & AC_FLAG_LOWERCASE) ? "(lowercase)" : "");

    ac_db_t *db = calloc(1, sizeof(*db));
    db->num_states   = hdr.num_states;
    db->num_patterns = hdr.num_patterns;
    db->lowercase    = (hdr.flags & AC_FLAG_LOWERCASE) != 0;
    db->states = malloc((size_t)hdr.num_states * sizeof(ac_state_t));
    if (!db->states) { fprintf(stderr, "OOM\n"); fclose(f); free(db); return NULL; }

    /* salta al blocco stati (dopo header di 64 byte) */
    fseek(f, ACDB_HEADER_SZ, SEEK_SET);
    size_t to_read = (size_t)hdr.num_states * sizeof(ac_state_t);
    if (fread(db->states, 1, to_read, f) != to_read) {
        fprintf(stderr, "acdb: stati troncati\n");
        free(db->states); free(db); fclose(f); return NULL;
    }
    fclose(f);

    /* analisi stato 0 (importante per debug) */
    printf("[ACDB] stato 0: output=%u  self-loops(byte→stato 0)=",
           db->states[0].output);
    int sl = 0;
    for (int i = 0; i < 256; i++) if (db->states[0].next[i] == 0) sl++;
    printf("%d/256\n", sl);

    /* controlla se output è usato come ID oppure come flag booleano */
    uint32_t max_out = 0;
    for (uint32_t i = 0; i < db->num_states; i++)
        if (db->states[i].output > max_out) max_out = db->states[i].output;
    printf("[ACDB] valore output max tra tutti gli stati: %u  (%s)\n",
           max_out,
           max_out <= 1 ? "output booleano 0/1" : "output = pattern ID");

    return db;
}

static void acdb_free(ac_db_t *db)
{
    if (db) { free(db->states); free(db); }
}

/* Scan multi-match: continua dopo il primo match per raccogliere tutti i pattern */
static int ac_scan_all(const ac_db_t *db, const uint8_t *buf, uint32_t len,
                       uint32_t *out_ids, int max_out)
{
    uint32_t state = 0;
    int n = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (db->lowercase) c = (uint8_t)tolower((unsigned char)c);
        state = db->states[state].next[c];
        if (db->states[state].output && n < max_out) {
            /* evita duplicati consecutivi (stesso stato finale raggiunto più volte) */
            if (n == 0 || out_ids[n-1] != db->states[state].output)
                out_ids[n++] = db->states[state].output;
        }
    }
    return n;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * CARICAMENTO PATTERN FILE (.hs)
 * ══════════════════════════════════════════════════════════════════════════════ */

/* Converte pattern .hs in bytes. Ritorna lunghezza, -1 se troppo complesso. */
static int hs_to_bytes(const char *hs, uint8_t *out, int maxout, int *nocase_out)
{
    *nocase_out = 0;
    /* formato: /pattern/flags  oppure  /pattern/ */
    if (hs[0] != '/') return -1;
    const char *p = hs + 1;
    const char *end = strrchr(p, '/');
    if (!end || end == p) return -1;

    /* flags dopo lo slash finale */
    if (strchr(end + 1, 'i')) *nocase_out = 1;

    int n = 0;
    int complex = 0;
    while (p < end && n < maxout) {
        if (*p == '\\') {
            p++;
            if (*p == 'x' || *p == 'X') {
                /* \xNN */
                char hex[3] = { p[1], p[2], 0 };
                out[n++] = (uint8_t)strtol(hex, NULL, 16);
                p += 3;
            } else if (*p == 'n')  { out[n++] = '\n'; p++; }
            else if (*p == 'r')    { out[n++] = '\r'; p++; }
            else if (*p == 't')    { out[n++] = '\t'; p++; }
            else if (*p == '0')    { out[n++] = '\0'; p++; }
            else                   { out[n++] = (uint8_t)*p; p++; }
        } else if (*p == '.' || *p == '*' || *p == '+' || *p == '?' ||
                   *p == '[' || *p == '(' || *p == '|') {
            /* metacaratteri regex veri → pattern complesso */
            complex = 1;
            out[n++] = (uint8_t)*p++;
        } else {
            out[n++] = (uint8_t)*p++;
        }
    }
    if (complex) return -2; /* complex: bytes parzialmente convertiti */
    return n;
}

static pattern_t *patterns_load(const char *path, int *count_out)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }

    pattern_t *pats = calloc(MAX_PATTERNS, sizeof(pattern_t));
    if (!pats) { fclose(f); return NULL; }

    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < MAX_PATTERNS) {
        line[strcspn(line, "\n")] = 0;
        if (!line[0]) continue;

        /* formato: ID:/pattern/flags */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        uint32_t id = (uint32_t)atoi(line);
        const char *hs = colon + 1;

        pats[n].id = id;
        strncpy(pats[n].text, hs, MAX_PATTERN_TEXT - 1);

        int nocase = 0;
        int r = hs_to_bytes(hs, pats[n].bytes, MAX_PATTERN_BYTES, &nocase);
        pats[n].nocase = nocase;
        if (r == -2) {
            pats[n].is_complex = 1;
            pats[n].nbytes = 0;
        } else if (r > 0) {
            pats[n].nbytes = r;
        } else {
            pats[n].nbytes = 0;
        }
        n++;
    }
    fclose(f);
    *count_out = n;
    printf("[PATTERNS] caricati %d pattern da %s\n", n, path);
    return pats;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * FLOW TABLE
 * ══════════════════════════════════════════════════════════════════════════════ */

static uint32_t flow_hash(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto)
{
    uint32_t h = sip ^ (dip * 2654435761u) ^ ((uint32_t)sp << 16 | dp) ^ (proto * 1234567u);
    h ^= h >> 16; h *= 0x45d9f3bU; h ^= h >> 16;
    return h & (FLOW_BUCKETS - 1);
}

static flow_entry_t *flow_get(flow_entry_t **table, uint32_t sip, uint32_t dip,
                               uint16_t sp, uint16_t dp, uint8_t proto,
                               double ts, stats_t *st)
{
    uint32_t h = flow_hash(sip, dip, sp, dp, proto);
    for (flow_entry_t *e = table[h]; e; e = e->next) {
        if (e->src_ip==sip && e->dst_ip==dip &&
            e->src_port==sp && e->dst_port==dp && e->proto==proto)
            return e;
    }
    /* nuovo flusso */
    flow_entry_t *e = calloc(1, sizeof(*e));
    e->src_ip=sip; e->dst_ip=dip; e->src_port=sp; e->dst_port=dp; e->proto=proto;
    e->first_ts = e->last_ts = ts;
    e->next = table[h]; table[h] = e;
    st->n_flows++;
    return e;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * HELPER: HEX DUMP
 * ══════════════════════════════════════════════════════════════════════════════ */

static void hexdump(const uint8_t *buf, int len, const char *prefix)
{
    for (int i = 0; i < len; i += 16) {
        printf("%s%04x  ", prefix, i);
        for (int j = 0; j < 16; j++) {
            if (i+j < len) printf("%02x ", buf[i+j]);
            else           printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (int j = 0; j < 16 && i+j < len; j++)
            printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
        printf("|\n");
    }
}

/* ══════════════════════════════════════════════════════════════════════════════
 * SIMULAZIONE XDP (fedele a xdp_prog_ac.c)
 * ══════════════════════════════════════════════════════════════════════════════ */

static void process_packet(uint8_t *user, const struct pcap_pkthdr *hdr,
                           const uint8_t *pkt)
{
    ctx_t  *ctx = (ctx_t *)user;
    stats_t *st = ctx->stats;
    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    uint32_t caplen = hdr->caplen;

    ctx->pkt_num++;
    st->total_pkts++;
    st->total_bytes += hdr->len;

    /* ── offset inizio IP in base al linktype ─────────────────────────────── */
    int ip_off = 0;
    uint16_t ethertype = 0;

    if (ctx->linktype == DLT_EN10MB) {
        if (caplen < 14) goto pass_not_ip;
        ethertype = ntohs(*(uint16_t *)(pkt + 12));
        /* salta VLAN 802.1Q */
        if (ethertype == 0x8100) {
            if (caplen < 18) goto pass_not_ip;
            ethertype = ntohs(*(uint16_t *)(pkt + 16));
            ip_off = 18;
        } else {
            ip_off = 14;
        }
    } else if (ctx->linktype == DLT_LINUX_SLL) {
        if (caplen < 16) goto pass_not_ip;
        ethertype = ntohs(*(uint16_t *)(pkt + DLT_LINUX_SLL_PROTO_OFF));
        ip_off = DLT_LINUX_SLL_HDR_LEN;
    } else if (ctx->linktype == 12 || ctx->linktype == 101) {
        /* DLT_RAW */
        ethertype = 0x0800;
        ip_off = 0;
    } else {
        goto pass_not_ip;
    }

    if (ethertype != 0x0800) goto pass_not_ip;  /* solo IPv4 */

    /* ── IP header ────────────────────────────────────────────────────────── */
    if ((int)caplen < ip_off + (int)sizeof(struct iphdr)) goto pass_not_ip;
    const struct iphdr *ip = (const struct iphdr *)(pkt + ip_off);
    int ihl = ip->ihl * 4;
    if (ihl < 20) goto pass_not_ip;

    uint8_t proto = ip->protocol;
    uint32_t sip  = ntohl(ip->saddr);
    uint32_t dip  = ntohl(ip->daddr);

    if (proto == IPPROTO_TCP)       st->n_tcp++;
    else if (proto == IPPROTO_UDP)  st->n_udp++;
    else                            st->n_other_ip++;

    /* ── Transport ────────────────────────────────────────────────────────── */
    int pay_off = ip_off + ihl; /* payload offset dall'inizio del frame */
    uint16_t sport = 0, dport = 0;
    int syn = 0, fin = 0, rst = 0;

    if (proto == IPPROTO_TCP) {
        if ((int)caplen < pay_off + (int)sizeof(struct tcphdr)) goto pass_not_transport;
        const struct tcphdr *tcp = (const struct tcphdr *)(pkt + pay_off);
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
        syn = tcp->syn; fin = tcp->fin; rst = tcp->rst;
        pay_off += tcp->doff * 4;
    } else if (proto == IPPROTO_UDP) {
        if ((int)caplen < pay_off + (int)sizeof(struct udphdr)) goto pass_not_transport;
        const struct udphdr *udp = (const struct udphdr *)(pkt + pay_off);
        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);
        pay_off += sizeof(struct udphdr);
    } else {
        goto pass_not_transport;
    }

    /* aggiorna contatori porta */
    st->port_counts[dport]++;
    if (sport != dport) st->port_counts[sport]++;

    /* aggiorna flow table */
    {
        flow_entry_t *fl = flow_get(ctx->flows, sip, dip, sport, dport, proto, ts, st);
        fl->pkt_count++;
        fl->byte_count += hdr->len;
        fl->last_ts = ts;
    }

    /* ── SYN/FIN/RST → PASS sempre (nessun payload applicativo) ─────────── */
    if (proto == IPPROTO_TCP && (syn || fin || rst)) goto pass_syn_fin_rst;

    /* ── Payload vuoto ────────────────────────────────────────────────────── */
    if (pay_off >= (int)caplen) goto pass_empty;

    /* ── app_map: porta monitorata? ───────────────────────────────────────── */
    if (ctx->mon_port != 0 && dport != ctx->mon_port && sport != ctx->mon_port)
        goto pass_not_monitored;

    /* ── Scan AC ──────────────────────────────────────────────────────────── */
    {
        const uint8_t *payload = pkt + pay_off;
        uint32_t pay_len = caplen - pay_off;
        if (pay_len > ctx->max_scan) pay_len = ctx->max_scan;

        /* aggiorna istogramma dimensione payload */
        {
            static const uint32_t bins[] = {0,1,64,128,256,512,1024,1500};
            int b = 0;
            for (int i = 1; i < 8; i++) if (pay_len >= bins[i]) b = i;
            st->payload_hist[b]++;
        }

        /* scan MULTI-MATCH (replica fedele + continua per statistiche) */
        uint32_t match_ids[MAX_MATCHES_PER_PKT];
        int      nmatch = ac_scan_all(ctx->db, payload, pay_len,
                                      match_ids, MAX_MATCHES_PER_PKT);

        /* aggiorna contatori pattern */
        for (int i = 0; i < nmatch; i++) {
            uint32_t mid = match_ids[i];
            if (mid < (uint32_t)MAX_PATTERNS) {
                if (st->pat_counts[mid] == 0 && mid > st->max_pat_id)
                    st->max_pat_id = mid;
                st->pat_counts[mid]++;
            }
        }

        int has_match = (nmatch > 0);

        /* ── OUTPUT VERBOSE ──────────────────────────────────────────────── */
        int do_print = ctx->verbose || ctx->step || ctx->hexdump;
#ifdef DEBUG_HEXDUMP
        do_print = 1;
#endif
        if (do_print) {
            char sip_s[INET_ADDRSTRLEN], dip_s[INET_ADDRSTRLEN];
            uint32_t sip_n = htonl(sip), dip_n = htonl(dip);
            inet_ntop(AF_INET, &sip_n, sip_s, sizeof(sip_s));
            inet_ntop(AF_INET, &dip_n, dip_s, sizeof(dip_s));

            char flags_s[8] = "------";
            if (proto == IPPROTO_TCP) {
                const struct tcphdr *tcp =
                    (const struct tcphdr *)(pkt + ip_off + ihl);
                if (tcp->syn) flags_s[0]='S';
                if (tcp->ack) flags_s[1]='A';
                if (tcp->psh) flags_s[2]='P';
                if (tcp->fin) flags_s[3]='F';
                if (tcp->rst) flags_s[4]='R';
                if (tcp->urg) flags_s[5]='U';
            }

            printf("\n[PKT %7lu] %s:%u → %s:%u  %s  pkt=%uB  payload=%uB\n",
                   (unsigned long)ctx->pkt_num,
                   sip_s, sport, dip_s, dport,
                   proto == IPPROTO_TCP ? flags_s : "UDP",
                   hdr->len, pay_len);

            if (has_match) {
                printf("  → SCAN: %d match → XDP_PASS\n", nmatch);
                for (int i = 0; i < nmatch; i++) {
                    uint32_t mid = match_ids[i];
                    const char *ptxt = "(sconosciuto)";
                    /* cerca il pattern nel file .hs caricato */
                    for (int j = 0; j < ctx->npat; j++) {
                        if (ctx->patterns[j].id == mid) {
                            ptxt = ctx->patterns[j].text;
                            break;
                        }
                    }
                    printf("     pattern ID=%-5u  %s\n", mid, ptxt);
                }
            } else {
                printf("  → SCAN: nessun match → XDP_DROP\n");
            }

#ifdef DEBUG_HEXDUMP
            hexdump(payload, pay_len, "     ");
#else
            if (ctx->hexdump)
                hexdump(payload, pay_len, "     ");
#endif

            if (ctx->step) {
                printf("  [Invio per continuare...] ");
                fflush(stdout);
                getchar();
            }
        }

        if (has_match) goto pass_ac_match;

        /* XDP_DROP */
        st->decisions[DEC_DROP_AC]++;
        return;
    }

/* ── Label PASS ───────────────────────────────────────────────────────────── */
pass_not_ip:
    st->n_non_ip++;
    st->decisions[DEC_PASS_NOT_IP]++;
    return;
pass_not_transport:
    st->decisions[DEC_PASS_NOT_TRANSPORT]++;
    return;
pass_not_monitored:
    st->decisions[DEC_PASS_NOT_MONITORED]++;
    return;
pass_syn_fin_rst:
    st->decisions[DEC_PASS_SYN_FIN_RST]++;
    return;
pass_empty:
    st->decisions[DEC_PASS_EMPTY]++;
    return;
pass_ac_match:
    st->decisions[DEC_PASS_AC_MATCH]++;
    return;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * REPORT FINALE
 * ══════════════════════════════════════════════════════════════════════════════ */

typedef struct { uint32_t id; uint64_t count; } id_count_t;
static int cmp_id_count(const void *a, const void *b)
{
    const id_count_t *x = (const id_count_t *)a;
    const id_count_t *y = (const id_count_t *)b;
    if (y->count != x->count) return (y->count > x->count) ? 1 : -1;
    return (int)x->id - (int)y->id;
}

typedef struct { uint16_t port; uint64_t count; } port_count_t;
static int cmp_port_count(const void *a, const void *b)
{
    const port_count_t *x = (const port_count_t *)a;
    const port_count_t *y = (const port_count_t *)b;
    return (y->count > x->count) ? 1 : (y->count < x->count ? -1 : 0);
}

static void print_report(const stats_t *st, pattern_t *patterns, int npat,
                         int top_n, flow_entry_t **flow_table)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                  REPORT FINALE SIM_AC                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* ── Panoramica ────────────────────────────────────────────────────────── */
    printf("── PANORAMICA ──────────────────────────────────────────────────\n");
    printf("  Pacchetti totali    : %lu\n",  (unsigned long)st->total_pkts);
    printf("  Byte totali         : %lu\n",  (unsigned long)st->total_bytes);
    printf("  Dim. media pacchetto: %.1f B\n",
           st->total_pkts ? (double)st->total_bytes / st->total_pkts : 0.0);
    printf("\n");

    /* ── Decisioni XDP ─────────────────────────────────────────────────────── */
    printf("── DECISIONI XDP ───────────────────────────────────────────────\n");
    uint64_t total_pass = 0, total_drop = 0;
    for (int i = 0; i < DEC__COUNT; i++) {
        if (!st->decisions[i]) continue;
        double pct = 100.0 * st->decisions[i] / st->total_pkts;
        if (i == DEC_DROP_AC) total_drop += st->decisions[i];
        else                  total_pass += st->decisions[i];
        printf("  %-35s : %10lu  (%5.2f%%)\n",
               dec_label[i], (unsigned long)st->decisions[i], pct);
    }
    printf("  ────────────────────────────────────────────────────────────\n");
    printf("  XDP_PASS totale                     : %10lu  (%5.2f%%)\n",
           (unsigned long)total_pass, 100.0 * total_pass / st->total_pkts);
    printf("  XDP_DROP totale                     : %10lu  (%5.2f%%)\n",
           (unsigned long)total_drop, 100.0 * total_drop / st->total_pkts);
    printf("\n");

    /* ── Protocolli ─────────────────────────────────────────────────────────── */
    printf("── PROTOCOLLI ──────────────────────────────────────────────────\n");
    printf("  TCP    : %lu  (%.1f%%)\n", (unsigned long)st->n_tcp,
           100.0 * st->n_tcp / st->total_pkts);
    printf("  UDP    : %lu  (%.1f%%)\n", (unsigned long)st->n_udp,
           100.0 * st->n_udp / st->total_pkts);
    printf("  Altri IP: %lu  (%.1f%%)\n", (unsigned long)st->n_other_ip,
           100.0 * st->n_other_ip / st->total_pkts);
    printf("  Non IP  : %lu  (%.1f%%)\n", (unsigned long)st->n_non_ip,
           100.0 * st->n_non_ip / st->total_pkts);
    printf("\n");

    /* ── Top porte ──────────────────────────────────────────────────────────── */
    printf("── TOP %d PORTE ─────────────────────────────────────────────────\n", MAX_TOP_PORTS);
    static port_count_t pcnts[65536];
    int nports = 0;
    for (int i = 0; i < 65536; i++) {
        if (st->port_counts[i]) {
            pcnts[nports].port  = (uint16_t)i;
            pcnts[nports].count = st->port_counts[i];
            nports++;
        }
    }
    qsort(pcnts, nports, sizeof(pcnts[0]), cmp_port_count);
    for (int i = 0; i < MAX_TOP_PORTS && i < nports; i++) {
        printf("  porta %-6u : %lu pkt\n",
               pcnts[i].port, (unsigned long)pcnts[i].count);
    }
    printf("\n");

    /* ── Distribuzione payload ──────────────────────────────────────────────── */
    printf("── DISTRIBUZIONE DIMENSIONE PAYLOAD (scansionato) ──────────────\n");
    static const char *bin_labels[] = {
        "0B","1-63B","64-127B","128-255B","256-511B","512-1023B","1024-1499B","1500+B"
    };
    for (int i = 0; i < 8; i++) {
        if (!st->payload_hist[i]) continue;
        double pct = 100.0 * st->payload_hist[i] /
                     (st->decisions[DEC_PASS_AC_MATCH] + st->decisions[DEC_DROP_AC] + 1);
        printf("  %-12s : %lu  (%.1f%%)\n",
               bin_labels[i], (unsigned long)st->payload_hist[i], pct);
    }
    printf("\n");

    /* ── Flussi ─────────────────────────────────────────────────────────────── */
    printf("── FLUSSI TCP/UDP ───────────────────────────────────────────────\n");
    printf("  Flussi unici (5-tuple): %lu\n", (unsigned long)st->n_flows);

    uint64_t pmin = UINT64_MAX, pmax = 0, ptot = 0;
    double   dmin = 1e18, dmax = 0;
    uint64_t fcount = 0;
    for (int b = 0; b < FLOW_BUCKETS; b++) {
        for (flow_entry_t *e = flow_table[b]; e; e = e->next) {
            fcount++;
            if (e->pkt_count < pmin) pmin = e->pkt_count;
            if (e->pkt_count > pmax) pmax = e->pkt_count;
            ptot += e->pkt_count;
            double dur = e->last_ts - e->first_ts;
            if (dur < dmin) dmin = dur;
            if (dur > dmax) dmax = dur;
        }
    }
    if (fcount) {
        printf("  Pacchetti/flusso: min=%lu  max=%lu  avg=%.1f\n",
               (unsigned long)pmin, (unsigned long)pmax,
               (double)ptot / fcount);
        printf("  Durata flusso:    min=%.3fs  max=%.3fs\n", dmin, dmax);
    }
    printf("  (Nota: ogni direzione TCP = flusso separato)\n");
    printf("\n");

    /* ── Top pattern matchati ───────────────────────────────────────────────── */
    printf("── TOP %d PATTERN PIÙ MATCHATI ──────────────────────────────────\n", top_n);

    /* raccoglie tutti i pattern con count > 0 */
    static id_count_t idc[MAX_PATTERNS];
    int nidc = 0;
    for (int i = 0; i < MAX_PATTERNS; i++) {
        if (st->pat_counts[i]) {
            idc[nidc].id    = (uint32_t)i;
            idc[nidc].count = st->pat_counts[i];
            nidc++;
        }
    }
    qsort(idc, nidc, sizeof(idc[0]), cmp_id_count);

    if (nidc == 0) {
        printf("  (nessun match registrato)\n");
    }
    for (int i = 0; i < top_n && i < nidc; i++) {
        uint32_t pid = idc[i].id;
        const char *ptxt = "(ID non trovato nel .hs)";
        for (int j = 0; j < npat; j++) {
            if (patterns[j].id == pid) { ptxt = patterns[j].text; break; }
        }
        printf("  #%-3d  ID=%-5u  match=%-8lu  %s\n",
               i+1, pid, (unsigned long)idc[i].count, ptxt);
    }
    printf("\n");

    /* ── Pattern attivi (con almeno 1 match) ────────────────────────────────── */
    printf("── RIEPILOGO PATTERN ────────────────────────────────────────────\n");
    printf("  Pattern con almeno 1 match: %d\n", nidc);

    /* quanti pattern unici nell'output ACDB? */
    /* (già mostrato nel load) */
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════════════
 * MAIN
 * ══════════════════════════════════════════════════════════════════════════════ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s -d <acdb> -r <pcap> [opzioni]\n\n"
        "  -d <acdb>     Database AC (obbligatorio)\n"
        "  -r <pcap>     File PCAP   (obbligatorio)\n"
        "  -p <port>     Porta monitorata (default 80; 0 = tutte)\n"
        "  -P <file.hs>  Pattern file per identificare i match\n"
        "  -v            Verbose: stampa ogni pacchetto\n"
        "  -s            Step: pausa dopo ogni pacchetto\n"
        "  -x            Hex dump del payload\n"
        "  -m <bytes>    MAX_SCAN in byte (default 1500)\n"
        "  -n <top>      Top-N pattern nel report (default 20)\n"
        "\nCompilazione debug (hexdump sempre attivo):\n"
        "  gcc -O0 -g -DDEBUG_HEXDUMP -o sim_ac sim_ac.c -lpcap\n",
        prog);
}

int main(int argc, char *argv[])
{
    const char *acdb_path = NULL;
    const char *pcap_path = NULL;
    const char *hs_path   = NULL;
    uint16_t    mon_port  = 80;
    uint32_t    max_scan  = MAX_SCAN_DEFAULT;
    int         verbose   = 0, step = 0, hexdump_flag = 0, top_n = 20;

    int opt;
    while ((opt = getopt(argc, argv, "d:r:p:P:vsxm:n:h")) != -1) {
        switch (opt) {
        case 'd': acdb_path  = optarg; break;
        case 'r': pcap_path  = optarg; break;
        case 'p': mon_port   = (uint16_t)atoi(optarg); break;
        case 'P': hs_path    = optarg; break;
        case 'v': verbose    = 1; break;
        case 's': step = verbose = 1; break;
        case 'x': hexdump_flag = verbose = 1; break;
        case 'm': max_scan   = (uint32_t)atoi(optarg); break;
        case 'n': top_n      = atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (!acdb_path || !pcap_path) { usage(argv[0]); return 1; }

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              SIM_AC — Simulatore XDP Aho-Corasick           ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    printf("[CONFIG] ACDB      : %s\n", acdb_path);
    printf("[CONFIG] PCAP      : %s\n", pcap_path);
    printf("[CONFIG] Porta     : %u %s\n", mon_port, mon_port==0?"(tutte)":"");
    printf("[CONFIG] MAX_SCAN  : %u byte\n", max_scan);
    if (hs_path) printf("[CONFIG] Patterns  : %s\n", hs_path);
    printf("\n");

    /* carica ACDB */
    ac_db_t *db = acdb_load(acdb_path);
    if (!db) return 1;

    /* carica pattern file (opzionale) */
    pattern_t *patterns = NULL;
    int npat = 0;
    if (hs_path) {
        patterns = patterns_load(hs_path, &npat);
    }

    /* alloca strutture */
    stats_t *st = calloc(1, sizeof(*st));
    st->pat_counts = calloc(MAX_PATTERNS, sizeof(uint64_t));
    if (!st->pat_counts) { fprintf(stderr, "OOM\n"); return 1; }

    flow_entry_t **flows = calloc(FLOW_BUCKETS, sizeof(flow_entry_t *));
    if (!flows) { fprintf(stderr, "OOM\n"); return 1; }

    /* apri PCAP */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_path, errbuf);
    if (!pcap) { fprintf(stderr, "pcap: %s\n", errbuf); return 1; }

    int linktype = pcap_datalink(pcap);
    printf("[PCAP] linktype = %d (%s)\n\n",
           linktype, pcap_datalink_val_to_name(linktype));

    ctx_t ctx = {
        .db       = db,
        .patterns = patterns,
        .npat     = npat,
        .stats    = st,
        .flows    = flows,
        .mon_port = mon_port,
        .max_scan = max_scan,
        .verbose  = verbose,
        .step     = step,
        .hexdump  = hexdump_flag,
        .linktype = linktype,
        .pkt_num  = 0,
    };

    printf("[*] Elaborazione PCAP in corso...\n");
    if (!verbose && !step) printf("    (usa -v per output per-pacchetto)\n");

    pcap_loop(pcap, 0, process_packet, (uint8_t *)&ctx);
    pcap_close(pcap);

    /* report finale */
    print_report(st, patterns, npat, top_n, flows);

    /* cleanup */
    acdb_free(db);
    free(patterns);
    free(st->pat_counts);
    free(st);
    /* (flow table non liberata: in un simulatore va bene) */
    free(flows);

    return 0;
}
