/*
 * ac_simfilter.c — Replica esatta della decisione di xdp_prog_ac.c su un pcap.
 * Scrive in output solo i pacchetti che l'XDP passerebbe a Suricata e stampa
 * il verdetto per pacchetto.
 *
 * Uso: ac_simfilter <acdb> <in.pcap> <out.pcap> [max_scan] [-q]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap/pcap.h>

#define PF_HASH1 0x9E3779B1u
#define PF_HASH2 0x85EBCA6Bu

struct hdr {
    char magic[4]; uint32_t version, num_states, flags, state_size;
    uint32_t num_patterns, num_skipped, min_len;
    uint32_t num_classes, stride, shift, trunc, pf_bl, pf_bs;
    uint8_t pad[8];
} __attribute__((packed));

struct db {
    uint32_t n, shift, esz;
    const uint8_t  *cls, *out;
    const uint16_t *nx16;
    const uint32_t *nx32;
    const uint8_t *t1, *t2, *ts;
    uint32_t psl, pss, szs;
};

static int load_db(const char *path, struct db *d)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *m = malloc(sz);
    if (fread(m, 1, sz, f) != (size_t)sz) { fclose(f); return -1; }
    fclose(f);
    struct hdr *h = (struct hdr *)m;
    uint32_t N = h->num_states;
    size_t pad = (8 - ((sizeof(*h) + 256 + (size_t)N) & 7)) & 7;
    d->n = N; d->shift = h->shift; d->esz = h->state_size;
    d->cls = m + sizeof(*h);
    d->out = d->cls + 256;
    d->nx16 = (const uint16_t *)(d->out + N + pad);
    d->nx32 = (const uint32_t *)d->nx16;
    size_t szl = ((size_t)1 << h->pf_bl) / 8;
    d->szs = (1u << h->pf_bs) / 8;
    d->psl = 32 - h->pf_bl; d->pss = 32 - h->pf_bs;
    d->t1 = (const uint8_t *)d->nx16 + (size_t)N * h->stride * h->state_size;
    d->t2 = d->t1 + szl;
    d->ts = d->t2 + szl;
    return 0;
}

static int pf_bit(const uint8_t *bm, uint32_t h)
{ return bm[h >> 3] & (1u << (h & 7)); }

static uint32_t ld32(const uint8_t *p)
{ uint32_t w; memcpy(&w, p, 4); return w | 0x20202020u; }

static int prefilter(const struct db *d, const uint8_t *buf, uint32_t len)
{
    if (len < 4) return 0;
    for (uint32_t i = 0; i + 4 <= len; i++) {
        uint32_t w = ld32(buf + i), v, L;
        if (!pf_bit(d->t1, (w * PF_HASH1) >> d->psl)) continue;
        if (i + 8 <= len) {
            uint32_t w2 = ld32(buf + i + 4);
            if (pf_bit(d->t2, (w2 * PF_HASH2) >> d->psl)) return 1;
        }
        v = w;
        if (pf_bit(d->ts, (v * PF_HASH1) >> d->pss)) return 1;
        for (L = 5; L <= 7; L++) {
            if (i + L > len) break;
            v = ((v << 5) | (v >> 27)) + (uint32_t)(buf[i + L - 1] | 0x20);
            if (pf_bit(d->ts + (L - 4) * d->szs, (v * PF_HASH1) >> d->pss))
                return 1;
        }
    }
    return 0;
}

static int dfa(const struct db *d, const uint8_t *buf, uint32_t len)
{
    uint32_t state = 0;
    if (d->esz == 2) {
        for (uint32_t i = 0; i < len; i++) {
            state = d->nx16[(state << d->shift) + d->cls[buf[i]]];
            if (d->out[state]) return 1;
        }
    } else {
        for (uint32_t i = 0; i < len; i++) {
            state = d->nx32[(state << d->shift) + d->cls[buf[i]]];
            if (d->out[state]) return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "uso: %s <acdb> <in.pcap> <out.pcap> [max_scan] [porta] [-q]\n", argv[0]);
        return 1;
    }
    uint32_t max_scan = (argc > 4) ? (uint32_t)atoi(argv[4]) : 1500;
    uint16_t mon_port = (argc > 5) ? (uint16_t)atoi(argv[5]) : 80;
    int quiet = 0, ft_mode = 0, firstk = 0;
    const char *flowcsv = NULL;
    for (int a = 6; a < argc; a++) {
        if (!strcmp(argv[a], "-q"))  quiet = 1;
        else if (!strcmp(argv[a], "-ft")) ft_mode = 1;          /* marca flusso su match */
        else if (!strncmp(argv[a], "-k", 2)) firstk = atoi(argv[a] + 2); /* passa primi K pkt/flusso */
        else if (!strncmp(argv[a], "--flowcsv=", 10)) flowcsv = argv[a] + 10;
    }

    struct db d;
    if (load_db(argv[1], &d)) return 1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *in = pcap_open_offline(argv[2], errbuf);
    if (!in) { fprintf(stderr, "%s\n", errbuf); return 1; }
    pcap_dumper_t *out = pcap_dump_open(in, argv[3]);
    if (!out) { fprintf(stderr, "dump: %s\n", pcap_geterr(in)); return 1; }

    struct pcap_pkthdr *ph;
    const u_char *pkt;
    uint64_t idx = 0, passed = 0, dropped = 0;

    /* Flow table: chiave 4-tupla normalizzata (direzione-indipendente).
     * Sempre attiva: raccoglie passed/dropped/matched per flusso monitorato,
     * necessari a classificare gli alert persi (reassembly vs miss-filtro).
     * Usata anche per -ft / -kN. */
    #define FT_SIZE (1u << 21)
    struct flowrec {
        uint64_t key;
        uint32_t ip_lo, ip_hi;
        uint16_t port_lo, port_hi;
        uint32_t passed, dropped;
        uint8_t  matched;   /* almeno un pacchetto del flusso ha fatto MATCH nel DFA */
    };
    static struct flowrec ft[FT_SIZE];

    while (pcap_next_ex(in, &ph, &pkt) == 1) {
        idx++;
        const char *verdict = "PASS";
        const char *why     = "non-ip";
        int drop = 0;
        struct flowrec *fr = NULL;   /* !=NULL solo per flussi monitorati */

        do {
            if (ph->caplen < 34) break;
            if (pkt[12] != 0x08 || pkt[13] != 0x00) break;
            uint32_t ihl = (pkt[14] & 0x0f) * 4;
            uint8_t proto = pkt[23];
            if (proto != 6 && proto != 17) { why = "non-tcp/udp"; break; }
            uint32_t l4 = 14 + ihl;
            uint16_t sport, dport;
            uint32_t pay_off;

            if (proto == 6) {
                if (ph->caplen < l4 + 20) break;
                sport = pkt[l4] << 8 | pkt[l4 + 1];
                dport = pkt[l4 + 2] << 8 | pkt[l4 + 3];
                uint8_t flags = pkt[l4 + 13];
                pay_off = l4 + (pkt[l4 + 12] >> 4) * 4;
                if (flags & 0x07) { why = "syn/fin/rst"; break; }   /* FIN|SYN|RST */
            } else {
                sport = pkt[l4] << 8 | pkt[l4 + 1];
                dport = pkt[l4 + 2] << 8 | pkt[l4 + 3];
                pay_off = l4 + 8;
            }

            /* pkt_len come l'XDP: min(frame, eth + ip.tot_len) — esclude il
             * padding Ethernet dei frame corti (allineamento bit-esatto). */
            uint16_t tot_len = (pkt[16] << 8) | pkt[17];
            uint32_t ip_len  = 14 + tot_len;
            uint32_t pkt_len = ip_len < ph->caplen ? ip_len : ph->caplen;

            if (pay_off >= pkt_len) { why = "payload-vuoto"; break; }
            if (sport != mon_port && dport != mon_port) { why = "porta-non-monitorata"; break; }

            /* Flow key normalizzata */
            uint32_t sip, dip;
            memcpy(&sip, pkt + 26, 4); memcpy(&dip, pkt + 30, 4);
            uint32_t ip_lo, ip_hi; uint16_t port_lo, port_hi;
            if (sip < dip || (sip == dip && sport <= dport)) {
                ip_lo = sip; port_lo = sport; ip_hi = dip; port_hi = dport;
            } else {
                ip_lo = dip; port_lo = dport; ip_hi = sip; port_hi = sport;
            }
            uint64_t lo = ((uint64_t)ip_lo << 16) | port_lo;
            uint64_t hi = ((uint64_t)ip_hi << 16) | port_hi;
            uint64_t fkey = lo * 0x9E3779B97F4A7C15ULL ^ hi;
            if (!fkey) fkey = 1;
            uint32_t h = (uint32_t)(fkey >> 40) & (FT_SIZE - 1);
            while (ft[h].key && ft[h].key != fkey)
                h = (h + 1) & (FT_SIZE - 1);
            fr = &ft[h];
            if (!fr->key) {
                fr->key = fkey;
                fr->ip_lo = ip_lo; fr->ip_hi = ip_hi;
                fr->port_lo = port_lo; fr->port_hi = port_hi;
            }

            uint32_t seen = fr->passed + fr->dropped;

            /* -ft: se flusso già marcato, passa tutto */
            if (ft_mode && fr->matched) { why = "flusso-marcato"; break; }

            uint32_t plen = pkt_len - pay_off;
            if (plen > max_scan) plen = max_scan;
            int pf = prefilter(&d, pkt + pay_off, plen);
            int m  = pf ? dfa(&d, pkt + pay_off, plen) : 0;
            if (m) fr->matched = 1;

            /* -kN: i primi N pacchetti del flusso passano comunque */
            if (firstk && seen < (uint32_t)firstk) { why = "primi-K"; break; }

            if (m) { why = "MATCH"; break; }
            verdict = "DROP"; why = "payload-pulito"; drop = 1;
        } while (0);

        if (fr) { if (drop) fr->dropped++; else fr->passed++; }

        if (drop) dropped++; else { passed++; pcap_dump((u_char *)out, ph, pkt); }
        if (!quiet)
            printf("#%-4llu %s  (%s)  len=%u\n",
                   (unsigned long long)idx, verdict, why, ph->caplen);
    }
    pcap_dump_close(out);
    pcap_close(in);

    if (flowcsv) {
        FILE *fc = fopen(flowcsv, "w");
        if (fc) {
            fprintf(fc, "flow,passed,dropped,matched\n");
            for (uint32_t i = 0; i < FT_SIZE; i++) {
                if (!ft[i].key) continue;
                struct flowrec *fr = &ft[i];
                fprintf(fc, "%u.%u.%u.%u:%u-%u.%u.%u.%u:%u,%u,%u,%u\n",
                        fr->ip_lo & 0xff, (fr->ip_lo >> 8) & 0xff,
                        (fr->ip_lo >> 16) & 0xff, (fr->ip_lo >> 24) & 0xff, fr->port_lo,
                        fr->ip_hi & 0xff, (fr->ip_hi >> 8) & 0xff,
                        (fr->ip_hi >> 16) & 0xff, (fr->ip_hi >> 24) & 0xff, fr->port_hi,
                        fr->passed, fr->dropped, fr->matched);
            }
            fclose(fc);
            fprintf(stderr, "flow-csv → %s\n", flowcsv);
        }
    }

    fprintf(stderr, "totale=%llu passati=%llu droppati=%llu → %s\n",
            (unsigned long long)(passed + dropped),
            (unsigned long long)passed, (unsigned long long)dropped, argv[3]);
    return 0;
}
