/*
 * ac_winbench.c — Benchmark offline: DFA sull'intero payload (variante attuale
 * del modulo) vs verifica a FINESTRA (DFA solo su <=trunc byte per ogni
 * posizione candidata confermata dal prefiltro n-gram).
 *
 * Correttezza per costruzione: ogni occorrenza di pattern inizia in una
 * posizione confermata dal prefiltro (T1 = primi 4 byte di ogni pattern,
 * T2/TS conferma) e i pattern sono troncati a `trunc` byte, quindi la
 * finestra [i, i+trunc) copre l'intera occorrenza. Il bench VERIFICA anche
 * empiricamente che il verdetto per pacchetto coincida (0 mismatch attesi).
 *
 * Uso: ac_winbench <acdb> <pcap> [max_scan] [porta]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define PF_HASH1 0x9E3779B1u
#define PF_HASH2 0x85EBCA6Bu

struct hdr {
    char magic[4]; uint32_t version, num_states, flags, state_size;
    uint32_t num_patterns, num_skipped, min_len;
    uint32_t num_classes, stride, shift, trunc, pf_bl, pf_bs;
    uint8_t pad[8];
} __attribute__((packed));

struct db {
    uint32_t n, shift, esz, trunc;
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
    d->trunc = h->trunc ? h->trunc : 16;
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

static inline int pf_bit(const uint8_t *bm, uint32_t h)
{ return bm[h >> 3] & (1u << (h & 7)); }

static inline uint32_t ld32(const uint8_t *p)
{ uint32_t w; memcpy(&w, p, 4); return w | 0x20202020u; }

/* Candidato confermato in posizione i? (stessa logica di ac_prefilter) */
static inline int candidate_at(const struct db *d, const uint8_t *buf,
                               uint32_t len, uint32_t i)
{
    uint32_t w = ld32(buf + i), v, L;
    if (!pf_bit(d->t1, (w * PF_HASH1) >> d->psl)) return 0;
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

/* Variante A — modulo attuale: prefiltro con early-exit, poi DFA intero. */
static int scan_full(const struct db *d, const uint8_t *buf, uint32_t len)
{
    if (len < 4) return 0;
    for (uint32_t i = 0; i + 4 <= len; i++)
        if (candidate_at(d, buf, len, i))
            return dfa(d, buf, len);
    return 0;
}

/* Variante B — finestra: per ogni candidato, DFA su <=trunc byte da i. */
static int scan_win(const struct db *d, const uint8_t *buf, uint32_t len)
{
    if (len < 4) return 0;
    for (uint32_t i = 0; i + 4 <= len; i++) {
        if (!candidate_at(d, buf, len, i))
            continue;
        uint32_t w = len - i;
        if (w > d->trunc) w = d->trunc;
        if (dfa(d, buf + i, w))
            return 1;
    }
    return 0;
}

struct pkt { const uint8_t *p; uint32_t len; };

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "uso: %s <acdb> <pcap> [max_scan] [porta]\n", argv[0]);
        return 1;
    }
    uint32_t max_scan = (argc > 3) ? (uint32_t)atoi(argv[3]) : 1500;
    uint16_t mon_port = (argc > 4) ? (uint16_t)atoi(argv[4]) : 80;

    struct db d;
    if (load_db(argv[1], &d)) return 1;
    fprintf(stderr, "acdb: %u stati, entry %uB, trunc=%u\n",
            d.n, d.esz, d.trunc);

    /* Carica il pcap in RAM e indicizza i payload monitorati (parsing
     * identico ad ac_simfilter: TCP/UDP porta monitorata, no SYN/FIN/RST,
     * pkt_len = min(caplen, eth+ip.tot_len), clamp a max_scan). */
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror(argv[2]); return 1; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *raw = malloc(fsz);
    if (fread(raw, 1, fsz, f) != (size_t)fsz) { fclose(f); return 1; }
    fclose(f);
    uint32_t magic; memcpy(&magic, raw, 4);
    if (magic != 0xa1b2c3d4 && magic != 0xa1b23c4d) {
        fprintf(stderr, "magic pcap non supportato: %#x\n", magic);
        return 1;
    }

    struct pkt *pk = malloc(sizeof(*pk) * 4u * 1024 * 1024);
    uint64_t npk = 0, tot_pkts = 0;
    long off = 24;
    while (off + 16 <= fsz) {
        uint32_t caplen; memcpy(&caplen, raw + off + 8, 4);
        const uint8_t *pkt = raw + off + 16;
        off += 16 + caplen;
        if (off > fsz) break;
        tot_pkts++;

        if (caplen < 34) continue;
        if (pkt[12] != 0x08 || pkt[13] != 0x00) continue;
        uint32_t ihl = (pkt[14] & 0x0f) * 4;
        uint8_t proto = pkt[23];
        if (proto != 6 && proto != 17) continue;
        uint32_t l4 = 14 + ihl;
        uint16_t sport, dport;
        uint32_t pay_off;
        if (proto == 6) {
            if (caplen < l4 + 20) continue;
            sport = pkt[l4] << 8 | pkt[l4 + 1];
            dport = pkt[l4 + 2] << 8 | pkt[l4 + 3];
            if (pkt[l4 + 13] & 0x07) continue;
            pay_off = l4 + (pkt[l4 + 12] >> 4) * 4;
        } else {
            sport = pkt[l4] << 8 | pkt[l4 + 1];
            dport = pkt[l4 + 2] << 8 | pkt[l4 + 3];
            pay_off = l4 + 8;
        }
        uint16_t tot_len = (pkt[16] << 8) | pkt[17];
        uint32_t ip_len = 14 + tot_len;
        uint32_t pkt_len = ip_len < caplen ? ip_len : caplen;
        if (pay_off >= pkt_len) continue;
        if (sport != mon_port && dport != mon_port) continue;
        uint32_t plen = pkt_len - pay_off;
        if (plen > max_scan) plen = max_scan;
        pk[npk].p = pkt + pay_off;
        pk[npk].len = plen;
        npk++;
    }
    fprintf(stderr, "pcap: %llu pacchetti, %llu payload monitorati (porta %u, max_scan %u)\n",
            (unsigned long long)tot_pkts, (unsigned long long)npk,
            mon_port, max_scan);

    /* 1) Equivalenza dei verdetti */
    uint64_t mism = 0, match_a = 0, bytes = 0;
    for (uint64_t i = 0; i < npk; i++) {
        int a = scan_full(&d, pk[i].p, pk[i].len);
        int b = scan_win(&d, pk[i].p, pk[i].len);
        match_a += a;
        bytes += pk[i].len;
        if (a != b && mism++ < 5)
            fprintf(stderr, "MISMATCH pkt#%llu len=%u full=%d win=%d\n",
                    (unsigned long long)i, pk[i].len, a, b);
    }
    printf("verdetti: %llu scan, match=%llu (%.1f%%), MISMATCH=%llu\n",
           (unsigned long long)npk, (unsigned long long)match_a,
           100.0 * match_a / npk, (unsigned long long)mism);

    /* 2) Timing: 3 passate per variante, tempo migliore */
    volatile int sink = 0;
    double best_a = 1e30, best_b = 1e30;
    for (int rep = 0; rep < 3; rep++) {
        double t0 = now_s();
        for (uint64_t i = 0; i < npk; i++)
            sink += scan_full(&d, pk[i].p, pk[i].len);
        double ta = now_s() - t0;
        if (ta < best_a) best_a = ta;

        t0 = now_s();
        for (uint64_t i = 0; i < npk; i++)
            sink += scan_win(&d, pk[i].p, pk[i].len);
        double tb = now_s() - t0;
        if (tb < best_b) best_b = tb;
    }
    (void)sink;
    printf("full-DFA : %.3f s  -> %.2f us/scan  (%.2f ns/byte medio)\n",
           best_a, best_a / npk * 1e6, best_a / bytes * 1e9);
    printf("windowed : %.3f s  -> %.2f us/scan  (%.2f ns/byte medio)\n",
           best_b, best_b / npk * 1e6, best_b / bytes * 1e9);
    printf("speedup  : %.2fx\n", best_a / best_b);
    return 0;
}
