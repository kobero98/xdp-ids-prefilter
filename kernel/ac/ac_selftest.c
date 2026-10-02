/* Replica userspace di ac_prefilter() + ac_scan() del modulo, per verifica. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PF_HASH1 0x9E3779B1u
#define PF_HASH2 0x85EBCA6Bu

struct hdr {
    char magic[4]; uint32_t version, num_states, flags, state_size;
    uint32_t num_patterns, num_skipped, min_len;
    uint32_t num_classes, stride, shift, trunc, pf_bl, pf_bs;
    uint8_t pad[8];
} __attribute__((packed));

static const uint8_t *g_cls, *g_out, *g_t1, *g_t2, *g_ts;
static const uint16_t *g_next16;
static uint32_t g_shift, g_psl, g_pss, g_szl, g_szs;

static int pf_bit(const uint8_t *bm, uint32_t h)
{ return bm[h >> 3] & (1u << (h & 7)); }

static uint32_t ld32(const uint8_t *p)
{ uint32_t w; memcpy(&w, p, 4); return w | 0x20202020u; }

static int prefilter(const uint8_t *buf, uint32_t len)
{
    if (len < 4) return 0;
    for (uint32_t i = 0; i + 4 <= len; i++) {
        uint32_t w = ld32(buf + i), v, L;
        if (!pf_bit(g_t1, (w * PF_HASH1) >> g_psl)) continue;
        if (i + 8 <= len) {
            uint32_t w2 = ld32(buf + i + 4);
            if (pf_bit(g_t2, (w2 * PF_HASH2) >> g_psl)) return 1;
        }
        v = w;
        if (pf_bit(g_ts, (v * PF_HASH1) >> g_pss)) return 1;
        for (L = 5; L <= 7; L++) {
            if (i + L > len) break;
            v = ((v << 5) | (v >> 27)) + (uint32_t)(buf[i + L - 1] | 0x20);
            if (pf_bit(g_ts + (L - 4) * g_szs, (v * PF_HASH1) >> g_pss)) return 1;
        }
    }
    return 0;
}

static int dfa(const uint8_t *buf, uint32_t len)
{
    uint32_t state = 0;
    for (uint32_t i = 0; i < len; i++) {
        state = g_next16[(state << g_shift) + g_cls[buf[i]]];
        if (g_out[state]) return 1;
    }
    return 0;
}

static void check(const char *name, const uint8_t *buf, uint32_t len)
{
    int pf = prefilter(buf, len), full = pf ? dfa(buf, len) : 0;
    int dfa_only = dfa(buf, len);
    printf("%-28s prefiltro=%d  scan=%d  dfa_diretto=%d %s\n",
           name, pf, full, dfa_only,
           (full == dfa_only) ? "OK" : "*** MISMATCH (falso negativo!) ***");
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *d = malloc(sz); fread(d, 1, sz, f); fclose(f);

    struct hdr *h = (struct hdr *)d;
    uint32_t N = h->num_states;
    size_t pad = (8 - ((sizeof(*h) + 256 + (size_t)N) & 7)) & 7;
    g_cls = d + sizeof(*h);
    g_out = g_cls + 256;
    g_next16 = (const uint16_t *)(g_out + N + pad);
    g_shift = h->shift;
    g_szl = (1u << h->pf_bl) / 8;  g_szs = (1u << h->pf_bs) / 8;
    g_psl = 32 - h->pf_bl;         g_pss = 32 - h->pf_bs;
    g_t1 = (const uint8_t *)g_next16 + (size_t)N * h->stride * h->state_size;
    g_t2 = g_t1 + g_szl;
    g_ts = g_t2 + g_szl;
    printf("acdb: %u stati, pf_bits %u/%u\n\n", N, h->pf_bl, h->pf_bs);

    /* payload con pattern lungo (sp_password, 11B), corto (NICK , 5B), pulito */
    uint8_t p1[1500], p2[1500], p3[1500], p4[1500];
    for (int i = 0; i < 1500; i++) { p1[i]=p2[i]=p3[i]=p4[i] = "qwzxjvkqpzm"[i % 11]; }
    memcpy(p1 + 700, "SP_PASSWORD", 11);           /* lungo, uppercase (case-fold) */
    memcpy(p2 + 900, "NICK ", 5);                  /* corto (5B, via TS5) */
    memcpy(p4 + 100, "Wonk-", 5);                  /* corto (5B, via TS5) */

    check("pattern lungo (case-fold)", p1, 1500);
    check("pattern corto 5B", p2, 1500);
    check("pulito (random)", p3, 1500);
    check("pattern corto Wonk-", p4, 1500);

    /* misura empirica del tasso di trigger su dati pseudo-casuali */
    srand(7);
    int trig = 0, runs = 2000;
    for (int r = 0; r < runs; r++) {
        for (int i = 0; i < 1500; i++) p3[i] = (uint8_t)rand();
        if (prefilter(p3, 1500)) trig++;
    }
    printf("\ntrigger su %d pacchetti random 1500B: %d (%.2f%%)\n",
           runs, trig, 100.0 * trig / runs);
    return 0;
}
