/*
 * ac_build.c — Aho-Corasick DFA builder per XDP packet filtering
 *
 * Legge un file di pattern formato Hyperscan (id:/pattern/[i] per riga),
 * estrae i pattern come stringhe esatte (skippando regex con metacaratteri),
 * costruisce il DFA Aho-Corasick completo (failure links già incorporati)
 * e lo serializza in un file .acdb.
 *
 * Il file .acdb viene caricato nel modulo kernel xdp_ac_module tramite
 * configfs (con dd, come il modulo Hyperscan carica il .db serializzato).
 * Il modulo espone poi il kfunc bpf_xdp_ac_scan() che l'XDP program
 * chiama per ogni pacchetto — senza FPU, senza SIMD.
 *
 * Tutti i pattern vengono normalizzati a lowercase: il modulo kernel
 * fa lo stesso sul payload prima di scansionare.
 *
 * Uso:
 *   ac_build [-n MAX_STATES] [-m MIN_LEN] [-o output.acdb] patterns.hs
 *
 *   -n MAX_STATES  max stati DFA (default 65536 → ~64 MB vmalloc nel kernel)
 *   -m MIN_LEN     lunghezza minima pattern in byte (default 4)
 *   -o OUTPUT      file di output (default: patterns.acdb)
 *
 * Formato file .acdb:
 *   struct ac_header  (64 byte)
 *   struct ac_state   (1028 byte) × num_states
 *
 * Dimensione totale ≈ 64 + num_states × 1028 byte.
 * Esempi: 4096 stati ≈ 4 MB, 16384 stati ≈ 16 MB, 65536 stati ≈ 64 MB.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

/* ── Costanti ───────────────────────────────────────────────────────────── */
#define DEFAULT_MAX_STATES  65536
#define DEFAULT_MIN_LEN     4
#define DEFAULT_TRUNC       16
#define MAX_PATTERN_LEN     512
#define ALPHA               256

/*
 * Sentinella: transizione non ancora definita nel trie.
 * Dopo build_dfa() tutte le transizioni sono indici validi [0, n_states).
 */
#define NO_TRANS  UINT32_MAX

/*
 * ── Prefiltro n-gram ──
 * Bitmap consultate dal modulo PRIMA del DFA: il DFA parte solo se il
 * pacchetto contiene un candidato. Il test per posizione è indipendente
 * dallo stato → la CPU sovrappone i load (niente catena seriale).
 *
 *   T1 : hash dei primi 4 byte (foldati) di TUTTI i pattern   — cancello
 *   T2 : hash dei byte 4..7 dei pattern con len ≥ 8           — conferma
 *   TS4..TS7 : hash dell'INTERO pattern corto (len 4..7)      — conferma
 *
 * Fold = byte | 0x20, applicato identico a pattern (già lowercase) e
 * payload: over-approssima tolower → possibili falsi positivi (li smaschera
 * il DFA), mai falsi negativi.
 */
#define PF_BITS_LONG   23   /* T1/T2: 2^23 bit = 1 MB ciascuna    */
#define PF_BITS_SHORT  20   /* TS4..TS7: 2^20 bit = 128 KB l'una  */
#define PF_HASH1       0x9E3779B1u
#define PF_HASH2       0x85EBCA6Bu

/* ── Strutture condivise con il modulo kernel ───────────────────────────── */

/*
 * Header del file .acdb versione 2: 64 byte.
 *
 * Layout del file:
 *   [64 B ] header
 *   [256 B] class_map[256]  — u8, mappa byte payload → classe di equivalenza
 *                             (il case-folding è già incorporato qui)
 *   [N B  ] output[N]       — u8, 1 = stato terminale
 *   [pad  ] zeri fino ad allineamento 8 della sezione next
 *   [...  ] next[N][stride] — u16 (state_size=2) o u32 (state_size=4)
 *
 * stride è num_classes arrotondato alla potenza di 2 successiva, così il
 * lookup nel modulo è  next[(state << shift) + class_map[c]]  senza imul
 * nella catena di load dipendenti.
 */
struct ac_header {
    char     magic[4];        /* "ACDB"                                  */
    uint32_t version;         /* 2                                       */
    uint32_t num_states;      /* numero di stati nel DFA (root incluso)  */
    uint32_t flags;           /* riservato (case-folding già in class_map)*/
    uint32_t state_size;      /* byte per entry di next[]: 2 o 4         */
    uint32_t num_patterns;    /* pattern effettivamente caricati nel DFA */
    uint32_t num_skipped;     /* pattern scartati (regex/corti/overflow) */
    uint32_t min_len;         /* MIN_LEN usato                           */
    uint32_t num_classes;     /* classi di equivalenza alfabeto reali    */
    uint32_t stride;          /* colonne per riga (pow2 ≥ num_classes)   */
    uint32_t shift;           /* log2(stride)                            */
    uint32_t trunc;           /* troncamento pattern usato (0 = nessuno) */
    uint32_t pf_bits_long;    /* log2 bit di T1/T2 (0 = no prefiltro)    */
    uint32_t pf_bits_short;   /* log2 bit di ogni TS4..TS7               */
    uint8_t  pad[8];          /* padding a 64 byte                       */
} __attribute__((packed));

_Static_assert(sizeof(struct ac_header) == 64, "ac_header deve essere 64 byte");

/* ── Tabelle di costruzione (heap) ──────────────────────────────────────── */
/*
 * Durante la costruzione usiamo tre tabelle separate:
 *   g_goto  : transizioni DFA [stato][byte], sentinella NO_TRANS nel trie
 *   g_output: flag terminale per stato
 *   g_fail  : failure function (usata solo durante build_dfa, poi scartata)
 *   g_bfsq  : coda BFS per build_dfa
 *
 * Memoria totale ≈ MAX_STATES × (ALPHA×4 + 4 + 4 + 4) byte.
 * Per 65536 stati ≈ 67 MB.
 */
static uint32_t (*g_goto)[ALPHA]; /* [max_states][256] */
static uint32_t  *g_output;
static uint32_t  *g_fail;
static uint32_t  *g_bfsq;
static int        g_n;            /* prossimo stato libero (0=root già usato) */
static int        g_max;

static int alloc_tables(int max)
{
    g_max    = max;
    g_goto   = malloc((size_t)max * ALPHA * sizeof(uint32_t));
    g_output = calloc((size_t)max, sizeof(uint32_t));
    g_fail   = calloc((size_t)max, sizeof(uint32_t));
    g_bfsq   = malloc((size_t)max * sizeof(uint32_t));
    if (!g_goto || !g_output || !g_fail || !g_bfsq) {
        fprintf(stderr, "ac_build: OOM per %d stati\n", max);
        return -1;
    }
    /* Tutte le transizioni inizialmente indefinite. */
    uint32_t *flat = (uint32_t *)g_goto;
    for (size_t i = 0; i < (size_t)max * ALPHA; i++)
        flat[i] = NO_TRANS;
    g_n = 1; /* stato 0 = root già riservato */
    return 0;
}

/* ── Parsing pattern ────────────────────────────────────────────────────── */

static const char METAS[] = ".*+?^$[](){}|";

/*
 * Ritorna 1 se il pattern (nella sintassi Hyperscan) contiene metacaratteri
 * regex non escapati — quindi non può essere trattato come stringa esatta.
 */
static int has_unescaped_meta(const char *p)
{
    while (*p) {
        if (*p == '\\' && *(p + 1)) { p += 2; continue; }
        if (strchr(METAS, *p))       return 1;
        p++;
    }
    return 0;
}

/*
 * Decodifica il pattern Hyperscan in byte grezzi.
 *   \xHH → valore HH
 *   \c   → c letterale (per \. \\ \/ etc.)
 * Normalizza tutto a lowercase per il matching case-insensitive.
 * Ritorna la lunghezza decodificata (≥0), o -1 su errore.
 */
static int decode_and_fold(const char *pat, uint8_t *out, int outsize)
{
    int len = 0;
    const char *p = pat;
    while (*p && len < outsize) {
        if (*p == '\\' && *(p + 1)) {
            if (*(p+1) == 'x' && *(p+2) && *(p+3)) {
                char hex[3] = { *(p+2), *(p+3), '\0' };
                char *endp;
                long val = strtol(hex, &endp, 16);
                if (endp == hex + 2) {
                    out[len++] = (uint8_t)tolower((unsigned char)val);
                    p += 4;
                    continue;
                }
            }
            /* \c → c letterale */
            out[len++] = (uint8_t)tolower((unsigned char)*(p + 1));
            p += 2;
            continue;
        }
        out[len++] = (uint8_t)tolower((unsigned char)*p);
        p++;
    }
    return len;
}

/* ── Inserimento nel trie ───────────────────────────────────────────────── */

/*
 * Inserisce il pattern (raw bytes, len byte) nel trie.
 * Ritorna 0 su successo, -1 se MAX_STATES è stato raggiunto.
 */
static int trie_insert(const uint8_t *pat, int len)
{
    int s = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = pat[i];
        if (g_goto[s][c] == NO_TRANS) {
            if (g_n >= g_max) return -1;
            /* Nuova foglia: tutte le sue transizioni inizialmente NO_TRANS. */
            g_goto[s][c] = (uint32_t)g_n++;
        }
        s = (int)g_goto[s][c];
    }
    g_output[s] = 1;
    return 0;
}

/* ── Raccolta prefissi pattern per il prefiltro n-gram ──────────────────── */

static uint8_t (*g_pat_pfx)[8];   /* primi 8 byte (già lowercase) */
static uint8_t  *g_pat_plen;      /* lunghezza troncata, cap 255  */
static uint32_t  g_pat_n, g_pat_cap;

static int save_pattern_prefix(const uint8_t *pat, int len)
{
    if (g_pat_n == g_pat_cap) {
        g_pat_cap = g_pat_cap ? g_pat_cap * 2 : 4096;
        g_pat_pfx  = realloc(g_pat_pfx,  g_pat_cap * sizeof(*g_pat_pfx));
        g_pat_plen = realloc(g_pat_plen, g_pat_cap);
        if (!g_pat_pfx || !g_pat_plen) return -1;
    }
    memset(g_pat_pfx[g_pat_n], 0, 8);
    memcpy(g_pat_pfx[g_pat_n], pat, len < 8 ? len : 8);
    g_pat_plen[g_pat_n] = (uint8_t)(len < 255 ? len : 255);
    g_pat_n++;
    return 0;
}

/* ── Costruzione bitmap prefiltro ───────────────────────────────────────── */

static inline uint32_t fold4le(const uint8_t *p)
{
    uint32_t w;
    memcpy(&w, p, 4);          /* little-endian su x86, come nel kernel */
    return w | 0x20202020u;
}

static inline void bit_set(uint8_t *bm, uint32_t h)
{
    bm[h >> 3] |= (uint8_t)(1u << (h & 7));
}

/*
 * Riempi le 6 bitmap. t1/t2 hanno 2^PF_BITS_LONG bit, ts[0..3] (len 4..7)
 * 2^PF_BITS_SHORT bit ciascuna. I buffer devono essere azzerati dal chiamante.
 */
static void build_prefilter(uint8_t *t1, uint8_t *t2, uint8_t *ts[4])
{
    for (uint32_t p = 0; p < g_pat_n; p++) {
        const uint8_t *pfx = g_pat_pfx[p];
        int            len = g_pat_plen[p];
        uint32_t       w   = fold4le(pfx);

        bit_set(t1, (w * PF_HASH1) >> (32 - PF_BITS_LONG));

        if (len >= 8) {
            uint32_t w2 = fold4le(pfx + 4);
            bit_set(t2, (w2 * PF_HASH2) >> (32 - PF_BITS_LONG));
        } else {
            /* Hash incrementale dell'intero pattern corto (4..7 byte). */
            uint32_t v = w;
            for (int j = 4; j < len; j++)
                v = ((v << 5) | (v >> 27)) + (uint32_t)(pfx[j] | 0x20);
            bit_set(ts[len - 4], (v * PF_HASH1) >> (32 - PF_BITS_SHORT));
        }
    }
}

/* ── Costruzione DFA (BFS + folding failure links) ─────────────────────── */

/*
 * Trasforma il trie in un DFA completo: per ogni stato e ogni byte,
 * la transizione è definita (nessun NO_TRANS rimane dopo questa funzione).
 *
 * Algoritmo standard Aho-Corasick, BFS:
 *   - Root: le transizioni mancanti tornano al root (loop).
 *   - Stato s a profondità d>0:
 *       se trie_goto[s][c] esiste → è la transizione DFA; fail del figlio
 *                                    = dfa_goto[fail[s]][c]
 *       altrimenti                → dfa_goto[s][c] = dfa_goto[fail[s]][c]
 *   - Output: output[s] |= output[fail[s]]  (propaga match lungo failure)
 *
 * Correttezza: quando processiamo s, g_goto[fail[s]][c] è già completo
 * perché fail[s] ha profondità < profondità di s (BFS garantisce ordine).
 */
static void build_dfa(void)
{
    int head = 0, tail = 0;

    /* Root (stato 0): failure = 0 (se stesso). */
    g_fail[0] = 0;
    for (int c = 0; c < ALPHA; c++) {
        if (g_goto[0][c] == NO_TRANS) {
            g_goto[0][c] = 0; /* loop al root */
        } else {
            uint32_t t = g_goto[0][c];
            g_fail[t] = 0;    /* figli diretti del root: failure = root */
            g_bfsq[tail++] = t;
        }
    }

    while (head < tail) {
        uint32_t s = g_bfsq[head++];

        /* Propaga output lungo failure chain. */
        g_output[s] |= g_output[g_fail[s]];

        for (int c = 0; c < ALPHA; c++) {
            if (g_goto[s][c] != NO_TRANS) {
                /*
                 * Transizione esplicita nel trie: questo figlio andrà in coda.
                 * Il suo failure link è dfa_goto[fail[s]][c] — già calcolato.
                 */
                uint32_t t = g_goto[s][c];
                g_fail[t] = g_goto[g_fail[s]][c];
                g_bfsq[tail++] = t;
            } else {
                /* Nessuna transizione esplicita: segui il failure link. */
                g_goto[s][c] = g_goto[g_fail[s]][c];
            }
        }
    }
}

/* ── Compressione alfabeto (classi di equivalenza) ──────────────────────── */
/*
 * Due byte c1, c2 sono equivalenti se le colonne g_goto[*][c1] e g_goto[*][c2]
 * sono identiche su tutti gli stati: il DFA non li distingue mai.
 *
 * I pattern sono già lowercased al momento dell'inserimento nel trie, quindi
 * le colonne dei caratteri uppercase sarebbero "morte": incorporiamo il
 * case-folding direttamente nella mappa — class_map[C] = classe della colonna
 * di tolower(C). Il modulo kernel non fa più tolower() per byte alla scan.
 *
 * Risultato in g_class_map[256] (byte payload → classe) e g_class_rep[]
 * (carattere rappresentante per ogni classe, usato per impaccare le colonne).
 */
static uint8_t  g_class_map[ALPHA];
static uint8_t  g_class_rep[ALPHA];
static int      g_n_classes;

static int compute_alphabet_classes(void)
{
    uint64_t hash[ALPHA];
    int      class_of[ALPHA];
    int      c, k;

    /* Hash FNV-1a della colonna per ogni carattere canonico (già lowercase). */
    for (c = 0; c < ALPHA; c++) {
        if (tolower(c) != c) continue;
        uint64_t h = 14695981039346656037ULL;
        for (int s = 0; s < g_n; s++) {
            h ^= g_goto[s][c];
            h *= 1099511628211ULL;
        }
        hash[c] = h;
    }

    g_n_classes = 0;
    for (c = 0; c < ALPHA; c++) {
        if (tolower(c) != c) continue;
        class_of[c] = -1;
        for (k = 0; k < g_n_classes; k++) {
            int r = g_class_rep[k];
            if (hash[c] != hash[r]) continue;
            /* Hash uguale: conferma con confronto colonna pieno. */
            int s;
            for (s = 0; s < g_n; s++)
                if (g_goto[s][c] != g_goto[s][r]) break;
            if (s == g_n) { class_of[c] = k; break; }
        }
        if (class_of[c] < 0) {
            if (g_n_classes >= ALPHA) return -1;
            g_class_rep[g_n_classes] = (uint8_t)c;
            class_of[c] = g_n_classes++;
        }
    }

    /* Mappa finale con case-folding incorporato. */
    for (c = 0; c < ALPHA; c++)
        g_class_map[c] = (uint8_t)class_of[tolower(c)];

    return 0;
}

/* ── Scrittura file .acdb (versione 2) ──────────────────────────────────── */

static int write_acdb(const char *path, uint32_t n_pat, uint32_t n_skip,
                      uint32_t min_len, uint32_t trunc)
{
    int      entry16 = (g_n <= 65535);
    uint32_t stride  = 1;
    uint32_t shift   = 0;

    while (stride < (uint32_t)g_n_classes) { stride <<= 1; shift++; }

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "ac_build: impossibile aprire '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    struct ac_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic[0]    = 'A'; hdr.magic[1] = 'C';
    hdr.magic[2]    = 'D'; hdr.magic[3] = 'B';
    hdr.version     = 2;
    hdr.num_states  = (uint32_t)g_n;
    hdr.flags       = 0;
    hdr.state_size  = entry16 ? 2 : 4;
    hdr.num_patterns= n_pat;
    hdr.num_skipped = n_skip;
    hdr.min_len     = min_len;
    hdr.num_classes = (uint32_t)g_n_classes;
    hdr.stride      = stride;
    hdr.shift       = shift;
    hdr.trunc       = trunc;
    hdr.pf_bits_long  = PF_BITS_LONG;
    hdr.pf_bits_short = PF_BITS_SHORT;

    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1) goto ioerr;
    if (fwrite(g_class_map, 1, ALPHA, f) != ALPHA) goto ioerr;

    /* output[]: u8 per stato. */
    for (int i = 0; i < g_n; i++) {
        uint8_t o = g_output[i] ? 1 : 0;
        if (fwrite(&o, 1, 1, f) != 1) goto ioerr;
    }

    /* Padding a 8 byte prima della sezione next. */
    {
        size_t  off = sizeof(hdr) + ALPHA + (size_t)g_n;
        uint8_t zero[8] = {0};
        size_t  pad = (8 - (off & 7)) & 7;
        if (pad && fwrite(zero, 1, pad, f) != pad) goto ioerr;
    }

    /* next[N][stride]: colonne impaccate per classe, resto della riga a 0. */
    for (int s = 0; s < g_n; s++) {
        for (uint32_t k = 0; k < stride; k++) {
            uint32_t v = (k < (uint32_t)g_n_classes)
                         ? g_goto[s][g_class_rep[k]] : 0;
            if (entry16) {
                uint16_t v16 = (uint16_t)v;
                if (fwrite(&v16, 2, 1, f) != 1) goto ioerr;
            } else {
                if (fwrite(&v, 4, 1, f) != 1) goto ioerr;
            }
        }
    }

    /* Bitmap prefiltro: T1 || T2 || TS4 || TS5 || TS6 || TS7. */
    {
        size_t   sz_long  = ((size_t)1 << PF_BITS_LONG)  / 8;
        size_t   sz_short = ((size_t)1 << PF_BITS_SHORT) / 8;
        uint8_t *t1 = calloc(1, sz_long);
        uint8_t *t2 = calloc(1, sz_long);
        uint8_t *ts_all = calloc(4, sz_short);
        uint8_t *ts[4];

        if (!t1 || !t2 || !ts_all) {
            fprintf(stderr, "ac_build: OOM bitmap prefiltro\n");
            free(t1); free(t2); free(ts_all);
            goto ioerr;
        }
        for (int k = 0; k < 4; k++)
            ts[k] = ts_all + (size_t)k * sz_short;

        build_prefilter(t1, t2, ts);

        int ok = fwrite(t1, 1, sz_long, f) == sz_long &&
                 fwrite(t2, 1, sz_long, f) == sz_long &&
                 fwrite(ts_all, 1, 4 * sz_short, f) == 4 * sz_short;
        free(t1); free(t2); free(ts_all);
        if (!ok) goto ioerr;
    }

    fclose(f);
    return 0;

ioerr:
    fprintf(stderr, "ac_build: errore scrittura: %s\n", strerror(errno));
    fclose(f);
    return -1;
}

/* ── Conteggio stati terminali ──────────────────────────────────────────── */
static int count_terminals(void)
{
    int n = 0;
    for (int i = 0; i < g_n; i++)
        if (g_output[i]) n++;
    return n;
}

/* ── DFA Minimization (partition refinement, variante Hopcroft) ─────────── */
/*
 * Raggruppa stati con comportamento identico (stesse transizioni verso le
 * stesse classi di equivalenza) fino a convergenza.
 *
 * Complessità: O(rounds × n × ALPHA) — nella pratica pochi round.
 * Memoria extra: O(n) — solo vettori di interi, nessuna copia della tabella.
 *
 * Al termine, g_goto[], g_output[] e g_n vengono aggiornati con il DFA
 * minimizzato. Lo stato root (originale 0) rimane stato 0.
 */

/* Puntatori usati dalla funzione di confronto qsort (non rientrante). */
static uint32_t *g_min_class;
static uint64_t *g_min_hash;

/* Calcola un hash FNV-1a della firma di ogni stato per il round corrente.
 * La firma è: (class[s], class[next[s][0]], ..., class[next[s][255]]). */
static void compute_sig_hashes(int n)
{
    for (int s = 0; s < n; s++) {
        uint64_t h = (uint64_t)g_min_class[s] * 14695981039346656037ULL;
        for (int c = 0; c < ALPHA; c++) {
            h ^= (uint64_t)g_min_class[g_goto[s][c]];
            h *= 1099511628211ULL;
        }
        g_min_hash[s] = h;
    }
}

/* Confronto totale tra due stati: (own_class, hash, transizioni). */
static int cmp_by_sig(const void *a, const void *b)
{
    uint32_t sa = *(const uint32_t *)a;
    uint32_t sb = *(const uint32_t *)b;

    if (g_min_class[sa] < g_min_class[sb]) return -1;
    if (g_min_class[sa] > g_min_class[sb]) return +1;

    /* Fast path: hash diversi → classi diverse (O(1)) */
    if (g_min_hash[sa] < g_min_hash[sb]) return -1;
    if (g_min_hash[sa] > g_min_hash[sb]) return +1;

    /* Hash collision (rarissimo): confronto pieno O(ALPHA) */
    for (int c = 0; c < ALPHA; c++) {
        uint32_t ca = g_min_class[g_goto[sa][c]];
        uint32_t cb = g_min_class[g_goto[sb][c]];
        if (ca < cb) return -1;
        if (ca > cb) return +1;
    }
    return 0; /* stati veramente equivalenti */
}

static int minimize_dfa(void)
{
    int n = g_n;
    if (n <= 2) return 0;

    uint32_t *class     = malloc((size_t)n * sizeof(uint32_t));
    uint32_t *new_class = malloc((size_t)n * sizeof(uint32_t));
    uint32_t *sort_idx  = malloc((size_t)n * sizeof(uint32_t));
    uint64_t *hash_arr  = malloc((size_t)n * sizeof(uint64_t));
    if (!class || !new_class || !sort_idx || !hash_arr) {
        fprintf(stderr, "ac_build: OOM minimizzazione\n");
        free(class); free(new_class); free(sort_idx); free(hash_arr);
        return -1;
    }

    /* Partizione iniziale: terminale (1) vs non-terminale (0). */
    for (int i = 0; i < n; i++)
        class[i] = g_output[i] ? 1 : 0;
    uint32_t n_classes = 2;

    g_min_class = class;
    g_min_hash  = hash_arr;

    fprintf(stderr, "ac_build: minimizzazione DFA (%d stati)...\n", n);

    for (int round = 0; ; round++) {
        compute_sig_hashes(n);
        for (int i = 0; i < n; i++) sort_idx[i] = (uint32_t)i;
        qsort(sort_idx, (size_t)n, sizeof(uint32_t), cmp_by_sig);

        /* Assegna nuovi ID di classe agli stati nell'ordine di sort. */
        new_class[sort_idx[0]] = 0;
        uint32_t nc = 0;
        for (int i = 1; i < n; i++) {
            if (cmp_by_sig(&sort_idx[i], &sort_idx[i - 1]) != 0)
                nc++;
            new_class[sort_idx[i]] = nc;
        }
        nc++;

        fprintf(stderr, "  round %2d: %u → %u classi\n", round, n_classes, nc);

        if (nc == n_classes) break; /* convergenza: nessuna classe si è divisa */
        n_classes = nc;
        memcpy(class, new_class, (size_t)n * sizeof(uint32_t));
    }
    /* new_class[] contiene la partizione finale. */

    /* Garantisce che il root (stato 0 originale) → classe 0. */
    uint32_t root_cls = new_class[0];
    if (root_cls != 0) {
        for (int i = 0; i < n; i++) {
            if      (new_class[i] == 0)        new_class[i] = root_cls;
            else if (new_class[i] == root_cls)  new_class[i] = 0;
        }
    }

    /* ── Costruzione DFA minimizzato ── */

    /* Un rappresentante per ogni classe. */
    uint32_t *rep = malloc((size_t)n_classes * sizeof(uint32_t));
    if (!rep) { fprintf(stderr, "ac_build: OOM rep\n"); goto out; }
    memset(rep, 0xff, (size_t)n_classes * sizeof(uint32_t));
    for (int s = 0; s < n; s++) {
        uint32_t cls = new_class[s];
        if (rep[cls] == UINT32_MAX)
            rep[cls] = (uint32_t)s;
    }

    /* Tabelle rimappate (n_classes stati). */
    uint32_t (*ng)[ALPHA] = malloc((size_t)n_classes * ALPHA * sizeof(uint32_t));
    uint32_t  *no         = malloc((size_t)n_classes * sizeof(uint32_t));
    if (!ng || !no) {
        fprintf(stderr, "ac_build: OOM tabelle min\n");
        free(rep); free(ng); free(no);
        goto out;
    }

    for (uint32_t cls = 0; cls < n_classes; cls++) {
        uint32_t r = rep[cls];
        for (int c = 0; c < ALPHA; c++)
            ng[cls][c] = new_class[g_goto[r][c]];
        no[cls] = g_output[r];
    }

    /* Sostituzione in-place delle tabelle globali. */
    memcpy(g_goto,   ng, (size_t)n_classes * ALPHA * sizeof(uint32_t));
    memcpy(g_output, no, (size_t)n_classes * sizeof(uint32_t));
    g_n = (int)n_classes;

    free(rep); free(ng); free(no);
    fprintf(stderr,
        "ac_build: DFA minimizzato: %d → %d stati (riduzione %.1f%%)\n",
        n, (int)n_classes, 100.0 * (n - n_classes) / n);

out:
    free(class); free(new_class); free(sort_idx); free(hash_arr);
    return 0;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s [-n MAX_STATES] [-m MIN_LEN] [-t TRUNC] [-o output.acdb] patterns.hs\n\n"
        "  -n MAX_STATES  stati DFA massimi (default %d)\n"
        "  -m MIN_LEN     lunghezza minima pattern in byte (default %d)\n"
        "  -t TRUNC       tronca i pattern ai primi TRUNC byte (default %d, 0=off)\n"
        "                 da prefiltro: i falsi positivi vanno a Suricata che verifica\n"
        "  -o OUTPUT      file output (default: patterns.acdb)\n\n"
        "Produce ACDB v2 (alfabeto compresso, entry u16 se stati < 65536).\n"
        "Il file .acdb viene caricato nel modulo kernel tramite:\n"
        "  dd if=patterns.acdb of=/sys/kernel/config/ac/<policy>/database\n",
        prog, DEFAULT_MAX_STATES, DEFAULT_MIN_LEN, DEFAULT_TRUNC);
}

int main(int argc, char **argv)
{
    int         max_states = DEFAULT_MAX_STATES;
    int         min_len    = DEFAULT_MIN_LEN;
    int         trunc      = DEFAULT_TRUNC;
    const char *outpath    = "patterns.acdb";
    int         opt;

    while ((opt = getopt(argc, argv, "n:m:t:o:h")) != -1) {
        switch (opt) {
        case 'n': max_states = atoi(optarg); break;
        case 'm': min_len    = atoi(optarg); break;
        case 't': trunc      = atoi(optarg); break;
        case 'o': outpath    = optarg;       break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind >= argc) { usage(argv[0]); return 1; }

    if (max_states < 2 || max_states > (1 << 24)) {
        fprintf(stderr, "ac_build: MAX_STATES fuori range [2, 16777216]\n");
        return 1;
    }

    /* ── Alloca tabelle ── */
    double alloc_mb = (double)max_states *
                      (ALPHA * sizeof(uint32_t) + 3 * sizeof(uint32_t)) / (1024.0*1024.0);
    fprintf(stderr, "ac_build: alloco %.1f MB per %d stati...\n", alloc_mb, max_states);
    if (alloc_tables(max_states) != 0) return 1;

    /* ── Leggi e inserisci pattern ── */
    FILE *fin = fopen(argv[optind], "r");
    if (!fin) {
        fprintf(stderr, "ac_build: impossibile aprire '%s': %s\n",
                argv[optind], strerror(errno));
        return 1;
    }

    uint32_t n_inserted = 0;   /* pattern inseriti (inclusi dup) */
    uint32_t n_new_term = 0;   /* pattern che hanno aggiunto almeno uno stato */
    uint32_t n_skip_meta  = 0;
    uint32_t n_skip_short = 0;
    uint32_t n_overflow   = 0;
    uint8_t  rawpat[MAX_PATTERN_LEN];
    char     line[4096];

    while (fgets(line, sizeof(line), fin)) {
        /* Formato: <id>:/<pattern>/[flag] */
        char *colon = strchr(line, ':');
        if (!colon || *(colon+1) != '/') continue;
        char *pat_start = colon + 2;

        char *last_slash = strrchr(pat_start, '/');
        if (!last_slash || last_slash == pat_start - 1) continue;
        *last_slash = '\0';
        /* flag (es. "i") è dopo l'ultimo slash — non ci serve più ora */

        /* Salta pattern con metacaratteri regex. */
        if (has_unescaped_meta(pat_start)) { n_skip_meta++;  continue; }

        /* Decodifica e case-fold. */
        int rawlen = decode_and_fold(pat_start, rawpat, sizeof(rawpat));
        if (rawlen < min_len) { n_skip_short++; continue; }

        /*
         * Troncamento: da prefiltro basta matchare il prefisso — un match
         * parziale produce al più un falso positivo che Suricata verifica.
         * Riduce drasticamente gli stati (i suffissi lunghi non condivisi
         * sono la maggioranza dei nodi del trie).
         */
        if (trunc > 0 && rawlen > trunc)
            rawlen = trunc;

        /* Inserisci nel trie. */
        int prev_n = g_n;
        if (trie_insert(rawpat, rawlen) < 0) {
            n_overflow++;
            continue;
        }
        if (save_pattern_prefix(rawpat, rawlen) < 0) {
            fprintf(stderr, "ac_build: OOM prefissi pattern\n");
            return 1;
        }
        n_inserted++;
        if (g_n > prev_n) n_new_term++;
    }
    fclose(fin);

    /* ── Report fase 1 ── */
    fprintf(stderr,
        "\n--- Trie inserimento ---\n"
        "  Pattern inseriti    : %u (di cui %u con nuovi stati)\n"
        "  Skippati (regex)    : %u\n"
        "  Skippati (< %d byte): %u\n"
        "  Overflow (MAX=%d) : %u\n"
        "  Stati nel trie      : %d\n",
        n_inserted, n_new_term,
        n_skip_meta,
        min_len, n_skip_short,
        max_states, n_overflow,
        g_n);

    if (n_overflow > 0)
        fprintf(stderr,
            "  ATTENZIONE: %u pattern non caricati — aumenta -n\n", n_overflow);

    /* ── Costruzione DFA ── */
    fprintf(stderr, "\nac_build: costruzione DFA (BFS failure folding)...\n");
    build_dfa();

    int pre_min_states = g_n;
    int pre_min_term   = count_terminals();
    fprintf(stderr,
        "\n--- DFA pre-minimizzazione ---\n"
        "  Stati totali        : %d\n"
        "  Stati terminali     : %d\n\n",
        pre_min_states, pre_min_term);

    /* ── Minimizzazione DFA ── */
    minimize_dfa();

    int terminals = count_terminals();

    /* ── Compressione alfabeto ── */
    fprintf(stderr, "ac_build: calcolo classi di equivalenza alfabeto...\n");
    if (compute_alphabet_classes() != 0) {
        fprintf(stderr, "ac_build: errore classi alfabeto\n");
        return 1;
    }

    uint32_t stride = 1, shift = 0;
    while (stride < (uint32_t)g_n_classes) { stride <<= 1; shift++; }
    int entry_sz = (g_n <= 65535) ? 2 : 4;

    size_t pf_bytes = 2 * (((size_t)1 << PF_BITS_LONG) / 8) +
                      4 * (((size_t)1 << PF_BITS_SHORT) / 8);
    size_t body = (size_t)ALPHA + (size_t)g_n;
    body += (8 - ((64 + body) & 7)) & 7;
    body += (size_t)g_n * stride * entry_sz;
    body += pf_bytes;
    double file_mb = (64.0 + (double)body) / (1024.0*1024.0);

    uint32_t n_short = 0;
    for (uint32_t p = 0; p < g_pat_n; p++)
        if (g_pat_plen[p] < 8) n_short++;

    fprintf(stderr,
        "\n--- DFA finale (ACDB v2) ---\n"
        "  Stati totali        : %d\n"
        "  Stati terminali     : %d\n"
        "  Troncamento pattern : %d byte\n"
        "  Classi alfabeto     : %d  (stride %u, shift %u)\n"
        "  Entry transizione   : u%d\n"
        "  Riga per stato      : %u byte\n"
        "  Prefiltro n-gram    : T1/T2 %u KB, TS×4 %u KB  (%u pattern corti <8B)\n"
        "  Dimensione .acdb    : %.2f MB  (= working set kernel)\n\n",
        g_n, terminals, trunc, g_n_classes, stride, shift,
        entry_sz * 8, stride * entry_sz,
        (1u << PF_BITS_LONG) / 8192, (1u << PF_BITS_SHORT) / 8192 * 4,
        n_short, file_mb);

    if (g_n > 65535)
        fprintf(stderr,
            "  NOTA: stati > 65535 → entry u32; riduci -t per righe u16\n\n");

    /* ── Scrivi file ── */
    if (write_acdb(outpath,
                   n_inserted,
                   n_skip_meta + n_skip_short + n_overflow,
                   (uint32_t)min_len, (uint32_t)trunc) != 0)
        return 1;

    fprintf(stderr, "ac_build: scritto '%s' (%.2f MB)\n", outpath, file_mb);
    return 0;
}
