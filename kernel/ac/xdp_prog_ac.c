/*
 * xdp_prog_ac.c — XDP BPF program con Aho-Corasick kfunc
 *
 * Speculare a xdp_prog_kern_test.c (Hyperscan) ma usa bpf_xdp_ac_scan()
 * invece di bpf_xdp_scan_bytes():
 *   - Nessun rex_scan_attr: il kfunc restituisce direttamente 0/1
 *   - Nessun FPU overhead (kernel_fpu_begin/end)
 *   - Scan loop puramente scalare nel modulo kernel
 *
 * Logica (identica al programma Hyperscan):
 *   1. Parsea Ethernet / IP / TCP / UDP, calcola payload_offset
 *   2. Cerca proto+porta in app_map
 *   3. Se trovato: scansiona con AC (DB ID_AC_CATTIVI)
 *        match    → XDP_PASS  (Suricata deve analizzarlo)
 *        no match → XDP_DROP  (pattern non riconosciuto: scarta)
 *        errore   → XDP_PASS  (fail-open)
 *   4. Se non trovato: XDP_PASS
 *
 * Deployment:
 *   clang -O2 -g -target bpf -c xdp_prog_ac.c -o xdp_prog_ac.o
 *   bpftool prog load xdp_prog_ac.o /sys/fs/bpf/xdp_prog_ac
 *   ip link set dev <iface> xdp pinned /sys/fs/bpf/xdp_prog_ac
 *
 * Il DB ID (ID_AC_CATTIVI) deve corrispondere all'id impostato via:
 *   echo 9999 > /sys/kernel/config/ac/cattivi/id
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* ID del database AC (deve combaciare con /sys/kernel/config/ac/<policy>/id) */
#define ID_AC_CATTIVI   9999

/* Numero massimo di byte da scansionare per pacchetto (dimensione trama Ethernet). */
#define MAX_SCAN        1500

char LICENSE[] SEC("license") = "GPL";

/* ── kfunc declaration ─────────────────────────────────────────────────── */
/*
 * bpf_xdp_ac_scan è definito in xdp_ac_module.ko.
 * Il verifier BPF lo risolve via BTF (__ksym).
 *
 * Ritorna: 1 = match, 0 = no match, <0 = errore
 */
int bpf_xdp_ac_scan(struct xdp_md *ctx,
                    __u32 db_id,
                    __u32 offset,
                    __u32 len) __ksym;

/* ── Mappa contatore drop (per-CPU) ────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} xdp_drop_cnt SEC(".maps");

/* ── Mappa timing scan (per-CPU): key 0=sum_ns, 1=count, 2=max_ns ──────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} ac_timing SEC(".maps");

static __always_inline void inc_drop_cnt(void)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&xdp_drop_cnt, &key);
    if (v)
        (*v)++;
}

/* ── Mappa policy proto/porta (condivisa con il programma Hyperscan) ───── */
struct __attribute__((packed)) app_key {
    __u8  ip_proto;
    __u16 port;
    __u8  pad;
};

struct app_policy {
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct app_key);
    __type(value, struct app_policy);
} app_map SEC(".maps");

/* ── XDP program ───────────────────────────────────────────────────────── */
SEC("xdp")
int xdp_prog_ac(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    /* ── IP ── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    __u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
    __u16 port_src = 0, port_dst = 0;

    /* ── TCP ── */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        port_src = __builtin_bswap16(tcp->source);
        port_dst = __builtin_bswap16(tcp->dest);
        payload_offset += tcp->doff * 4;

        /* SYN/FIN/RST: nessun payload applicativo, passa sempre */
        if (tcp->syn || tcp->fin || tcp->rst)
            return XDP_PASS;
    }

    /* ── UDP ── */
    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        port_src = __builtin_bswap16(udp->source);
        port_dst = __builtin_bswap16(udp->dest);
        payload_offset += sizeof(struct udphdr);
    }

    /* ── Payload vuoto: niente da scansionare ──
     * pkt_len va derivato da ip->tot_len, NON dal frame: i frame corti
     * vengono paddati a 60 byte sul filo e il padding verrebbe scansionato
     * come payload (gli ACK puri risulterebbero "clean" → DROP, spezzando
     * lo stream TCP che Suricata deve ricostruire). */
    __u32 frame_len = (__u32)((void *)data_end - data);
    __u32 ip_len    = sizeof(struct ethhdr) + __builtin_bswap16(ip->tot_len);
    __u32 pkt_len   = ip_len < frame_len ? ip_len : frame_len;
    if (payload_offset >= pkt_len)
        return XDP_PASS;

    /* ── app_map lookup ── */
    struct app_key key_dst = { .ip_proto = proto, .port = port_dst, .pad = 0 };
    struct app_key key_src = { .ip_proto = proto, .port = port_src, .pad = 0 };

    struct app_policy *pol_dst = bpf_map_lookup_elem(&app_map, &key_dst);
    struct app_policy *pol_src = bpf_map_lookup_elem(&app_map, &key_src);

    if (!(pol_dst && pol_dst->enabled) && !(pol_src && pol_src->enabled)) {
        return XDP_PASS;   /* protocollo non monitorato */
    }

    /* ── Scan AC ── */
    __u32 payload_len = pkt_len - payload_offset;
    if (payload_len > MAX_SCAN)
        payload_len = MAX_SCAN;

    /*
     * Strumentazione timing: attiva solo con -DAC_TIMING (per timing_scan_test).
     * Negli stress/speed test la si esclude → path più pulito, niente overhead
     * di 2× bpf_ktime_get_ns + 3 map lookup per pacchetto.
     */
#ifdef AC_TIMING
    __u64 t0 = bpf_ktime_get_ns();
    int ret = bpf_xdp_ac_scan(ctx, ID_AC_CATTIVI, payload_offset, payload_len);
    __u64 dt = bpf_ktime_get_ns() - t0;

    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u64 *sum = bpf_map_lookup_elem(&ac_timing, &k0);
    __u64 *cnt = bpf_map_lookup_elem(&ac_timing, &k1);
    __u64 *mx  = bpf_map_lookup_elem(&ac_timing, &k2);
    if (sum) *sum += dt;
    if (cnt) (*cnt)++;
    if (mx && dt > *mx) *mx = dt;
#else
    int ret = bpf_xdp_ac_scan(ctx, ID_AC_CATTIVI, payload_offset, payload_len);
#endif

    if (ret < 0)
        return XDP_PASS;   /* errore: fail-open */

    if (ret == 1)
        return XDP_PASS;   /* match: Suricata deve vederlo */

    /* No match: pacchetto non corrisponde a nessun pattern noto */
    inc_drop_cnt();
    return XDP_DROP;
}
