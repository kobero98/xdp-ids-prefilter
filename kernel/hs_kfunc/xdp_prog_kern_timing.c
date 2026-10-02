#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "rex.h"

#define ID_BUONI          1234
#define ID_CATTIVI        4321
#define ID_CATTIVI_STREAM 4322

#define DBG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)

// =======================
// COUNTERS INDEX
// =======================
#define CNT_COND        0
#define CNT_ERROR       1
#define CNT_BAD         2
#define CNT_GOOD        3
#define CNT_PACKET      4
#define PAKCET_TCP_S    5
#define PRIMO_IF        6
#define SECONDO_IF      7

// =======================
// TIMING INDEX
// =======================
#define TIMING_SUM_NS    0   /* somma dei tempi di scan in ns (per CPU) */
#define TIMING_COUNT     1   /* numero di scan eseguiti (per CPU)        */
#define TIMING_MAX_NS    2   /* tempo massimo osservato in ns (per CPU)  */
#define TIMING_SUM_BYTES 3   /* somma dei byte scansionati (per CPU)     */

char LICENSE[] SEC("license") = "GPL";

// =======================
// kfunc
// =======================
int bpf_xdp_scan_bytes(struct xdp_md *ctx, __u32 offset, __u32 len,
                       struct rex_scan_attr *scan_attr,
                       __u32 payload_offset) __ksym;

int bpf_xdp_stream_scan_bytes(struct xdp_md *ctx,
                               struct rex_scan_attr *scan_attr,
                               struct rex_flow_key  *key,
                               __u32 payload_offset, __u32 len) __ksym;

// =======================
// MAPPA POLICY
// =======================
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

// =======================
// COUNTERS MAP
// =======================
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// =======================
// TIMING MAP (per CPU)
// indice 0: somma ns, 1: conteggio scan, 2: max ns
// =======================
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} hs_timing SEC(".maps");

// =======================
// helpers
// =======================
static __always_inline void inc_counter(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v)
        (*v)++;
}

static __always_inline void timing_record(__u64 elapsed_ns, __u32 nbytes)
{
    __u32 k;
    __u64 *v;

    k = TIMING_SUM_NS;
    v = bpf_map_lookup_elem(&hs_timing, &k);
    if (v)
        *v += elapsed_ns;

    k = TIMING_COUNT;
    v = bpf_map_lookup_elem(&hs_timing, &k);
    if (v)
        (*v)++;

    k = TIMING_MAX_NS;
    v = bpf_map_lookup_elem(&hs_timing, &k);
    if (v && elapsed_ns > *v)
        *v = elapsed_ns;

    k = TIMING_SUM_BYTES;
    v = bpf_map_lookup_elem(&hs_timing, &k);
    if (v)
        *v += nbytes;
}

// =======================
// HTTP PAYLOAD DUMP
// =======================
static __always_inline void dump_http_payload(
    void *data,
    void *data_end,
    __u32 payload_offset
)
{
    unsigned char *p = data + payload_offset;
    char buf[48] = {};

    if ((void *)(p + 48) > data_end) {
        DBG("non posso stampare %p, %p", p, data_end);
        return;
    }

#pragma unroll
    for (int i = 0; i < 47; i++) {
        if ((void *)(p + i + 1) > data_end)
            break;
        char c = p[i];
        buf[i] = (c >= 32 && c <= 126) ? c : '.';
    }

    DBG("HTTP PAYLOAD: %.47s", buf);
}

// =======================
// XDP PROGRAM
// =======================
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    inc_counter(CNT_PACKET);

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    __u16 port_src = 0;
    __u16 port_dst = 0;

    __u32 payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

    // =======================
    // TCP
    // =======================
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        port_dst = __builtin_bswap16(tcp->dest);
        port_src = __builtin_bswap16(tcp->source);
        payload_offset += tcp->doff * 4;

        if (tcp->syn || tcp->fin || tcp->rst) {
            inc_counter(PAKCET_TCP_S);
            return XDP_PASS;
        }
    }

    // =======================
    // UDP
    // =======================
    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        port_dst = __builtin_bswap16(udp->dest);
        port_src = __builtin_bswap16(udp->source);
        payload_offset += sizeof(struct udphdr);
    }

    // =======================
    // TLS APPLICATION DATA BYPASS
    // =======================
    if (proto == IPPROTO_TCP && (port_dst == 443 || port_src == 443)) {
        __u32 pkt_len_tls = (void *)data_end - data;
        if (payload_offset + 2 <= pkt_len_tls) {
            unsigned char *p = (unsigned char *)data + payload_offset;
            if ((void *)(p + 2) <= data_end) {
                if (p[0] == 0x17 && p[1] == 0x03) {
                    inc_counter(CNT_GOOD);
                    return XDP_DROP;
                }
            }
        }
    }

    // =======================
    // MAP LOOKUP
    // =======================
    struct app_key key_dst = { .ip_proto = proto, .port = port_dst, .pad = 0 };
    struct app_key key_src = { .ip_proto = proto, .port = port_src, .pad = 0 };

    struct app_policy *pol_dst = bpf_map_lookup_elem(&app_map, &key_dst);
    struct app_policy *pol_src = bpf_map_lookup_elem(&app_map, &key_src);

    int cond = 0;
    if (pol_src && pol_src->enabled) cond = 1;
    if (pol_dst && pol_dst->enabled) cond = 1;

    __u32 pkt_len = data_end - data;

    struct rex_scan_attr attr = {};

    // =======================
    // PROTOCOLLO MATCHATO
    // =======================
    if (cond == 1) {
        inc_counter(CNT_COND);

        if (payload_offset >= pkt_len)
            return XDP_PASS;

        __u32 payload_len = pkt_len - payload_offset;

        if (payload_len == 0)
            return XDP_PASS;

        attr.database_id = ID_CATTIVI;

        __u64 t_start = bpf_ktime_get_ns();

        int ret = bpf_xdp_scan_bytes(
            ctx,
            0,
            payload_len,
            &attr,
            payload_offset
        );

        __u64 t_end = bpf_ktime_get_ns();
        timing_record(t_end - t_start, payload_len);

        if (ret < 0) {
            inc_counter(CNT_ERROR);
            return XDP_PASS;
        }

        if (attr.nr_events > 0) {
            inc_counter(CNT_BAD);
            return XDP_PASS;
        }

        inc_counter(CNT_GOOD);
        return XDP_DROP;
    }

    return XDP_PASS;
}
