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
// CONTATORE XDP_DROP (per-CPU)
// =======================
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} xdp_drop_cnt SEC(".maps");

static __always_inline void inc_drop_cnt(void)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&xdp_drop_cnt, &key);
    if (v)
        (*v)++;
}

// =======================
// MAPPA POLICY
// =======================
struct __attribute__((packed)) app_key {
    __u8 ip_proto;
    __u16 port;
    __u8 pad;
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

    if ((void *)(p + 48) > data_end){
	    DBG("non posso stampare %p, %p",p,data_end);
	    return;
    }

#pragma unroll
    for (int i = 0; i < 47; i++) {

        if ((void *)(p + i + 1) > data_end)
            break;

        char c = p[i];

        if (c >= 32 && c <= 126)
            buf[i] = c;
        else
            buf[i] = '.';
    }

    DBG("HTTP PAYLOAD: %.47s", buf);
}

// =======================
// XDP PROGRAM
// =======================
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;


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

    // CORRETTO: usa ip->ihl
    __u32 payload_offset =
        sizeof(struct ethhdr) + (ip->ihl * 4);

    // =======================
    // TCP
    // =======================
    if (proto == IPPROTO_TCP) {

        struct tcphdr *tcp =
            (void *)ip + (ip->ihl * 4);

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        port_dst = __builtin_bswap16(tcp->dest);
        port_src = __builtin_bswap16(tcp->source);

        // CORRETTO: usa tcp->doff
        payload_offset += tcp->doff * 4;

        /* SYN/FIN/RST packets must always reach Suricata for TCP session
         * tracking. Ethernet padding can make payload_len non-zero even
         * for pure handshake packets, so the payload_len==0 guard below
         * is not sufficient. Check flags here, before any Hyperscan scan. */
        if (tcp->syn || tcp->fin || tcp->rst)
            return XDP_PASS;
    }

    // =======================
    // UDP
    // =======================
    if (proto == IPPROTO_UDP) {

        struct udphdr *udp =
            (void *)ip + (ip->ihl * 4);

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        port_dst = __builtin_bswap16(udp->dest);
        port_src = __builtin_bswap16(udp->source);

        payload_offset += sizeof(struct udphdr);
    }

    // =======================
    // EARLY PAYLOAD CHECK (TCP + UDP)
    // Pacchetti senza payload applicativo non hanno nulla da scansionare.
    // Il check avviene prima del map lookup per entrambi i protocolli.
    // =======================
    __u32 pkt_len = (void *)data_end - data;

    if (payload_offset >= pkt_len)
        return XDP_PASS;

    // =======================
    // MAP LOOKUP
    // =======================
    struct app_key key_dst = {
        .ip_proto = proto,
        .port = port_dst,
        .pad = 0
    };

    struct app_key key_src = {
        .ip_proto = proto,
        .port = port_src,
        .pad = 0
    };

    struct app_policy *pol_dst =
        bpf_map_lookup_elem(&app_map, &key_dst);

    struct app_policy *pol_src =
        bpf_map_lookup_elem(&app_map, &key_src);

    int cond = 0;

    if (pol_src && pol_src->enabled)
        cond = 1;

    if (pol_dst && pol_dst->enabled)
        cond = 1;

    struct rex_scan_attr attr = {};

    // =======================
    // PROTOCOLLO MATCHATO
    // =======================
    if (cond == 1) {

        __u32 payload_len = pkt_len - payload_offset;

        attr.database_id = ID_CATTIVI;

        int ret = bpf_xdp_scan_bytes(
            ctx,
            0,
            payload_len,
            &attr,
            payload_offset
        );

        if (ret < 0)
            return XDP_PASS;

        if (attr.nr_events > 0)
            return XDP_PASS;

        inc_drop_cnt();
        return XDP_DROP;
    }

    // =======================
    // DB BUONI
    // =======================
    /*
   
    attr.database_id = ID_BUONI;

    int ret = bpf_xdp_scan_bytes(
        ctx,
        0,
        pkt_len - payload_offset,
        &attr,
        payload_offset
    );

    if (ret >= 0 && attr.nr_events > 0) {
        inc_counter(CNT_GOOD);
        return bpf_redirect(0, 0);
    }
	*/
    return XDP_PASS;
}
