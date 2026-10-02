#include "pcap_analyzer.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static Flow flow_table[MAX_FLOWS];
static int  flow_count = 0;

static int flow_exists(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto) {
    for (int i = 0; i < flow_count; i++) {
        Flow *f = &flow_table[i];
        if (f->proto == proto &&
            ((f->src_ip == sip && f->dst_ip == dip && f->src_port == sp && f->dst_port == dp) ||
             (f->src_ip == dip && f->dst_ip == sip && f->src_port == dp && f->dst_port == sp)))
            return 1;
    }
    return 0;
}

static void flow_add(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto) {
    if (flow_count >= MAX_FLOWS) return;
    flow_table[flow_count].src_ip   = sip;
    flow_table[flow_count].dst_ip   = dip;
    flow_table[flow_count].src_port = sp;
    flow_table[flow_count].dst_port = dp;
    flow_table[flow_count].proto    = proto;
    flow_count++;
}

#define PORT_MATCH(sp, dp, port) ((sp) == (port) || (dp) == (port))

/* Returns the application-layer ProtoKind based on transport + ports. */
static ProtoKind classify_port(uint8_t transport, uint16_t sp, uint16_t dp) {
    if (transport == IPPROTO_TCP) {
        if (PORT_MATCH(sp, dp,  80))                              return PROTO_HTTP;
        if (PORT_MATCH(sp, dp, 443))                              return PROTO_TLS;
        if (PORT_MATCH(sp, dp,  53))                              return PROTO_DNS;
        if (PORT_MATCH(sp, dp,  21) || PORT_MATCH(sp, dp, 20))   return PROTO_FTP;
        if (PORT_MATCH(sp, dp, 445) || PORT_MATCH(sp, dp, 139))  return PROTO_SMB;
        if (PORT_MATCH(sp, dp, 135))                              return PROTO_DCERPC;
        if (PORT_MATCH(sp, dp,  22))                              return PROTO_SSH;
        if (PORT_MATCH(sp, dp,  25) || PORT_MATCH(sp, dp, 587) ||
            PORT_MATCH(sp, dp, 465))                              return PROTO_SMTP;
        if (PORT_MATCH(sp, dp, 143) || PORT_MATCH(sp, dp, 993))  return PROTO_IMAP;
        if (PORT_MATCH(sp, dp, 110) || PORT_MATCH(sp, dp, 995))  return PROTO_POP3;
        if (PORT_MATCH(sp, dp, 502))                              return PROTO_MODBUS;
        if (PORT_MATCH(sp, dp, 20000))                            return PROTO_DNP3;
        if (PORT_MATCH(sp, dp, 2049))                             return PROTO_NFS;
        if (PORT_MATCH(sp, dp,  88))                              return PROTO_KRB5;
        if (PORT_MATCH(sp, dp, 1883) || PORT_MATCH(sp, dp, 8883)) return PROTO_MQTT;
        if (PORT_MATCH(sp, dp, 5900))                             return PROTO_RFB;
        if (PORT_MATCH(sp, dp, 3389))                             return PROTO_RDP;
        if (PORT_MATCH(sp, dp,  23))                              return PROTO_TELNET;
        if (PORT_MATCH(sp, dp, 5432))                             return PROTO_PGSQL;
    } else if (transport == IPPROTO_UDP) {
        if (PORT_MATCH(sp, dp,  53))                              return PROTO_DNS;
        if (PORT_MATCH(sp, dp, 443))                              return PROTO_QUIC;
        if (PORT_MATCH(sp, dp, 5353))                             return PROTO_MDNS;
        if (PORT_MATCH(sp, dp,  67) || PORT_MATCH(sp, dp,  68))  return PROTO_DHCP;
        if (PORT_MATCH(sp, dp, 500) || PORT_MATCH(sp, dp, 4500)) return PROTO_IKE;
        if (PORT_MATCH(sp, dp, 6881))                             return PROTO_BITTORRENT_DHT;
        if (PORT_MATCH(sp, dp, 123))                              return PROTO_NTP;
        if (PORT_MATCH(sp, dp, 161) || PORT_MATCH(sp, dp, 162))  return PROTO_SNMP;
        if (PORT_MATCH(sp, dp,  69))                              return PROTO_TFTP;
        if (PORT_MATCH(sp, dp,  88))                              return PROTO_KRB5;
        if (PORT_MATCH(sp, dp, 2049))                             return PROTO_NFS;
    }
    return PROTO_OTHER;
}

int pcap_analyze(const char *filename, PcapStats *stats) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(stats, 0, sizeof(*stats));
    flow_count = 0;

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return -1;
    }

    int datalink = pcap_datalink(handle);
    int eth_offset = 0;
    if (datalink == DLT_EN10MB) eth_offset = 14;
    else if (datalink == DLT_LINUX_SLL) eth_offset = 16;

    struct pcap_pkthdr *header;
    const u_char *data;
    int ret;

    while ((ret = pcap_next_ex(handle, &header, &data)) == 1) {
        if (header->caplen < (unsigned)(eth_offset + (int)sizeof(struct ip)))
            continue;

        const struct ip *iph = (const struct ip *)(data + eth_offset);
        if (iph->ip_v != 4) continue;

        stats->total_ip++;
        int ip_hlen = iph->ip_hl * 4;
        uint8_t proto = iph->ip_p;

        if (proto == IPPROTO_TCP) {
            const struct tcphdr *th = (const struct tcphdr *)((const u_char *)iph + ip_hlen);
            uint16_t sp = ntohs(th->th_sport);
            uint16_t dp = ntohs(th->th_dport);
            if (!flow_exists(iph->ip_src.s_addr, iph->ip_dst.s_addr, sp, dp, proto))
                flow_add(iph->ip_src.s_addr, iph->ip_dst.s_addr, sp, dp, proto);
            ProtoKind pk = classify_port(proto, sp, dp);
            stats->proto_packets[pk]++;
            stats->total_app_packets++;
        } else if (proto == IPPROTO_UDP) {
            const struct udphdr *uh = (const struct udphdr *)((const u_char *)iph + ip_hlen);
            uint16_t sp = ntohs(uh->uh_sport);
            uint16_t dp = ntohs(uh->uh_dport);
            stats->udp_packets++;
            ProtoKind pk = classify_port(proto, sp, dp);
            stats->proto_packets[pk]++;
            stats->total_app_packets++;
        }
    }

    if (ret == -1) fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(handle));
    stats->tcp_flows = flow_count;
    pcap_close(handle);

    if (stats->total_ip == 0) {
        fprintf(stderr, "Error: PCAP is empty or contains no IPv4 packets.\n");
        return -1;
    }
    return 0;
}
