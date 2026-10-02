#ifndef PCAP_ANALYZER_H
#define PCAP_ANALYZER_H

#include <stdint.h>

#define MAX_FLOWS 65536

/* Application-layer protocol kinds detected from the PCAP */
typedef enum {
    PROTO_HTTP = 0,
    PROTO_TLS,
    PROTO_DNS,
    PROTO_QUIC,
    PROTO_FTP,
    PROTO_SMB,
    PROTO_MDNS,
    PROTO_DCERPC,
    PROTO_DHCP,
    PROTO_SSH,
    PROTO_SMTP,
    PROTO_IMAP,
    PROTO_POP3,
    PROTO_MODBUS,
    PROTO_DNP3,
    PROTO_NFS,
    PROTO_IKE,
    PROTO_KRB5,
    PROTO_BITTORRENT_DHT,
    PROTO_MQTT,
    PROTO_NTP,
    PROTO_RFB,
    PROTO_RDP,
    PROTO_SNMP,
    PROTO_TFTP,
    PROTO_TELNET,
    PROTO_PGSQL,
    PROTO_OTHER,
    PROTO_COUNT
} ProtoKind;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} Flow;

typedef struct {
    long total_ip;
    long tcp_flows;
    long udp_packets;
    long proto_packets[PROTO_COUNT];
    long total_app_packets;
} PcapStats;

int pcap_analyze(const char *filename, PcapStats *stats);

#endif
