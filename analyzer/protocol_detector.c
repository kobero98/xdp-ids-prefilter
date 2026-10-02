#include "protocol_detector.h"
#include <stdio.h>
#include <string.h>

static const char *proto_name(ProtoKind k) {
    switch (k) {
        case PROTO_HTTP:           return "HTTP";
        case PROTO_TLS:            return "TLS/HTTPS";
        case PROTO_DNS:            return "DNS";
        case PROTO_QUIC:           return "QUIC";
        case PROTO_FTP:            return "FTP";
        case PROTO_SMB:            return "SMB";
        case PROTO_MDNS:           return "mDNS";
        case PROTO_DCERPC:         return "DCERPC";
        case PROTO_DHCP:           return "DHCP";
        case PROTO_SSH:            return "SSH";
        case PROTO_SMTP:           return "SMTP";
        case PROTO_IMAP:           return "IMAP";
        case PROTO_POP3:           return "POP3";
        case PROTO_MODBUS:         return "Modbus";
        case PROTO_DNP3:           return "DNP3";
        case PROTO_NFS:            return "NFS";
        case PROTO_IKE:            return "IKE";
        case PROTO_KRB5:           return "Kerberos5";
        case PROTO_BITTORRENT_DHT: return "BitTorrent-DHT";
        case PROTO_MQTT:           return "MQTT";
        case PROTO_NTP:            return "NTP";
        case PROTO_RFB:            return "RFB/VNC";
        case PROTO_RDP:            return "RDP";
        case PROTO_SNMP:           return "SNMP";
        case PROTO_TFTP:           return "TFTP";
        case PROTO_TELNET:         return "Telnet";
        case PROTO_PGSQL:          return "PostgreSQL";
        default:                   return "OTHER";
    }
}

void detect_protocols(const PcapStats *s, ProtoSelection *sel) {
    memset(sel, 0, sizeof(*sel));
    long total = s->total_app_packets;
    if (total == 0) total = 1;

    for (int k = 0; k < PROTO_COUNT; k++) {
        sel->protos[k].kind = (ProtoKind)k;
        sel->protos[k].pct  = 100.0 * s->proto_packets[k] / total;
    }

    /* insertion sort descending by percentage */
    int order[PROTO_COUNT];
    for (int i = 0; i < PROTO_COUNT; i++) order[i] = i;
    for (int i = 1; i < PROTO_COUNT; i++)
        for (int j = i; j > 0 && sel->protos[order[j]].pct > sel->protos[order[j-1]].pct; j--) {
            int tmp = order[j]; order[j] = order[j-1]; order[j-1] = tmp;
        }

    double cumul = 0.0;
    for (int i = 0; i < PROTO_COUNT; i++) {
        int idx = order[i];
        if (sel->protos[idx].pct == 0.0) break;
        /* PROTO_OTHER is a catch-all bucket, not a real application protocol.
         * Selecting it would pull in every tcp/udp/ip rule, defeating the
         * whole purpose of the protocol-targeted pre-filter. */
        if (idx == PROTO_OTHER) continue;
        sel->selected[idx] = 1;
        sel->n_selected++;
        cumul += sel->protos[idx].pct;
        if (cumul >= 30.0) break;
    }
}

int proto_default_port(ProtoKind k) {
    switch (k) {
        case PROTO_HTTP:            return 80;
        case PROTO_TLS:             return 443;
        case PROTO_DNS:             return 53;
        case PROTO_QUIC:            return 443;
        case PROTO_FTP:             return 21;
        case PROTO_SMB:             return 445;
        case PROTO_MDNS:            return 5353;
        case PROTO_DCERPC:          return 135;
        case PROTO_DHCP:            return 67;
        case PROTO_SSH:             return 22;
        case PROTO_SMTP:            return 25;
        case PROTO_IMAP:            return 143;
        case PROTO_POP3:            return 110;
        case PROTO_MODBUS:          return 502;
        case PROTO_DNP3:            return 20000;
        case PROTO_NFS:             return 2049;
        case PROTO_IKE:             return 500;
        case PROTO_KRB5:            return 88;
        case PROTO_BITTORRENT_DHT:  return 6881;
        case PROTO_MQTT:            return 1883;
        case PROTO_NTP:             return 123;
        case PROTO_RFB:             return 5900;
        case PROTO_RDP:             return 3389;
        case PROTO_SNMP:            return 161;
        case PROTO_TFTP:            return 69;
        case PROTO_TELNET:          return 23;
        case PROTO_PGSQL:           return 5432;
        default:                    return 0;
    }
}

void write_proto_meta(const ProtoSelection *sel, const char *pcap_path) {
    /* Find primary port: if all selected protocols share one port, use it;
     * if they differ (e.g. HTTP=80 + DNS=53) fall back to 0 (all ports). */
    int first_port = -1;
    int port = 0;
    int all_same = 1;

    for (int k = 0; k < PROTO_COUNT; k++) {
        if (!sel->selected[k]) continue;
        int p = proto_default_port((ProtoKind)k);
        if (first_port < 0) { first_port = p; port = p; }
        else if (p != first_port) { all_same = 0; }
    }
    if (!all_same) port = 0;

    FILE *f = fopen("proto_meta.txt", "w");
    if (!f) { perror("proto_meta.txt"); return; }

    fprintf(f, "# Generato da analyzer — usato da run_empirical.sh\n");
    fprintf(f, "PCAP: %s\n", pcap_path ? pcap_path : "");
    fprintf(f, "PROTOS:");
    for (int k = 0; k < PROTO_COUNT; k++)
        if (sel->selected[k]) fprintf(f, " %s", proto_name((ProtoKind)k));
    fprintf(f, "\nPORT: %d\n", port);
    fclose(f);
    printf("    proto_meta.txt scritto  (PORT=%d)\n", port);
}

void print_proto_stats(const ProtoSelection *sel) {
    printf("\n=== Protocol Distribution ===\n");
    for (int i = 0; i < PROTO_COUNT; i++) {
        if (sel->protos[i].pct > 0.0)
            printf("  %-16s %.2f%%\n",
                   proto_name(sel->protos[i].kind), sel->protos[i].pct);
    }
    printf("\nSelected protocols (>= 50%% coverage):\n");
    for (int i = 0; i < PROTO_COUNT; i++)
        if (sel->selected[i])
            printf("  [*] %-16s %.2f%%\n",
                   proto_name(sel->protos[i].kind), sel->protos[i].pct);
}
