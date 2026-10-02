#ifndef PROTOCOL_DETECTOR_H
#define PROTOCOL_DETECTOR_H

#include "pcap_analyzer.h"

typedef struct {
    ProtoKind kind;
    double    pct;
} ProtoStat;

typedef struct {
    ProtoStat protos[PROTO_COUNT];
    int       selected[PROTO_COUNT];
    int       n_selected;
} ProtoSelection;

void detect_protocols(const PcapStats *s, ProtoSelection *sel);
void print_proto_stats(const ProtoSelection *sel);
int  proto_default_port(ProtoKind k);
void write_proto_meta(const ProtoSelection *sel, const char *pcap_path);

#endif
