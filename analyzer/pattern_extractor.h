#ifndef PATTERN_EXTRACTOR_H
#define PATTERN_EXTRACTOR_H

#include "rules_parser.h"
#include "protocol_detector.h"

#define MAX_CONTENT 2048
#define MAX_PREFIX  128

typedef struct {
    char    content[MAX_CONTENT];  /* raw Suricata content value */
    char    prefix[MAX_PREFIX];    /* Hyperscan regex prefix (raw regex, not Suricata notation) */
    int     nocase;
    int     offset;     /* -1 = not set */
    int     depth;      /* -1 = not set */
    int     startswith;
} Pattern;

/*
 * Reasons a rule can be discarded.
 * FILTER_OK means accepted; all others mean discarded.
 * Order: stateful first, then proto, then content checks.
 */
typedef enum {
    FILTER_OK = 0,
    FILTER_STATEFUL,              /* uses flowbits/threshold/detection_filter/... */
    FILTER_PROTO_MISMATCH,        /* rule protocol not in detected traffic         */
    FILTER_NO_CONTENT,            /* rule has no content: keyword at all           */
    FILTER_MULTI_CONTENT_NO_FP,   /* multiple content: but no fast_pattern set     */
    FILTER_CONTENT_EXTRACT_FAIL,  /* longest content extraction failed             */
    FILTER_EMPTY_CONTENT,         /* extracted content string is empty             */
    FILTER_TOO_SHORT_SINGLE,      /* single content ≤3 decoded bytes: not selective */
    FILTER_GENERIC_CONTENT,       /* all contents are generic HTTP tokens (GET/POST/...) */
    FILTER_GENERIC_URI_PATTERN,   /* best content is a generic URL path or header value   */
    FILTER_REASON_COUNT
} FilterReason;

/* Aggregated discard counters, one slot per FilterReason. */
typedef struct {
    long counts[FILTER_REASON_COUNT];
    long upgraded;  /* rules where a longer content replaced a too-short fast_pattern */
} FilterStats;

/*
 * Returns FILTER_OK and fills pat if the rule should be kept.
 * Otherwise returns the discard reason (pat is undefined).
 * stats may be NULL.
 *
 * Single-content rules with no explicit fast_pattern are accepted:
 * Suricata implicitly uses the only content as the fast pattern.
 */
FilterReason extract_pattern(SuricataRule *r, const ProtoSelection *sel,
                             Pattern *pat, FilterStats *stats);

/* Returns 1 if the rule's protocol matches any selected protocol. */
int rule_proto_matches(const SuricataRule *r, const ProtoSelection *sel);

/* Print aggregated filter statistics. */
void print_filter_stats(const FilterStats *stats, int total_rules);

#endif
