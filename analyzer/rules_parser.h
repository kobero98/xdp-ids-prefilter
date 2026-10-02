#ifndef RULES_PARSER_H
#define RULES_PARSER_H

#define MAX_RULES       200000
#define MAX_LINE        8192
#define MAX_RULE_PROTO  32

typedef struct {
    char  *raw;        /* full original line (heap) */
    char   proto[MAX_RULE_PROTO];
    int    has_fast_pattern;
    int    discard;    /* 1 = filtered out */
} SuricataRule;

typedef struct {
    SuricataRule *rules;
    int           count;
} RuleSet;

int  rules_load(const char *filename, RuleSet *rs);
void rules_free(RuleSet *rs);

#endif
