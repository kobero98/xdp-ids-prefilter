#include "rules_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *stateful_keywords[] = {
    "threshold", "detection_filter", "limit", "flowbits", "flowint", NULL
};

static int has_stateful(const char *line) {
    for (int i = 0; stateful_keywords[i]; i++)
        if (strstr(line, stateful_keywords[i])) return 1;
    return 0;
}

/* Extract the protocol field: alert <proto> ... */
static void extract_proto(const char *line, char *out, int outsz) {
    out[0] = '\0';
    const char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    /* skip action word */
    while (*p && !isspace((unsigned char)*p)) p++;
    while (*p &&  isspace((unsigned char)*p)) p++;
    int i = 0;
    while (*p && !isspace((unsigned char)*p) && i < outsz - 1)
        out[i++] = (char)tolower((unsigned char)*p++);
    out[i] = '\0';
}

int rules_load(const char *filename, RuleSet *rs) {
    rs->rules = calloc(MAX_RULES, sizeof(SuricataRule));
    if (!rs->rules) { perror("calloc"); return -1; }
    rs->count = 0;

    FILE *f = fopen(filename, "r");
    if (!f) { perror(filename); return -1; }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* skip comments and empty lines */
        const char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;

        if (rs->count >= MAX_RULES) {
            fprintf(stderr, "Warning: MAX_RULES reached, truncating.\n");
            break;
        }

        SuricataRule *r = &rs->rules[rs->count++];
        r->raw = strdup(line);
        extract_proto(line, r->proto, sizeof(r->proto));
        r->has_fast_pattern = (strstr(line, "fast_pattern") != NULL);
        r->discard = 0;
    }
    fclose(f);
    return 0;
}

void rules_free(RuleSet *rs) {
    for (int i = 0; i < rs->count; i++)
        free(rs->rules[i].raw);
    free(rs->rules);
    rs->rules  = NULL;
    rs->count  = 0;
}
