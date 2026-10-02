#include "hyperscan_formatter.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Characters that must be escaped inside a /regex/ */
static const char *REGEX_SPECIAL = ".*+?()[]{}|^$\\/";

/* Convert Suricata content value to Hyperscan regex string.
   Handles ASCII text and binary |HH HH| sequences.
   out must be at least outsz bytes. Returns 0 ok, -1 error. */
static int content_to_regex(const char *content, char *out, int outsz) {
    const char *p = content;
    int oi = 0;

#define PUSH(c) do { if (oi >= outsz - 1) return -1; out[oi++] = (c); } while(0)
#define PUSHS(s) do { for (const char *_s=(s); *_s; _s++) { PUSH(*_s); } } while(0)

    while (*p) {
        if (*p == '|') {
            /* binary section: |HH HH ...| */
            p++;
            while (*p && *p != '|') {
                while (*p == ' ') p++;
                if (*p == '|') break;
                /* read two hex digits */
                if (!isxdigit((unsigned char)p[0]) ||
                    !isxdigit((unsigned char)p[1])) { p++; continue; }
                char hex[5];
                snprintf(hex, sizeof(hex), "\\x%c%c", p[0], p[1]);
                PUSHS(hex);
                p += 2;
            }
            if (*p == '|') p++;
        } else {
            /* check if this char needs escaping */
            if (strchr(REGEX_SPECIAL, *p)) PUSH('\\');
            PUSH(*p);
            p++;
        }
    }
    out[oi] = '\0';
    return (oi == 0) ? -1 : 0;
}

/*
 * Returns the decoded byte length of a Suricata content value.
 *
 * Suricata uses depth:N with offset:O to mean a window of N bytes
 * starting at byte O (absolute depth = O + N). Hyperscan min_offset
 * and max_offset are END positions of a match, so we need the content
 * length to compute them correctly.
 */
static int content_byte_len(const char *content) {
    const char *p = content;
    int len = 0;
    while (*p) {
        if (*p == '|') {
            p++;
            while (*p && *p != '|') {
                while (*p == ' ') p++;
                if (*p == '|') break;
                if (isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) {
                    len++;
                    p += 2;
                } else {
                    p++;
                }
            }
            if (*p == '|') p++;
        } else {
            len++;
            p++;
        }
    }
    return len;
}

int hs_write_pattern(FILE *fp, int id, const Pattern *pat) {
    char regex[MAX_CONTENT * 4];
    if (content_to_regex(pat->content, regex, sizeof(regex)) != 0)
        return -1;

    int clen       = content_byte_len(pat->content);
    int eff_offset = (pat->offset >= 0) ? pat->offset : 0;

    /* flags */
    char flags[8] = "";
    if (pat->nocase) strcpy(flags, "i");

    /* --- compute Hyperscan extended parameters ---
     *
     * Suricata semantics:
     *   offset:O  → pattern starts at byte >= O
     *   depth:D   → window of D bytes from offset (absolute end = O + D)
     *
     * Hyperscan semantics (end-position of match):
     *   min_offset = O + content_length   (match ends at or after O + clen)
     *   max_offset = O + D                (match ends at or before O + D)
     *
     * startswith is shorthand for offset:0; depth:clen; so both
     * min_offset and max_offset equal clen.
     */
    char ext[128] = "";
    int  has_ext  = 0;
    char tmp[64];

    if (pat->startswith) {
        snprintf(tmp, sizeof(tmp), "min_offset=%d,max_offset=%d", clen, clen);
        strncat(ext, tmp, sizeof(ext) - strlen(ext) - 1);
        has_ext = 1;
    } else {
        if (pat->offset >= 0) {
            snprintf(tmp, sizeof(tmp), "min_offset=%d", pat->offset + clen);
            strncat(ext, tmp, sizeof(ext) - strlen(ext) - 1);
            has_ext = 1;
        }

        if (pat->depth >= 0) {
            if (has_ext) strncat(ext, ",", sizeof(ext) - strlen(ext) - 1);
            snprintf(tmp, sizeof(tmp), "max_offset=%d", eff_offset + pat->depth);
            strncat(ext, tmp, sizeof(ext) - strlen(ext) - 1);
            has_ext = 1;
        }
    }

    if (has_ext)
        fprintf(fp, "%d:/%s%s/%s{%s}\n", id, pat->prefix, regex, flags, ext);
    else
        fprintf(fp, "%d:/%s%s/%s\n", id, pat->prefix, regex, flags);

    return 0;
}
