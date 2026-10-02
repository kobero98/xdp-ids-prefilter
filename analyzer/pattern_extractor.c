#include "pattern_extractor.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>

/*
 * For each ProtoKind detected in the PCAP, this table lists all the
 * Suricata rule protocol keywords that should be considered a match.
 * The inner array is NULL-terminated; unused trailing slots are NULL.
 */
#define MAX_SURI_NAMES 10

static const char *proto_suri_map[PROTO_COUNT][MAX_SURI_NAMES] = {
    [PROTO_HTTP]           = {"http", "http1", "http2", "websocket", "tcp", "ip", NULL},
    [PROTO_TLS]            = {"tls", "tcp", "ip", NULL},
    [PROTO_DNS]            = {"dns", "udp", "ip", NULL},
    [PROTO_QUIC]           = {"quic", "udp", "ip", NULL},
    [PROTO_FTP]            = {"ftp", "ftp-data", "tcp", "ip", NULL},
    [PROTO_SMB]            = {"smb", "tcp", "ip", NULL},
    [PROTO_MDNS]           = {"dns", "udp", "ip", NULL},
    [PROTO_DCERPC]         = {"dcerpc", "tcp", "ip", NULL},
    [PROTO_DHCP]           = {"dhcp", "udp", "ip", NULL},
    [PROTO_SSH]            = {"ssh", "tcp", "ip", NULL},
    [PROTO_SMTP]           = {"smtp", "tcp", "ip", NULL},
    [PROTO_IMAP]           = {"imap", "tcp", "ip", NULL},
    [PROTO_POP3]           = {"tcp", "ip", NULL},
    [PROTO_MODBUS]         = {"modbus", "tcp", "ip", NULL},
    [PROTO_DNP3]           = {"dnp3", "tcp", "ip", NULL},
    [PROTO_NFS]            = {"nfs", "tcp", "ip", NULL},
    [PROTO_IKE]            = {"ike", "ikev2", "udp", "ip", NULL},
    [PROTO_KRB5]           = {"krb5", "tcp", "udp", "ip", NULL},
    [PROTO_BITTORRENT_DHT] = {"bittorrent-dht", "udp", "ip", NULL},
    [PROTO_MQTT]           = {"mqtt", "tcp", "ip", NULL},
    [PROTO_NTP]            = {"ntp", "udp", "ip", NULL},
    [PROTO_RFB]            = {"rfb", "tcp", "ip", NULL},
    [PROTO_RDP]            = {"rdp", "tcp", "ip", NULL},
    [PROTO_SNMP]           = {"snmp", "udp", "ip", NULL},
    [PROTO_TFTP]           = {"tftp", "udp", "ip", NULL},
    [PROTO_TELNET]         = {"tcp", "ip", NULL},
    [PROTO_PGSQL]          = {"pgsql", "tcp", "ip", NULL},
    [PROTO_OTHER]          = {"tcp", "udp", "ip", NULL},
};

int rule_proto_matches(const SuricataRule *r, const ProtoSelection *sel) {
    for (int k = 0; k < PROTO_COUNT; k++) {
        if (!sel->selected[k]) continue;
        for (int n = 0; n < MAX_SURI_NAMES && proto_suri_map[k][n]; n++) {
            if (strcmp(r->proto, proto_suri_map[k][n]) == 0) return 1;
        }
    }
    return 0;
}

/*
 * Decode a Suricata content string into raw bytes.
 * Returns the number of bytes written.
 */
static int content_decode(const char *content, unsigned char *out, int outsz) {
    const char *p = content;
    int len = 0;
    while (*p && len < outsz - 1) {
        if (*p == '|') {
            p++;
            while (*p && *p != '|') {
                while (*p == ' ') p++;
                if (*p == '|') break;
                if (isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) {
                    unsigned int byte;
                    sscanf(p, "%2x", &byte);
                    out[len++] = (unsigned char)byte;
                    p += 2;
                } else { p++; }
            }
            if (*p == '|') p++;
        } else {
            out[len++] = (unsigned char)*p++;
        }
    }
    out[len] = '\0';
    return len;
}

/*
 * Re-encode raw bytes as a Suricata content string.
 * Printable ASCII (except special chars) is kept as-is; others use |HH| notation.
 */
static void content_encode(const unsigned char *bytes, int len, char *out, int outsz) {
    int oi = 0;
    for (int i = 0; i < len && oi < outsz - 6; i++) {
        unsigned char b = bytes[i];
        if (b >= 32 && b <= 126 &&
            b != '"' && b != ';' && b != ':' && b != '|' && b != '\\') {
            out[oi++] = (char)b;
        } else {
            out[oi++] = '|';
            oi += snprintf(out + oi, outsz - oi, "%02X", b);
            out[oi++] = '|';
        }
    }
    out[oi] = '\0';
}

/* Count how many valid content:"..." fields are in the rule. */
static int count_contents(const char *line) {
    int count = 0;
    const char *p = line;
    while ((p = strstr(p, "content:")) != NULL) {
        p += 8;
        while (*p == ' ') p++;
        if (*p == '"') count++;
    }
    return count;
}

/*
 * Collect modifiers (nocase, startswith, offset, depth) from a region
 * of the rule that follows a content:" field.
 */
static void collect_modifiers(const char *region,
                               int *nocase, int *offset, int *depth, int *startswith)
{
    if (strstr(region, "nocase"))     *nocase = 1;
    if (strstr(region, "startswith")) *startswith = 1;

    const char *p = strstr(region, "offset:");
    if (p) { p += 7; *offset = atoi(p); }

    p = strstr(region, "depth:");
    if (p) { p += 6; *depth = atoi(p); }
}

/*
 * Suricata sticky buffer keywords: when one of these precedes a content:",
 * offset/depth/startswith are relative to that application-layer field, not
 * the raw packet payload that XDP scans.  We must NOT emit Hyperscan
 * min_offset/max_offset in that case.
 */
static const char *STICKY_BUFS[] = {
    "http.uri", "http.user_agent", "http.host", "http.server",
    "http.stat_code", "http.method", "http.accept", "http.accept_enc",
    "http.accept_lang", "http.connection", "http.content_type",
    "http.content_len", "http.cookie", "http.header", "http.raw_header",
    "http.header_names", "http.request_header", "http.response_header",
    "http.request_body", "http.response_body", "http.request_line",
    "http.response_line", "http.start", "http.referer",
    "http.location", "http.protocol",
    "file.data", "dns.query", "dns.answer",
    "tls.sni", "tls.cert_subject", "tls.cert_issuer",
    "tls.cert_serial", "tls.fingerprint",
    "ssh.protoversion", "ssh.softwareversion",
    "smtp.rcpt_to", "smtp.mail_from", "smtp.helo",
    "pkthdr",
    NULL
};

/*
 * Mapping from Suricata sticky buffer keyword → Hyperscan regex prefix and
 * fallback-suppression flag.
 *
 * hs_prefix  — regex text prepended to the content pattern (already in Hyperscan
 *              regex notation: \x0d\x0a = CRLF, \/ = literal slash, etc.).
 *              NULL means "no prefix, leave content as-is".
 *              ""   means "no prefix text but use startswith constraint" (http.method).
 *
 * no_fallback — when 1, the content is kept as-is even if it is shorter than
 *              MIN_PATTERN_BYTES.  Used for body buffers: falling back to the
 *              longest content in the rule would replace a specific body string
 *              (e.g. "ic=") with a generic method keyword like "POST", which
 *              would match ALL POST requests instead of only the attack traffic.
 *
 * Body buffers (http.request_body, http.response_body) have hs_prefix=NULL
 * because the content can appear ANYWHERE in the body, not just at the first
 * byte after the \r\n\r\n separator.  A \r\n\r\n anchor would cause false
 * negatives whenever the malicious content is not the very first thing in the
 * body (e.g. "POST /x HTTP/1.1\r\n…\r\n\r\nparam=ok&evil=<content>").
 *
 * HTTP method prefix for http.uri is only effective when the content begins
 * with '/' (URI path prefix).  For mid-URI patterns like "id=", "cmd=", the
 * method and the content are not adjacent in the raw payload, so the prefix
 * would never match — those cases are handled separately in extract_pattern().
 */
static const struct {
    const char *kw;
    const char *hs_prefix;
    int         no_fallback;
} STICKY_PREFIX_MAP[] = {
    /* HTTP request line — URI path patterns start with '/' right after method */
    { "http.uri",          "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) ", 0 },
    /* HTTP request/response headers — always \r\n<Name>: <value> */
    { "http.user_agent",   "\\x0d\\x0aUser-Agent: ",       0 },
    { "http.host",         "\\x0d\\x0aHost: ",             0 },
    { "http.server",       "\\x0d\\x0aServer: ",           0 },
    { "http.referer",      "\\x0d\\x0aReferer: ",          0 },
    { "http.cookie",       "\\x0d\\x0aCookie: ",           0 },
    { "http.location",     "\\x0d\\x0aLocation: ",         0 },
    { "http.connection",   "\\x0d\\x0aConnection: ",       0 },
    { "http.content_type", "\\x0d\\x0aContent-Type: ",     0 },
    { "http.accept",       "\\x0d\\x0aAccept: ",           0 },
    { "http.accept_enc",   "\\x0d\\x0aAccept-Encoding: ",  0 },
    { "http.accept_lang",  "\\x0d\\x0aAccept-Language: ",  0 },
    { "http.content_len",  "\\x0d\\x0aContent-Length: ",   0 },
    /* HTTP status line: HTTP/1.0 NNN or HTTP/1.1 NNN */
    { "http.stat_code",    "HTTP\\/1\\.[01] ",              0 },
    /* Body: content can appear anywhere after the header separator, not just
     * at position 0 of the body — no prefix.  Fallback suppressed to avoid
     * replacing specific body content with generic method keywords. */
    { "http.request_body",  NULL, 1 },
    { "http.response_body", NULL, 1 },
    /* Method at position 0: restore startswith, no text prefix */
    { "http.method",        "",   0 },
    { NULL, NULL, 0 }
};

/*
 * Returns the Hyperscan regex prefix string for the sticky buffer keyword
 * that most recently (rightmost in the rule text) precedes content_pos.
 * Returns NULL if no sticky buffer was found or if no prefix is defined for it.
 *
 * Two-step process:
 *  1. Scan ALL known sticky buffer keywords (STICKY_BUFS) to find the one
 *     closest to content_pos — this is the field the content is matched against.
 *  2. Look that keyword up in STICKY_PREFIX_MAP.  If there is a prefix, return
 *     it.  If not (e.g. file.data, tls.sni), return NULL so no prefix is added.
 *
 * Step 1 uses STICKY_BUFS (not STICKY_PREFIX_MAP) so that sticky buffers
 * without a defined prefix (e.g. file.data appearing between http.stat_code
 * and a fast_pattern content) correctly block a more-distant entry from the
 * map being mistakenly applied.
 */
/*
 * Returns the Hyperscan regex prefix for the sticky buffer keyword closest
 * (rightmost) to content_pos.  Sets *no_fallback_out when the matching map
 * entry requests fallback suppression (body buffers).
 *
 * Returns NULL when:
 *  - no sticky buffer appears before content_pos, or
 *  - the closest sticky buffer is not in STICKY_PREFIX_MAP, or
 *  - the closest sticky buffer IS in the map but has hs_prefix == NULL
 *    (body buffers — *no_fallback_out will still be set in this case).
 */
static const char *get_hs_prefix_before(const char *rule_start,
                                         const char *content_pos,
                                         int *no_fallback_out)
{
    if (no_fallback_out) *no_fallback_out = 0;

    /* Step 1: find the rightmost sticky buffer keyword of any kind. */
    const char *best_pos = NULL;
    const char *best_kw  = NULL;

    for (int i = 0; STICKY_BUFS[i]; i++) {
        const char *kw   = STICKY_BUFS[i];
        size_t      klen = strlen(kw);
        const char *p    = rule_start;
        const char *last = NULL;

        while (p < content_pos) {
            p = strstr(p, kw);
            if (!p || p >= content_pos) break;
            char after = p[klen];
            if (after == ';' || after == ' ' || after == '\t' || after == '\0')
                last = p;
            p += klen;
        }

        if (last && (!best_pos || last > best_pos)) {
            best_pos = last;
            best_kw  = kw;
        }
    }

    if (!best_kw) return NULL;

    /* Step 2: look up the prefix (and no_fallback flag) for that keyword. */
    for (int i = 0; STICKY_PREFIX_MAP[i].kw; i++) {
        if (strcmp(best_kw, STICKY_PREFIX_MAP[i].kw) == 0) {
            if (no_fallback_out)
                *no_fallback_out = STICKY_PREFIX_MAP[i].no_fallback;
            return STICKY_PREFIX_MAP[i].hs_prefix;
        }
    }

    return NULL;
}

/* Returns 1 if any sticky buffer keyword appears in [rule_start, content_pos).
 * When true, startswith/offset/depth must not be translated to Hyperscan
 * min/max_offset because those values are relative to the field, not the
 * raw packet payload. */
static int sticky_before_content(const char *rule_start, const char *content_pos)
{
    for (int i = 0; STICKY_BUFS[i]; i++) {
        size_t klen = strlen(STICKY_BUFS[i]);
        const char *p = rule_start;
        while (p < content_pos) {
            p = strstr(p, STICKY_BUFS[i]);
            if (!p || p >= content_pos) break;
            /* word-boundary: must be followed by ';', space, or tab */
            char after = p[klen];
            if (after == ';' || after == ' ' || after == '\t' || after == '\0')
                return 1;
            p += klen;
        }
    }
    return 0;
}

/*
 * Extract the content that has the fast_pattern modifier.
 * Scans all content:"..." fields and picks the one whose region
 * (up to the next content:" or end of rule) contains "fast_pattern".
 */
static int find_fast_pattern_content(const char *line, char *out, int outsz,
                                     int *nocase, int *offset, int *depth,
                                     int *startswith, const char **pos_out)
{
    *nocase = 0; *offset = -1; *depth = -1; *startswith = 0;
    if (pos_out) *pos_out = NULL;

    const char *p = line;
    while ((p = strstr(p, "content:")) != NULL) {
        const char *content_start = p;
        p += 8;
        while (*p == ' ') p++;
        if (*p != '"') continue;
        p++;

        char buf[MAX_CONTENT];
        int bi = 0;
        while (*p && !(*p == '"' && *(p-1) != '\\') && bi < MAX_CONTENT - 1)
            buf[bi++] = *p++;
        buf[bi] = '\0';
        if (*p == '"') p++;

        const char *region_end = strstr(p, "content:");
        if (!region_end) region_end = line + strlen(line);

        const char *fp = strstr(p, "fast_pattern");
        if (!fp || fp >= region_end) {
            p = region_end;
            continue;
        }

        char region[MAX_CONTENT * 4];
        size_t rlen = (size_t)(region_end - content_start);
        if (rlen >= sizeof(region)) rlen = sizeof(region) - 1;
        strncpy(region, content_start, rlen);
        region[rlen] = '\0';

        collect_modifiers(region, nocase, offset, depth, startswith);

        /* startswith/offset/depth are relative to the application-layer field,
         * not the raw payload XDP scans — clear them when a sticky buffer
         * keyword precedes this content keyword. */
        if (sticky_before_content(line, content_start)) {
            *startswith = 0;
            *offset     = -1;
            *depth      = -1;
        }

        /* Handle fast_pattern:chop notation — fast_pattern:N,M means use
         * only M bytes of the content starting at byte offset N.
         * Example: content:"aaaaaaaaabc"; fast_pattern:8,4; → uses "aabc" */
        if (fp[12] == ':') {
            int fp_off = 0, fp_len = 0;
            const char *cp = fp + 13;
            fp_off = atoi(cp);
            const char *comma = strchr(cp, ',');
            if (comma && fp_off >= 0) {
                fp_len = atoi(comma + 1);
                if (fp_len > 0) {
                    unsigned char decoded[MAX_CONTENT];
                    int dlen = content_decode(buf, decoded, sizeof(decoded));
                    if (fp_off + fp_len <= dlen) {
                        content_encode(decoded + fp_off, fp_len, out, outsz);
                        return 1;
                    }
                }
            }
        }

        strncpy(out, buf, outsz - 1);
        out[outsz - 1] = '\0';
        if (pos_out) *pos_out = content_start;
        return 1;
    }
    return 0;
}

/*
 * Extract the single content:"..." field from a rule that has exactly one.
 * Suricata implicitly uses the only content as the fast pattern.
 */
static int find_single_content(const char *line, char *out, int outsz,
                               int *nocase, int *offset, int *depth, int *startswith,
                               const char **pos_out)
{
    *nocase = 0; *offset = -1; *depth = -1; *startswith = 0;
    if (pos_out) *pos_out = NULL;

    const char *p = strstr(line, "content:");
    if (!p) return 0;

    const char *content_start = p;
    p += 8;
    while (*p == ' ') p++;
    if (*p != '"') return 0;
    p++;

    char buf[MAX_CONTENT];
    int bi = 0;
    while (*p && !(*p == '"' && *(p-1) != '\\') && bi < MAX_CONTENT - 1)
        buf[bi++] = *p++;
    buf[bi] = '\0';
    if (*p == '"') p++;

    /* region: from content_start to next content: (even negated), or end of rule.
     * Must NOT extend past other content keywords to avoid capturing their
     * modifiers (e.g. depth: belonging to content:!"..." entries). */
    const char *region_end = strstr(p, "content:");
    if (!region_end) region_end = line + strlen(line);
    char region[MAX_CONTENT * 4];
    size_t rlen = (size_t)(region_end - content_start);
    if (rlen >= sizeof(region)) rlen = sizeof(region) - 1;
    strncpy(region, content_start, rlen);
    region[rlen] = '\0';

    collect_modifiers(region, nocase, offset, depth, startswith);

    /* Same sticky-buffer guard as in find_fast_pattern_content. */
    if (sticky_before_content(line, content_start)) {
        *startswith = 0;
        *offset     = -1;
        *depth      = -1;
    }

    strncpy(out, buf, outsz - 1);
    out[outsz - 1] = '\0';
    if (pos_out) *pos_out = content_start;
    return 1;
}

/*
 * Tokens so generic that they match vast amounts of unrelated traffic.
 * Using any of these alone as a Hyperscan pre-filter gives XDP near-zero
 * filtering power.  All entries are compared case-insensitively against the
 * FULL decoded content string (exact length match).
 *
 * HTTP methods: appear in every request of that type.
 * SQL single keywords: SELECT/INSERT/UPDATE/FROM/UNION appear in legitimate
 *   HTML (articles, tutorials, web apps) and cannot distinguish attacks from
 *   normal DB-backed sites.  Compound expressions like "UNION SELECT" or
 *   "OR 1=1" are in ATTACK_KEYWORDS and are scored highly.
 */
static const char *GENERIC_CONTENT_BLACKLIST[] = {
    /* HTTP methods */
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
    "PATCH", "CONNECT", "TRACE",
    /* Single SQL keywords — too generic on their own */
    "SELECT", "INSERT", "UPDATE", "FROM", "UNION", "INTO",
    "WHERE", "DROP", "EXEC", "ASCII(",
    NULL
};

static int content_is_generic(const unsigned char *decoded, int dlen)
{
    for (int i = 0; GENERIC_CONTENT_BLACKLIST[i]; i++) {
        const char *bl   = GENERIC_CONTENT_BLACKLIST[i];
        int         blen = (int)strlen(bl);
        if (dlen != blen) continue;
        int match = 1;
        for (int j = 0; j < blen; j++) {
            if (toupper((unsigned char)decoded[j]) != (unsigned char)bl[j])
                { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * SPECIFICITY SCORING
 * Replaces "longest wins" with a score that reflects how selective a content
 * keyword is as a Hyperscan pre-filter.  Higher score = fewer false positives.
 * Negative score = content is too generic and should be rejected.
 * ------------------------------------------------------------------------- */

/* Known attack payload strings.  A content that contains any of these is
 * very unlikely to appear in legitimate traffic and scores highest. */
/*
 * Only COMPOUND or highly-specific attack strings go here.
 * Single SQL keywords like SELECT, INSERT, UPDATE are intentionally excluded:
 * they appear in legitimate HTTP responses (blog posts, JS code, etc.) and
 * would promote hundreds of duplicate patterns that offer no precision gain.
 * Compound expressions like "UNION SELECT" or "OR 1=1" cannot appear in
 * legitimate traffic and are kept.
 */
static const char *ATTACK_KEYWORDS[] = {
    /* SQL injection — compound expressions only */
    "UNION SELECT", "UNION ALL SELECT",
    "OR 1=1", "OR '1'='1", "' OR '", "AND 1=1", "' AND '",
    "xp_cmdshell", "information_schema", "LOAD_FILE(",
    "INTO OUTFILE", "BENCHMARK(", "WAITFOR DELAY",
    "'; DROP TABLE", "1; DROP TABLE",
    /* XSS */
    "<script", "javascript:", "vbscript:", "onerror=", "onload=",
    "onclick=", "onmouseover=", "onfocus=",
    "document.cookie", "document.write",
    "<iframe", "<object ", "<embed ",
    /* Path traversal / LFI */
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "../etc/", "..\\windows\\", "../../../../",
    /* Command injection */
    "/bin/bash", "/bin/sh", "cmd.exe",
    /* PHP wrappers */
    "php://", "data://", "expect://",
    NULL
};

/* Case-insensitive substring search in raw bytes. */
static int str_icontains(const unsigned char *hay, int hlen, const char *needle)
{
    int nlen = (int)strlen(needle);
    if (nlen > hlen) return 0;
    for (int i = 0; i <= hlen - nlen; i++) {
        int ok = 1;
        for (int j = 0; j < nlen; j++) {
            if (toupper((unsigned char)hay[i+j]) != toupper((unsigned char)needle[j]))
                { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

static int contains_attack_keyword(const unsigned char *decoded, int dlen)
{
    for (int i = 0; ATTACK_KEYWORDS[i]; i++)
        if (str_icontains(decoded, dlen, ATTACK_KEYWORDS[i]))
            return 1;
    return 0;
}

/* UUID/CLSID: 8-4-4-4-12 hex chars with dashes — specific malware class id. */
static int looks_like_uuid(const unsigned char *decoded, int dlen)
{
    if (dlen < 36) return 0;
    static const int seg[] = {8, 4, 4, 4, 12};
    int pos = 0;
    for (int s = 0; s < 5; s++) {
        for (int i = 0; i < seg[s]; i++) {
            if (pos >= dlen || !isxdigit(decoded[pos++])) return 0;
        }
        if (s < 4) {
            if (pos >= dlen || decoded[pos++] != '-') return 0;
        }
    }
    return (pos == 36);
}

/* Returns 1 if the RAW content string has >= min_seq consecutive hex-escaped
 * bytes (\xNN notation or Suricata |NN NN| pipe notation).
 * Binary protocol data and shellcode typically have long runs of such bytes. */
static int has_hex_escape_run(const char *raw_content, int min_seq)
{
    int run = 0;
    const char *p = raw_content;
    while (*p) {
        if (p[0] == '\\' && p[1] == 'x' &&
            isxdigit((unsigned char)p[2]) && isxdigit((unsigned char)p[3])) {
            if (++run >= min_seq) return 1;
            p += 4;
        } else if (p[0] == '|') {
            p++;
            int nb = 0;
            while (*p && *p != '|') {
                while (*p == ' ') p++;
                if (isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1]))
                    { nb++; p += 2; }
                else p++;
            }
            if (*p == '|') p++;
            if (nb >= min_seq) return 1;
            run = 0;
        } else {
            run = 0;
            p++;
        }
    }
    return 0;
}

/* Common HTTP header values that appear in virtually every request/response.
 * Matched as substring so that "\r\nContent-Type: application/json" also hits. */
static const char *GENERIC_HEADER_VALUES[] = {
    "application/x-www-form-urlencoded",
    "application/json",
    "text/html",
    "text/plain",
    "text/xml",
    "multipart/form-data",
    "gzip, deflate",
    "gzip,deflate",
    "keep-alive",
    "chunked",
    "no-cache",
    NULL
};

static int is_generic_header_value(const unsigned char *decoded, int dlen)
{
    for (int i = 0; GENERIC_HEADER_VALUES[i]; i++)
        if (str_icontains(decoded, dlen, GENERIC_HEADER_VALUES[i]))
            return 1;
    return 0;
}

/* A bare URL path: starts with '/', contains no '=' (no specific parameter
 * values).  These match ANY request to that URL path (e.g. /index.php?) and
 * give XDP zero filtering power.
 * MUST be called after contains_attack_keyword so that /etc/passwd is not
 * misclassified — attack keywords are checked first in content_specificity_score. */
static int is_generic_url_path(const unsigned char *decoded, int dlen)
{
    if (dlen < 1 || decoded[0] != '/') return 0;
    for (int i = 0; i < dlen; i++)
        if (decoded[i] == '=') return 0;   /* has a specific parameter value */
    return 1;
}

/*
 * Specificity score for a content keyword candidate.
 * Higher = better pre-filter.  Negative = too generic, reject unless no
 * better alternative exists.
 *
 * raw_content: the raw Suricata content string (for hex-escape run detection).
 */
static int content_specificity_score(const unsigned char *decoded, int dlen,
                                     const char *raw_content)
{
    /* Level 1: known attack payloads — highest priority */
    if (contains_attack_keyword(decoded, dlen))
        return 1000 + dlen;

    /* Level 2a: UUID/CLSID — specific malware class identifiers */
    if (looks_like_uuid(decoded, dlen))
        return 800 + dlen;

    /* Level 2b: binary protocol data / shellcode indicator */
    if (has_hex_escape_run(raw_content, 4))
        return 600 + dlen;

    /* Level 4: bare URL path without specific parameter values — penalize */
    if (is_generic_url_path(decoded, dlen))
        return -100;

    /* Level 5: generic HTTP header values (Content-Type: text/html, etc.) */
    if (is_generic_header_value(decoded, dlen))
        return -50;

    /* Default: decoded length as proxy for specificity */
    return dlen;
}

/*
 * Scan all non-negated content:"..." fields in the rule and return the longest
 * one that is NOT in the generic-content blacklist (HTTP methods, etc.).
 * If every non-negated content is generic, *skipped_generic_out is set to 1
 * so the caller can emit FILTER_GENERIC_CONTENT instead of FILTER_CONTENT_EXTRACT_FAIL.
 * Returns 1 on success, 0 if no usable content was found.
 */
/*
 * Find the best content keyword in the rule by specificity score.
 * Score replaces "longest wins": a short SQL injection payload beats a long
 * but generic URL path.
 *
 * *skipped_generic_out  — set if any HTTP method keyword (GET/POST/…) was seen
 * *all_scored_low_out   — set if content was found but every candidate scored
 *                         negative (generic URL paths, generic header values)
 */
static int find_longest_content(const char *line, char *out, int outsz, int *nocase,
                                const char **pos_out, int *skipped_generic_out,
                                int *all_scored_low_out)
{
    *nocase = 0;
    if (pos_out)             *pos_out             = NULL;
    if (skipped_generic_out) *skipped_generic_out = 0;
    if (all_scored_low_out)  *all_scored_low_out  = 0;

    int          best_score  = INT_MIN;
    char         best_buf[MAX_CONTENT] = {0};
    int          best_nc     = 0;
    const char  *best_pos    = NULL;
    int          saw_generic  = 0;
    int          saw_scorable = 0;  /* at least one non-method, non-negated content seen */

    const char *p = line;
    while ((p = strstr(p, "content:")) != NULL) {
        const char *content_start = p;
        p += 8;
        while (*p == ' ') p++;

        int negated = 0;
        if (*p == '!') { negated = 1; p++; }
        while (*p == ' ') p++;

        if (*p != '"') continue;
        p++;

        char buf[MAX_CONTENT];
        int bi = 0;
        while (*p && !(*p == '"' && *(p-1) != '\\') && bi < MAX_CONTENT - 1)
            buf[bi++] = *p++;
        buf[bi] = '\0';
        if (*p == '"') p++;

        if (negated) continue;

        unsigned char decoded[MAX_CONTENT];
        int dlen = content_decode(buf, decoded, sizeof(decoded));

        /* Skip generic HTTP method tokens (GET/POST/…). */
        if (content_is_generic(decoded, dlen)) {
            saw_generic = 1;
            continue;
        }

        saw_scorable = 1;
        int score = content_specificity_score(decoded, dlen, buf);

        if (score > best_score) {
            const char *region_end = strstr(p, "content:");
            if (!region_end) region_end = line + strlen(line);
            char region[MAX_CONTENT * 4];
            size_t rlen = (size_t)(region_end - content_start);
            if (rlen >= sizeof(region)) rlen = sizeof(region) - 1;
            strncpy(region, content_start, rlen);
            region[rlen] = '\0';

            best_score = score;
            best_pos   = content_start;
            strncpy(best_buf, buf, MAX_CONTENT - 1);
            best_buf[MAX_CONTENT - 1] = '\0';
            best_nc = (strstr(region, "nocase") != NULL) ? 1 : 0;
        }
    }

    if (skipped_generic_out) *skipped_generic_out = saw_generic;

    if (!saw_scorable) {
        /* Only method-blacklisted content or fully negated content. */
        return 0;
    }

    if (best_score < 0) {
        /* Content exists but every candidate is a generic URL path or header. */
        if (all_scored_low_out) *all_scored_low_out = 1;
        return 0;
    }

    strncpy(out, best_buf, outsz - 1);
    out[outsz - 1] = '\0';
    *nocase = best_nc;
    if (pos_out) *pos_out = best_pos;
    return 1;
}

static const char *stateful_kw[] = {
    "threshold", "detection_filter", "limit", "flowbits", "flowint", NULL
};

static int has_stateful(const char *line) {
    for (int i = 0; stateful_kw[i]; i++)
        if (strstr(line, stateful_kw[i])) return 1;
    return 0;
}

static void record(FilterStats *stats, FilterReason reason) {
    if (stats) stats->counts[reason]++;
}

FilterReason extract_pattern(SuricataRule *r, const ProtoSelection *sel,
                             Pattern *pat, FilterStats *stats) {
    memset(pat, 0, sizeof(*pat));
    pat->offset = -1;
    pat->depth  = -1;

    if (has_stateful(r->raw)) {
        record(stats, FILTER_STATEFUL);
        return FILTER_STATEFUL;
    }

    if (!rule_proto_matches(r, sel)) {
        record(stats, FILTER_PROTO_MISMATCH);
        return FILTER_PROTO_MISMATCH;
    }

    int nc = count_contents(r->raw);
    if (nc == 0) {
        record(stats, FILTER_NO_CONTENT);
        return FILTER_NO_CONTENT;
    }

    /* Pick the best content by specificity score (not raw length).
     * Prefers attack-payload strings, UUIDs, and binary sequences over generic
     * URL paths and common header values.  Reports why nothing was selected. */
    const char *content_pos      = NULL;
    int         skipped_generic   = 0;
    int         all_scored_low    = 0;
    int found = find_longest_content(r->raw, pat->content, MAX_CONTENT,
                                     &pat->nocase, &content_pos,
                                     &skipped_generic, &all_scored_low);

    if (!found) {
        if (all_scored_low) {
            record(stats, FILTER_GENERIC_URI_PATTERN);
            return FILTER_GENERIC_URI_PATTERN;
        }
        if (skipped_generic) {
            record(stats, FILTER_GENERIC_CONTENT);
            return FILTER_GENERIC_CONTENT;
        }
        record(stats, FILTER_CONTENT_EXTRACT_FAIL);
        return FILTER_CONTENT_EXTRACT_FAIL;
    }
    if (pat->content[0] == '\0') {
        record(stats, FILTER_EMPTY_CONTENT);
        return FILTER_EMPTY_CONTENT;
    }

    /* Reject patterns that are still too short (≤3 decoded bytes) even after
     * skipping generic tokens.  These cannot be selective pre-filters. */
    {
        unsigned char _dec[MAX_CONTENT];
        int _dlen = content_decode(pat->content, _dec, sizeof(_dec));
        if (_dlen <= 3) {
            record(stats, FILTER_TOO_SHORT_SINGLE);
            return FILTER_TOO_SHORT_SINGLE;
        }
    }

    /* Determine the sticky-buffer prefix for the selected content position.
     * A non-empty prefix (e.g. "\r\nUser-Agent: ") anchors the match to the
     * correct application-layer field in the raw packet payload. */
    int         no_fallback = 0;
    const char *pfx = content_pos
                          ? get_hs_prefix_before(r->raw, content_pos, &no_fallback)
                          : NULL;

    /* http.uri prefix is only valid when the content begins with '/' (URI path).
     * For mid-URI patterns (query params like "id=") the method token is not
     * adjacent in the raw payload — drop the prefix to avoid false negatives. */
    if (pfx != NULL && strncmp(pfx, "(GET|", 5) == 0) {
        unsigned char _first[MAX_CONTENT];
        int _flen = content_decode(pat->content, _first, sizeof(_first));
        if (_flen == 0 || _first[0] != '/') {
            pfx = NULL;
        }
    }

    if (pfx != NULL) {
        if (pfx[0] != '\0') {
            strncpy(pat->prefix, pfx, MAX_PREFIX - 1);
            pat->prefix[MAX_PREFIX - 1] = '\0';
        } else {
            /* empty prefix → http.method: anchor to byte 0 of TCP payload */
            pat->startswith = 1;
        }
    }

    record(stats, FILTER_OK);
    return FILTER_OK;
}

void print_filter_stats(const FilterStats *stats, int total_rules) {
    static const char *labels[FILTER_REASON_COUNT] = {
        [FILTER_OK]                  = "Accepted",
        [FILTER_STATEFUL]            = "Stateful keywords (flowbits/threshold/...)",
        [FILTER_PROTO_MISMATCH]      = "Protocol not in traffic",
        [FILTER_NO_CONTENT]          = "No content: keyword",
        [FILTER_MULTI_CONTENT_NO_FP] = "Multiple content:, no fast_pattern (unused)",
        [FILTER_CONTENT_EXTRACT_FAIL]= "Content extraction failed",
        [FILTER_EMPTY_CONTENT]       = "Extracted content is empty",
        [FILTER_TOO_SHORT_SINGLE]    = "Best content <=3 bytes: not selective",
        [FILTER_GENERIC_CONTENT]     = "All contents are generic HTTP tokens (GET/POST/...)",
        [FILTER_GENERIC_URI_PATTERN] = "Best content is generic URL path or header value",
    };

    printf("\n=== Filter Statistics (%d rules total) ===\n", total_rules);
    for (int i = 0; i < FILTER_REASON_COUNT; i++) {
        double pct = total_rules ? 100.0 * stats->counts[i] / total_rules : 0.0;
        printf("  %-44s %6ld  (%5.1f%%)\n", labels[i], stats->counts[i], pct);
    }
    printf("  %-44s %6ld\n", "Upgraded to longer content (too-short fp)", stats->upgraded);
}
