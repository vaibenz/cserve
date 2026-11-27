#include "http.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* ---------- small helpers ---------- */

static const char *find_head_end(const char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i;
    return NULL;
}

/* Returns the length of the line starting at p (excluding CRLF), or -1 if a
 * bare CR or LF appears. Rejecting stray CR/LF closes off request smuggling
 * tricks that rely on parsers disagreeing about line endings. */
static long line_length(const char *p, const char *limit) {
    for (const char *q = p; q + 1 < limit; q++) {
        if (q[0] == '\r' && q[1] == '\n') return (long)(q - p);
        if (q[0] == '\r' || q[0] == '\n') return -1;
    }
    return -1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int is_ows(char c) { return c == ' ' || c == '\t'; }

static int ieq(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    return alen == blen && strncasecmp(a, b, blen) == 0;
}

/* RFC 9110 token characters, used for methods and header names. */
static int is_tchar(char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
    return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* Characters of a reg-name or IPv4 address (RFC 3986 section 3.2.2). */
static int is_reg_name_char(char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
    return c != '\0' && strchr("-._~!$&'()*+,;=%", c) != NULL;
}

/* uri-host [ ":" port ] (RFC 3986): a reg-name or IPv4 address, or an IPv6 address in brackets,
 * then an optional colon and a port of digits. The value may be empty. */
static int is_host_value(const char *v, size_t n) {
    size_t i = 0;
    if (n > 0 && v[0] == '[') {
        int colons = 0;
        for (i = 1; i < n && v[i] != ']'; i++) {
            if (v[i] == ':') colons++;
            else if (v[i] != '.' && hexval(v[i]) < 0) return 0;
        }
        if (i == n || colons == 0) return 0; /* unclosed, or not an IPv6 address */
        i++;
    } else {
        while (i < n && v[i] != ':') {
            if (!is_reg_name_char(v[i])) return 0;
            i++;
        }
    }
    if (i == n) return 1;
    if (v[i++] != ':') return 0;
    for (; i < n; i++)
        if (v[i] < '0' || v[i] > '9') return 0;
    return 1;
}

/* ---------- public API ---------- */

int http_url_decode(const char *src, size_t n, char *dst, size_t dstsz) {
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        char c = src[i];
        if (c == '%') {
            if (i + 2 >= n) return -1;
            int hi = hexval(src[i + 1]), lo = hexval(src[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            c = (char)(hi * 16 + lo);
            if (c == '\0') return -1;
            i += 2;
        }
        if (j + 1 >= dstsz) return -1;
        dst[j++] = c;
    }
    dst[j] = '\0';
    return (int)j;
}

int http_url_encode(const char *src, char *dst, size_t dstsz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        int plain = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
                    strchr("-._~!$&'()*+,;=@/", *p) != NULL;
        if (j + (plain ? 1 : 3) >= dstsz) return -1;
        if (plain) {
            dst[j++] = (char)*p;
        } else {
            dst[j++] = '%';
            dst[j++] = hex[*p >> 4];
            dst[j++] = hex[*p & 15];
        }
    }
    if (j >= dstsz) return -1;
    dst[j] = '\0';
    return (int)j;
}

int http_path_is_safe(const char *path) {
    if (path[0] != '/') return 0;
    const char *p = path;
    while (*p) {
        while (*p == '/') p++;
        const char *seg = p;
        while (*p && *p != '/') p++;
        if (p - seg == 2 && seg[0] == '.' && seg[1] == '.') return 0;
        if (memchr(seg, '\\', (size_t)(p - seg))) return 0;
    }
    return 1;
}

int http_path_is_hidden(const char *path) {
    const char *p = path;
    int first = 1;
    while (*p) {
        while (*p == '/') p++;
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t n = (size_t)(p - seg);
        /* "." names the directory itself, and ".." is refused by http_path_is_safe. */
        int dotted = n > 0 && seg[0] == '.' && !(n == 1) && !(n == 2 && seg[1] == '.');
        /* RFC 8615: /.well-known/ is meant to be served (ACME challenges, security.txt). */
        if (dotted && !(first && n == 11 && memcmp(seg, ".well-known", 11) == 0)) return 1;
        if (n > 0) first = 0;
    }
    return 0;
}

/*
 * Copies a header value. A value that does not fit is dropped, and so is a
 * header that appears twice: two Range headers make the request ambiguous, so
 * neither is used. `seen` remembers which of these headers have appeared.
 */
static void copy_value(char *dst, size_t dstsz, const char *v, size_t n, unsigned *seen, unsigned bit) {
    if (*seen & bit) {
        dst[0] = '\0';
        return;
    }
    *seen |= bit;
    if (n == 0 || n >= dstsz) return;
    memcpy(dst, v, n);
    dst[n] = '\0';
}

static parse_result parse_head(const char *buf, size_t len, http_request *req) {
    const char *end = find_head_end(buf, len);
    if (!end) return len >= MAX_HEADERS_SIZE ? PARSE_TOO_LARGE : PARSE_INCOMPLETE;
    size_t head_len = (size_t)(end - buf) + 4;
    if (head_len > MAX_HEADERS_SIZE) return PARSE_TOO_LARGE;

    memset(req, 0, sizeof *req);
    req->header_len = head_len;
    const char *limit = end + 2; /* every line in [buf, limit) ends with CRLF */

    /* Request line: METHOD SP request-target SP HTTP-version */
    long ll = line_length(buf, limit);
    if (ll <= 0) return PARSE_ERROR;
    const char *line = buf, *line_end = buf + ll;

    const char *sp1 = memchr(line, ' ', (size_t)ll);
    if (!sp1 || sp1 == line || sp1 - line > 16) return PARSE_ERROR;
    for (const char *q = line; q < sp1; q++)
        if (!is_tchar(*q)) return PARSE_ERROR;
    /* Methods are case sensitive: "get" is a different (unsupported) method. */
    size_t mlen = (size_t)(sp1 - line);
    if (mlen == 3 && memcmp(line, "GET", 3) == 0) req->method = M_GET;
    else if (mlen == 4 && memcmp(line, "HEAD", 4) == 0) req->method = M_HEAD;
    else req->method = M_OTHER;

    const char *target = sp1 + 1;
    const char *sp2 = memchr(target, ' ', (size_t)(line_end - target));
    if (!sp2 || sp2 == target) return PARSE_ERROR;
    size_t target_len = (size_t)(sp2 - target);
    if (target_len >= MAX_PATH_LEN) return PARSE_URI_TOO_LONG;
    /* A request target is a URI, which is ASCII only (RFC 3986): a client percent encodes anything
     * else. Raw bytes from 0x80 up are refused too, so the query, which is kept as sent and echoed
     * into a redirect's Location, can only ever hold visible ASCII. */
    for (size_t i = 0; i < target_len; i++) {
        unsigned char c = (unsigned char)target[i];
        if (c <= 0x20 || c >= 0x7f) return PARSE_ERROR;
    }
    /* RFC 9112 section 3.2.2: a server MUST accept the absolute form ("http://host/path"),
     * even though clients only send it to proxies. The scheme and authority are dropped and the
     * rest is served like an origin form target; an empty path means "/". */
    int empty_path = 0;
    size_t skip = 0;
    if (target_len > 7 && strncasecmp(target, "http://", 7) == 0) skip = 7;
    else if (target_len > 8 && strncasecmp(target, "https://", 8) == 0) skip = 8;
    if (skip) {
        size_t a = skip;
        while (a < target_len && target[a] != '/' && target[a] != '?' && target[a] != '#') a++;
        if (a == skip) return PARSE_ERROR; /* no authority: "http:///x" */
        /* The authority stands in for Host (RFC 9112 section 3.2.2), so it is held to the same shape:
         * host[:port]. Userinfo ("http://user@x/") is refused too, as RFC 9110 section 4.2.4 advises. */
        if (!is_host_value(target + skip, a - skip)) return PARSE_ERROR;
        target += a;
        target_len -= a;
        empty_path = target_len == 0 || target[0] != '/';
    } else if (target_len == 1 && target[0] == '*') {
        /* The asterisk form ("OPTIONS * HTTP/1.1", RFC 9112 section 3.2.4) is a well formed request
         * about the server as a whole, so it gets the 405 and Allow of any other OPTIONS rather than a
         * 400. Any other method with "*" is malformed. The path is left as "/" for the caller. */
        if (mlen != 7 || memcmp(line, "OPTIONS", 7) != 0) return PARSE_ERROR;
        empty_path = 1;
        target_len = 0;
    } else if (target[0] != '/') {
        return PARSE_ERROR; /* neither origin nor absolute form */
    }
    size_t path_len = target_len;
    for (size_t i = 0; i < target_len; i++)
        if ((target[i] == '?' || target[i] == '#') && path_len == target_len) path_len = i;
    if (empty_path) {
        req->path[0] = '/';
        req->path[1] = '\0';
    } else if (http_url_decode(target, path_len, req->path, sizeof req->path) < 0) {
        return PARSE_ERROR;
    }
    /* Kept as sent (every byte is visible ASCII, checked above) so a redirect can carry it on. */
    if (path_len < target_len && target[path_len] == '?') {
        size_t q = path_len + 1, qe = q;
        while (qe < target_len && target[qe] != '#') qe++;
        memcpy(req->query, target + q, qe - q);
        req->query[qe - q] = '\0';
    }

    const char *ver = sp2 + 1;
    size_t ver_len = (size_t)(line_end - ver);
    if (ver_len == 8 && memcmp(ver, "HTTP/1.1", 8) == 0) req->version_minor = 1;
    else if (ver_len == 8 && memcmp(ver, "HTTP/1.0", 8) == 0) req->version_minor = 0;
    /* RFC 9112 section 2.3: a higher minor version of a major version we implement ("HTTP/1.2") is
     * processed as the highest one we know, HTTP/1.1, rather than refused with a 505. */
    else if (ver_len == 8 && memcmp(ver, "HTTP/1.", 7) == 0 && ver[7] >= '2' && ver[7] <= '9')
        req->version_minor = 1;
    else if (ver_len == 8 && memcmp(ver, "HTTP/", 5) == 0 && ver[5] >= '0' && ver[5] <= '9' &&
             ver[6] == '.' && ver[7] >= '0' && ver[7] <= '9')
        return PARSE_BAD_VERSION;
    else return PARSE_ERROR;

    /* Header fields */
    int saw_host = 0, saw_close = 0, saw_keep_alive = 0;
    unsigned seen = 0;
    req->content_length = -1;
    const char *p = line_end + 2;
    while (p < limit) {
        ll = line_length(p, limit);
        if (ll <= 0) return PARSE_ERROR;
        /* RFC 9110 section 5.5: a NUL in a field value MUST be rejected (or replaced). Parsers that
         * stop at the NUL and parsers that do not would read different headers out of one line. */
        if (memchr(p, '\0', (size_t)ll)) return PARSE_ERROR;
        const char *colon = memchr(p, ':', (size_t)ll);
        if (!colon || colon == p) return PARSE_ERROR;
        /* The other control characters (all but HTAB, and DEL) are not valid in a field value either.
         * Some proxies refuse them and some pass them on, which is the kind of disagreement smuggling
         * needs, and a value holding an escape sequence is a terminal injection in anything that logs it. */
        for (const char *q = colon + 1; q < p + ll; q++) {
            unsigned char c = (unsigned char)*q;
            if ((c < 0x20 && c != '\t') || c == 0x7f) return PARSE_ERROR;
        }
        for (const char *q = p; q < colon; q++)
            if (!is_tchar(*q)) return PARSE_ERROR; /* also rejects "Name : value" */

        const char *v = colon + 1, *v_end = p + ll;
        while (v < v_end && is_ows(*v)) v++;
        while (v_end > v && is_ows(v_end[-1])) v_end--;
        size_t name_len = (size_t)(colon - p), v_len = (size_t)(v_end - v);

        if (ieq(p, name_len, "Host")) {
            if (saw_host++) return PARSE_ERROR;
            /* RFC 9112 section 3.2: a Host with an invalid value MUST get a 400, like a missing one. */
            if (!is_host_value(v, v_len)) return PARSE_ERROR;
        } else if (ieq(p, name_len, "Content-Length")) {
            if (v_len == 0 || v_len > 18) return PARSE_ERROR;
            long long cl = 0;
            for (size_t i = 0; i < v_len; i++) {
                if (v[i] < '0' || v[i] > '9') return PARSE_ERROR;
                cl = cl * 10 + (v[i] - '0');
            }
            if (req->content_length >= 0 && req->content_length != cl) return PARSE_ERROR;
            req->content_length = cl;
        } else if (ieq(p, name_len, "Range")) {
            copy_value(req->range, sizeof req->range, v, v_len, &seen, 1);
        } else if (ieq(p, name_len, "If-None-Match")) {
            copy_value(req->if_none_match, sizeof req->if_none_match, v, v_len, &seen, 2);
            req->has_if_none_match = 1;
        } else if (ieq(p, name_len, "If-Modified-Since")) {
            copy_value(req->if_modified_since, sizeof req->if_modified_since, v, v_len, &seen, 4);
        } else if (ieq(p, name_len, "If-Range")) {
            copy_value(req->if_range, sizeof req->if_range, v, v_len, &seen, 8);
            req->has_if_range = 1;
        } else if (ieq(p, name_len, "Transfer-Encoding")) {
            return PARSE_ERROR; /* request bodies are not supported by a static server */
        } else if (ieq(p, name_len, "Connection")) {
            const char *t = v;
            while (t < v_end) {
                const char *comma = memchr(t, ',', (size_t)(v_end - t));
                const char *te = comma ? comma : v_end;
                const char *ts = t;
                while (ts < te && is_ows(*ts)) ts++;
                const char *tend = te;
                while (tend > ts && is_ows(tend[-1])) tend--;
                if (ieq(ts, (size_t)(tend - ts), "close")) saw_close = 1;
                if (ieq(ts, (size_t)(tend - ts), "keep-alive")) saw_keep_alive = 1;
                t = comma ? comma + 1 : v_end;
            }
        }
        p += ll + 2;
    }

    if (req->version_minor == 1 && !saw_host) return PARSE_ERROR; /* RFC 9112 section 3.2 */
    if (req->content_length < 0) req->content_length = 0;
    req->keep_alive = req->version_minor == 1 ? !saw_close : (saw_keep_alive && !saw_close);
    return PARSE_OK;
}

/*
 * RFC 9112 section 2.2: a server SHOULD ignore at least one empty line (CRLF)
 * received before the request line. Some clients send a stray CRLF after a
 * request body, which would otherwise turn the next pipelined request into a
 * 400. The skipped bytes count towards header_len, so the caller consumes
 * them, and towards MAX_HEADERS_SIZE, so a stream of CRLFs cannot hold a
 * connection open without ever sending a request.
 */
parse_result http_parse_request(const char *buf, size_t len, http_request *req) {
    size_t skip = 0;
    while (skip + 1 < len && buf[skip] == '\r' && buf[skip + 1] == '\n') skip += 2;
    parse_result pr = parse_head(buf + skip, len - skip, req);
    if (pr == PARSE_INCOMPLETE && len >= MAX_HEADERS_SIZE) return PARSE_TOO_LARGE;
    if (pr != PARSE_OK) return pr;
    req->header_len += skip;
    return req->header_len > MAX_HEADERS_SIZE ? PARSE_TOO_LARGE : PARSE_OK;
}

/* Parses a decimal of at most 18 digits (no overflow). Returns digits read, or 0. */
static int parse_digits(const char **p, long long *out) {
    long long v = 0;
    int n = 0;
    while (**p >= '0' && **p <= '9') {
        if (++n > 18) return 0;
        v = v * 10 + (**p - '0');
        (*p)++;
    }
    *out = v;
    return n;
}

int http_parse_range(const char *v, long long size, long long *first, long long *last) {
    /* Range unit names are case insensitive (RFC 9110 section 14.1); other units are ignored. */
    if (strncasecmp(v, "bytes=", 6) != 0) return 0;
    const char *p = v + 6;
    while (is_ows(*p)) p++;
    long long a = -1, b = -1;
    if (*p == '-') { /* suffix: the last b bytes */
        p++;
        if (!parse_digits(&p, &b)) return 0;
    } else {
        if (!parse_digits(&p, &a) || *p++ != '-') return 0;
        if (*p >= '0' && *p <= '9' && !parse_digits(&p, &b)) return 0;
        if (b >= 0 && b < a) return 0; /* "bytes=5-3" is invalid, so the header is ignored */
    }
    while (is_ows(*p)) p++;
    if (*p != '\0') return 0; /* a second range ("0-1,5-6") or trailing junk: send the whole file */

    if (a < 0) { /* suffix range */
        if (b == 0) return -1;
        /* RFC 9110 section 14.1.1 counts a non zero suffix length as satisfiable even for an empty file,
         * so 416 would be wrong, but no 206 can carry zero bytes: send the whole (empty) file instead. */
        if (size == 0) return 0;
        *first = b >= size ? 0 : size - b;
        *last = size - 1;
        return 1;
    }
    if (a >= size) return -1;
    *first = a;
    *last = b < 0 || b >= size ? size - 1 : b;
    return 1;
}

int http_format_etag(char *out, size_t outsz, unsigned long long ino, long long size, long long mtime_sec,
                     long mtime_nsec) {
    int n = snprintf(out, outsz, "\"%llx-%llx-%llx%08lx\"", ino, (unsigned long long)size,
                     (unsigned long long)mtime_sec, (unsigned long)mtime_nsec);
    return n < 0 || (size_t)n >= outsz ? -1 : n;
}

static const char *const g_days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *const g_months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

int http_format_date(char *out, size_t outsz, long long t) {
    time_t tt = (time_t)t;
    struct tm tm;
    if (!gmtime_r(&tt, &tm)) return -1;
    int n = snprintf(out, outsz, "%s, %02d %s %04d %02d:%02d:%02d GMT", g_days[tm.tm_wday], tm.tm_mday,
                     g_months[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return n < 0 || (size_t)n >= outsz ? -1 : n;
}

/* Days from 1970-01-01 to y-m-d in the proleptic Gregorian calendar (Howard Hinnant's algorithm). */
static long long days_from_civil(long long y, int m, int d) {
    y -= m <= 2;
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long yoe = y - era * 400;
    long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

long long http_parse_date(const char *v) {
    /* Exactly "Www, DD Mmm YYYY HH:MM:SS GMT": 29 characters. Obsolete formats are not accepted;
     * an unparseable If-Modified-Since is simply ignored, which is always safe. */
    if (strlen(v) != 29 || v[3] != ',' || v[4] != ' ' || v[7] != ' ' || v[11] != ' ' || v[16] != ' ' ||
        v[19] != ':' || v[22] != ':' || v[25] != ' ' || memcmp(v + 26, "GMT", 3) != 0)
        return -1;
    int wday = -1, mon = -1;
    for (int i = 0; i < 7; i++)
        if (memcmp(v, g_days[i], 3) == 0) wday = i;
    for (int i = 0; i < 12; i++)
        if (memcmp(v + 8, g_months[i], 3) == 0) mon = i + 1;
    if (wday < 0 || mon < 0) return -1;
    const int at[] = {5, 12, 17, 20, 23}, len[] = {2, 4, 2, 2, 2};
    int f[5];
    for (int k = 0; k < 5; k++) {
        f[k] = 0;
        for (int i = 0; i < len[k]; i++) {
            char c = v[at[k] + i];
            if (c < '0' || c > '9') return -1;
            f[k] = f[k] * 10 + (c - '0');
        }
    }
    int day = f[0], year = f[1], hh = f[2], mm = f[3], ss = f[4];
    static const int mdays[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (day < 1 || day > mdays[mon - 1] || hh > 23 || mm > 59 || ss > 60) return -1;
    int leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if (mon == 2 && day == 29 && !leap) return -1;
    long long days = days_from_civil(year, mon, day);
    if (((days % 7 + 11) % 7) != wday) return -1; /* 1970-01-01 was a Thursday */
    return days * 86400 + hh * 3600 + mm * 60 + (ss > 59 ? 59 : ss);
}

int http_etag_matches(const char *list, const char *etag) {
    const char *e = etag[0] == 'W' && etag[1] == '/' ? etag + 2 : etag; /* weak comparison */
    size_t elen = strlen(e);
    /* "*" is the whole value or nothing (RFC 9110 section 13.1.2): "*, \"x\"" or "*abc" is malformed,
     * and a malformed list must not turn into a 304 for a client that may hold no copy at all. */
    const char *s = list;
    while (is_ows(*s)) s++;
    if (*s == '*') {
        s++;
        while (is_ows(*s)) s++;
        return *s == '\0';
    }
    /* The whole list is checked before a match counts: "\"abc\"junk" or two tags with no comma
     * between them are malformed wherever the match sits. */
    const char *p = list;
    int matched = 0;
    for (;;) {
        while (is_ows(*p) || *p == ',') p++;
        if (*p == '\0') return matched;
        if (p[0] == 'W' && p[1] == '/') p += 2;
        if (*p != '"') return 0; /* malformed list: no match, so the full response is sent */
        const char *q = strchr(p + 1, '"');
        if (!q) return 0;
        if ((size_t)(q + 1 - p) == elen && memcmp(p, e, elen) == 0) matched = 1;
        p = q + 1;
        while (is_ows(*p)) p++;
        if (*p != ',' && *p != '\0') return 0; /* a tag must be followed by a comma or the end */
    }
}

const char *http_mime_type(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *dot = strrchr(slash ? slash : path, '.');
    if (!dot) return "application/octet-stream";
    static const struct { const char *ext, *type; } table[] = {
        {".html", "text/html; charset=utf-8"}, {".htm", "text/html; charset=utf-8"},
        {".css", "text/css; charset=utf-8"},   {".js", "text/javascript; charset=utf-8"},
        {".json", "application/json"},         {".txt", "text/plain; charset=utf-8"},
        {".md", "text/markdown; charset=utf-8"}, {".xml", "application/xml"},
        {".png", "image/png"},   {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},   {".svg", "image/svg+xml"}, {".webp", "image/webp"},
        {".ico", "image/x-icon"}, {".pdf", "application/pdf"}, {".wasm", "application/wasm"},
        {".woff2", "font/woff2"}, {".mp4", "video/mp4"},
        {".mjs", "text/javascript; charset=utf-8"}, {".map", "application/json"},
        {".csv", "text/csv; charset=utf-8"},   {".avif", "image/avif"},
        {".woff", "font/woff"},  {".ttf", "font/ttf"},   {".otf", "font/otf"},
        {".webm", "video/webm"}, {".mp3", "audio/mpeg"}, {".ogg", "audio/ogg"},
        {".wav", "audio/wav"},   {".zip", "application/zip"}, {".gz", "application/gzip"},
        {".webmanifest", "application/manifest+json"},
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcasecmp(dot, table[i].ext) == 0) return table[i].type;
    return "application/octet-stream";
}

const char *http_status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 414: return "URI Too Long";
    case 416: return "Range Not Satisfiable";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 505: return "HTTP Version Not Supported";
    default: return "Unknown";
    }
}

int http_format_head(char *out, size_t outsz, int status, const char *content_type,
                     long long content_length, int keep_alive, const char *extra_headers) {
    char date[64], length[48] = "";
    if (http_format_date(date, sizeof date, (long long)time(NULL)) < 0) date[0] = '\0';
    if (content_length >= 0) snprintf(length, sizeof length, "Content-Length: %lld\r\n", content_length);
    int n = snprintf(out, outsz,
                     "HTTP/1.1 %d %s\r\n"
                     "Server: cserve\r\n"
                     "Date: %s\r\n"
                     "X-Content-Type-Options: nosniff\r\n"
                     "%s%s%s"
                     "%s"
                     "Connection: %s\r\n"
                     "%s\r\n",
                     status, http_status_text(status), date, content_type ? "Content-Type: " : "",
                     content_type ? content_type : "", content_type ? "\r\n" : "", length,
                     keep_alive ? "keep-alive" : "close", extra_headers ? extra_headers : "");
    return (n < 0 || (size_t)n >= outsz) ? -1 : n;
}
