/*
 * http.h: a small, strict HTTP/1.x request parser and response helpers.
 *
 * The parser is a pure function over a byte buffer. It never allocates and
 * never touches sockets, which makes it easy to unit test and safe to call
 * repeatedly as more bytes arrive on a non blocking connection.
 */
#ifndef CSERVE_HTTP_H
#define CSERVE_HTTP_H

#include <stddef.h>

#define MAX_HEADERS_SIZE 8192 /* request line + headers, like nginx's default */
#define MAX_PATH_LEN 2048     /* decoded request path */
#define MAX_RANGE_LEN 64      /* a longer Range header is ignored (a full 200 is always allowed) */
#define MAX_ETAGS_LEN 512     /* a longer If-None-Match or If-Range is ignored too */
#define MAX_DATE_LEN 64

typedef enum { M_GET, M_HEAD, M_OTHER } http_method;

typedef enum {
    PARSE_INCOMPLETE = 0,     /* need more bytes */
    PARSE_OK = 1,             /* a full request head was parsed */
    PARSE_ERROR = -1,         /* malformed: 400 */
    PARSE_TOO_LARGE = -2,     /* head exceeds MAX_HEADERS_SIZE: 431 */
    PARSE_URI_TOO_LONG = -3,  /* 414 */
    PARSE_BAD_VERSION = -4    /* well formed but not HTTP/1.0 or 1.1: 505 */
} parse_result;

typedef struct {
    http_method method;
    char path[MAX_PATH_LEN]; /* percent decoded, query string removed */
    int version_minor;       /* 0 or 1 */
    int keep_alive;          /* should the connection stay open afterwards */
    long long content_length;
    size_t header_len;       /* bytes consumed, including the final CRLFCRLF */
    /* Header values copied out, so they outlive the receive buffer. Empty when absent. */
    char range[MAX_RANGE_LEN];
    char if_none_match[MAX_ETAGS_LEN];
    char if_modified_since[MAX_DATE_LEN];
    char if_range[MAX_ETAGS_LEN];
} http_request;

parse_result http_parse_request(const char *buf, size_t len, http_request *req);

/* Percent decodes src[0..n) into dst. Returns decoded length, or -1 on a bad
 * escape, an encoded NUL byte, or if dst is too small. */
int http_url_decode(const char *src, size_t n, char *dst, size_t dstsz);

/* 1 if path is absolute and has no ".." segment, else 0. */
int http_path_is_safe(const char *path);

/*
 * Range: a single byte range against a representation of `size` bytes (RFC 9110
 * section 14). Returns 1 with the inclusive [*first, *last] for a satisfiable
 * range, -1 when it is well formed but unsatisfiable (416), or 0 when the
 * header should be ignored and the whole file sent: malformed, or a multi
 * range request, which a server may always answer with a plain 200.
 */
int http_parse_range(const char *v, long long size, long long *first, long long *last);

/* Validators. A strong ETag from the file's identity, size and modification time. */
int http_format_etag(char *out, size_t outsz, unsigned long long ino, long long size, long long mtime_sec,
                     long mtime_nsec);
/* IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"). Returns -1 if it does not parse. */
long long http_parse_date(const char *v);
int http_format_date(char *out, size_t outsz, long long t);

/* If-None-Match: 1 if etag is listed (weak comparison) or the list is "*". */
int http_etag_matches(const char *list, const char *etag);

const char *http_mime_type(const char *path);
const char *http_status_text(int status);

/* Writes a response head into out. extra_headers may be "" and must end in
 * CRLF when non empty. A negative content_length omits the header (304).
 * Returns bytes written, or -1 if out is too small. */
int http_format_head(char *out, size_t outsz, int status, const char *content_type,
                     long long content_length, int keep_alive, const char *extra_headers);

#endif
