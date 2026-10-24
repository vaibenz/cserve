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
} http_request;

parse_result http_parse_request(const char *buf, size_t len, http_request *req);

/* Percent decodes src[0..n) into dst. Returns decoded length, or -1 on a bad
 * escape, an encoded NUL byte, or if dst is too small. */
int http_url_decode(const char *src, size_t n, char *dst, size_t dstsz);

/* 1 if path is absolute and has no ".." segment, else 0. */
int http_path_is_safe(const char *path);

const char *http_mime_type(const char *path);
const char *http_status_text(int status);

/* Writes a response head into out. extra_headers may be "" and must end in
 * CRLF when non empty. Returns bytes written, or -1 if out is too small. */
int http_format_head(char *out, size_t outsz, int status, const char *content_type,
                     long long content_length, int keep_alive, const char *extra_headers);

#endif
