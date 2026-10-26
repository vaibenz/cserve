/*
 * fuzz_http.c: coverage guided fuzzing of the request parser (libFuzzer).
 *
 *   make fuzz FUZZ_TIME=60
 *
 * Built with AddressSanitizer and UndefinedBehaviorSanitizer, so any out of
 * bounds access, overflow or other undefined behaviour stops the run. On top
 * of "does not crash", each input is checked against properties the server
 * depends on:
 *
 *   1. The verdict depends only on the request head. Parsing exactly the head,
 *      or the head followed by whatever comes next (the start of a pipelined
 *      request), gives the same result and the same fields.
 *   2. A head is never judged before it is complete: every prefix shorter than
 *      the head is INCOMPLETE (or TOO_LARGE once over the size limit).
 *   3. An accepted request is well formed: the head ends in CRLFCRLF, the path
 *      is absolute and NUL terminated, the version is 1.0 or 1.1.
 *   4. http_path_is_safe agrees with a separate, simple reimplementation of
 *      the rule (no ".." segment, no backslash, absolute).
 *   5. Percent encoding round trips: any bytes without NUL, encoded as %XX and
 *      decoded, come back unchanged.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/http.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) __builtin_trap();                                                             \
    } while (0)

static int same_request(const http_request *a, const http_request *b) {
    return a->method == b->method && strcmp(a->path, b->path) == 0 && a->version_minor == b->version_minor &&
           a->keep_alive == b->keep_alive && a->content_length == b->content_length &&
           a->header_len == b->header_len;
}

/* The path rule written a second, deliberately naive way. */
static int naive_safe(const char *path) {
    if (path[0] != '/') return 0;
    if (strchr(path, '\\')) return 0;
    size_t n = strlen(path);
    for (size_t i = 0; i + 1 < n + 1; i++) {
        int seg_start = i == 0 || path[i - 1] == '/';
        if (seg_start && path[i] == '.' && i + 1 < n && path[i + 1] == '.' && (i + 2 == n || path[i + 2] == '/'))
            return 0;
    }
    return 1;
}

static void check_parser(const char *buf, size_t size) {
    http_request req, again;
    parse_result r = http_parse_request(buf, size, &req);
    CHECK(r == PARSE_INCOMPLETE || r == PARSE_OK || r == PARSE_ERROR || r == PARSE_TOO_LARGE ||
          r == PARSE_URI_TOO_LONG || r == PARSE_BAD_VERSION);
    if (r == PARSE_INCOMPLETE) CHECK(size < MAX_HEADERS_SIZE);

    /* Find where the head ends independently of the parser. */
    size_t head = 0;
    for (size_t i = 0; i + 3 < size; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            head = i + 4;
            break;
        }

    if (r == PARSE_OK) {
        CHECK(head != 0 && req.header_len == head && head <= size && head <= MAX_HEADERS_SIZE);
        CHECK(memcmp(buf + head - 4, "\r\n\r\n", 4) == 0);
        CHECK(req.path[0] == '/');
        CHECK(memchr(req.path, '\0', MAX_PATH_LEN) != NULL);
        CHECK(req.version_minor == 0 || req.version_minor == 1);
        CHECK(req.keep_alive == 0 || req.keep_alive == 1);
        CHECK(req.content_length >= 0);
        CHECK(http_path_is_safe(req.path) == naive_safe(req.path));
    }

    if (head != 0 && head <= MAX_HEADERS_SIZE) {
        /* Property 1: only the head matters. */
        parse_result r2 = http_parse_request(buf, head, &again);
        CHECK(r2 == r);
        if (r == PARSE_OK) CHECK(same_request(&req, &again));
        /* Property 2: no verdict before the head is complete. */
        size_t cuts[3] = {head - 1, head / 2, head > 3 ? head - 3 : 0};
        for (int k = 0; k < 3; k++) {
            parse_result rp = http_parse_request(buf, cuts[k], &again);
            CHECK(rp == PARSE_INCOMPLETE);
        }
    }
}

static void check_url_roundtrip(const uint8_t *data, size_t size) {
    if (size > 512) size = 512;
    char enc[512 * 3 + 1], dec[512 + 1];
    size_t raw = 0;
    uint8_t orig[512];
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0) continue; /* an encoded NUL is rejected on purpose */
        orig[raw] = data[i];
        static const char hex[] = "0123456789ABCDEF";
        enc[raw * 3] = '%';
        enc[raw * 3 + 1] = hex[data[i] >> 4];
        enc[raw * 3 + 2] = hex[data[i] & 15];
        raw++;
    }
    int n = http_url_decode(enc, raw * 3, dec, sizeof dec);
    CHECK(n == (int)raw);
    CHECK(memcmp(dec, orig, raw) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    check_parser((const char *)data, size);
    check_url_roundtrip(data, size);
    return 0;
}
