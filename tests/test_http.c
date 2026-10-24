/* Unit tests for the HTTP parser. Built with AddressSanitizer and UBSan by `make test`. */
#include "../src/http.h"

#include <stdio.h>
#include <string.h>

static int failures = 0, checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        }                                                                    \
    } while (0)

static parse_result parse(const char *s, http_request *r) {
    return http_parse_request(s, strlen(s), r);
}

static void test_basic_get(void) {
    http_request r;
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK);
    CHECK(r.method == M_GET);
    CHECK(strcmp(r.path, "/") == 0);
    CHECK(r.version_minor == 1);
    CHECK(r.keep_alive == 1);
    CHECK(r.header_len == strlen("GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
}

static void test_incomplete(void) {
    http_request r;
    CHECK(parse("", &r) == PARSE_INCOMPLETE);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\n", &r) == PARSE_INCOMPLETE);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\n\r", &r) == PARSE_INCOMPLETE);
}

static void test_methods(void) {
    http_request r;
    CHECK(parse("HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK && r.method == M_HEAD);
    CHECK(parse("POST /x HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK && r.method == M_OTHER);
    CHECK(parse("get /x HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK && r.method == M_OTHER);
    CHECK(parse("G(T /x HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse(" / HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
}

static void test_keep_alive_rules(void) {
    http_request r;
    CHECK(parse("GET / HTTP/1.0\r\n\r\n", &r) == PARSE_OK && r.keep_alive == 0);
    CHECK(parse("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", &r) == PARSE_OK && r.keep_alive == 1);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &r) == PARSE_OK && r.keep_alive == 0);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nconnection: Upgrade, CLOSE\r\n\r\n", &r) == PARSE_OK &&
          r.keep_alive == 0);
}

static void test_target(void) {
    http_request r;
    CHECK(parse("GET /a%20b.txt?x=1#f HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK);
    CHECK(strcmp(r.path, "/a b.txt") == 0);
    CHECK(parse("GET /a%00b HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET /a%zz HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET /a% HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET http://x/ HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET /a\x01 HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
}

static void test_versions_and_headers(void) {
    http_request r;
    CHECK(parse("GET / HTTP/2.0\r\nHost: a\r\n\r\n", &r) == PARSE_BAD_VERSION);
    CHECK(parse("GET / FOO/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET / HTTP/1.1\r\n\r\n", &r) == PARSE_ERROR);                       /* no Host */
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", &r) == PARSE_ERROR); /* two Hosts */
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nBadHeader\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET / HTTP/1.1\r\nHost : a\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\nX: y\r\n\r\n", &r) == PARSE_ERROR);       /* bare LF */
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == PARSE_ERROR);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n", &r) == PARSE_OK &&
          r.content_length == 12);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", &r) ==
          PARSE_ERROR);
    CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", &r) == PARSE_ERROR);
}

static void test_limits(void) {
    http_request r;
    static char big[MAX_HEADERS_SIZE + 64];
    memset(big, 'a', sizeof big);
    memcpy(big, "GET / HTTP/1.1\r\nX: ", 19);
    CHECK(http_parse_request(big, sizeof big, &r) == PARSE_TOO_LARGE);

    static char uri[MAX_PATH_LEN + 64];
    int n = snprintf(uri, sizeof uri, "GET /");
    memset(uri + n, 'b', MAX_PATH_LEN);
    strcpy(uri + n + MAX_PATH_LEN, " HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK(parse(uri, &r) == PARSE_URI_TOO_LONG);
}

static void test_pipelining(void) {
    http_request r;
    const char *two = "GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n";
    CHECK(parse(two, &r) == PARSE_OK && strcmp(r.path, "/1") == 0);
    const char *rest = two + r.header_len;
    CHECK(parse(rest, &r) == PARSE_OK && strcmp(r.path, "/2") == 0);
}

static void test_path_safety(void) {
    CHECK(http_path_is_safe("/") == 1);
    CHECK(http_path_is_safe("/a/b.txt") == 1);
    CHECK(http_path_is_safe("/a/..b") == 1);
    CHECK(http_path_is_safe("/...") == 1);
    CHECK(http_path_is_safe("/..") == 0);
    CHECK(http_path_is_safe("/../etc/passwd") == 0);
    CHECK(http_path_is_safe("/a/../../b") == 0);
    CHECK(http_path_is_safe("//..//x") == 0);
    CHECK(http_path_is_safe("/a\\..\\b") == 0);
    CHECK(http_path_is_safe("relative") == 0);

    http_request r; /* an encoded traversal decodes first, then is caught */
    CHECK(parse("GET /%2e%2e/secret HTTP/1.1\r\nHost: a\r\n\r\n", &r) == PARSE_OK);
    CHECK(http_path_is_safe(r.path) == 0);
}

static void test_helpers(void) {
    CHECK(strncmp(http_mime_type("/x/index.HTML"), "text/html", 9) == 0);
    CHECK(strcmp(http_mime_type("/a.png"), "image/png") == 0);
    CHECK(strcmp(http_mime_type("/dir.d/noext"), "application/octet-stream") == 0);
    char buf[512];
    int n = http_format_head(buf, sizeof buf, 404, "text/plain", 7, 0, "");
    CHECK(n > 0);
    CHECK(strncmp(buf, "HTTP/1.1 404 Not Found\r\n", 24) == 0);
    CHECK(strstr(buf, "Content-Length: 7\r\n") != NULL);
    CHECK(strstr(buf, "Connection: close\r\n") != NULL);
    CHECK(n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0);
    CHECK(http_format_head(buf, 16, 200, "text/plain", 1, 1, "") == -1);
}

int main(void) {
    test_basic_get();
    test_incomplete();
    test_methods();
    test_keep_alive_rules();
    test_target();
    test_versions_and_headers();
    test_limits();
    test_pipelining();
    test_path_safety();
    test_helpers();
    printf("%d/%d parser checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
