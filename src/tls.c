#include "tls.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    static const unsigned char http11[] = "\x08http/1.1";
    unsigned char *sel;
    if (SSL_select_next_proto(&sel, outlen, http11, sizeof http11 - 1, in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL; /* the client only speaks something else, such as h2 */
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *tls_context(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) goto fail;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /* No renegotiation, no compression (CRIME), server picks the cipher order. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE |
                                 SSL_OP_IGNORE_UNEXPECTED_EOF); /* a peer that just disconnects reads as EOF */
    /* Partial writes, and the retry of a write may use a different buffer address. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                              SSL_MODE_RELEASE_BUFFERS);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) goto fail;
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) goto fail;
    if (SSL_CTX_check_private_key(ctx) != 1) goto fail;
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    return ctx;
fail:
    fprintf(stderr, "cserve: TLS setup failed:\n");
    ERR_print_errors_fp(stderr);
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}

SSL *tls_session(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_accept_state(ssl);
    return ssl;
}

/* Maps an OpenSSL result to our convention: TLS_WANT, 0 for a clean close, or -1. */
static int classify(SSL *ssl, int ret) {
    int err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return TLS_WANT;
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_SYSCALL:
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return TLS_WANT;
        /* fall through */
    default:
        ERR_clear_error(); /* the error queue is per thread: never leave it for another connection */
        return -1;
    }
}

int tls_handshake(SSL *ssl) {
    ERR_clear_error();
    int r = SSL_do_handshake(ssl);
    if (r == 1) return 1;
    int c = classify(ssl, r);
    return c == TLS_WANT ? TLS_WANT : -1;
}

ssize_t tls_read(SSL *ssl, void *buf, size_t len) {
    ERR_clear_error();
    size_t n = 0;
    int r = SSL_read_ex(ssl, buf, len, &n);
    if (r == 1) return (ssize_t)n;
    return classify(ssl, r);
}

ssize_t tls_write(SSL *ssl, const void *buf, size_t len) {
    ERR_clear_error();
    size_t n = 0;
    int r = SSL_write_ex(ssl, buf, len, &n);
    if (r == 1) return (ssize_t)n;
    int c = classify(ssl, r);
    return c == 0 ? -1 : c;
}

void tls_free_context(SSL_CTX *ctx) { SSL_CTX_free(ctx); }

void tls_close(SSL *ssl) {
    if (!ssl) return;
    ERR_clear_error();
    if (SSL_is_init_finished(ssl)) SSL_shutdown(ssl); /* one non blocking attempt at close_notify */
    ERR_clear_error();
    SSL_free(ssl);
}
