/*
 * tls.h: TLS on non blocking sockets, through OpenSSL.
 *
 * Every call returns instead of blocking. When OpenSSL needs the socket to
 * become readable or writable before it can continue (which, in the middle of
 * a handshake or a TLS 1.3 key update, is not always the direction you would
 * expect), the call returns TLS_WANT and the event loop simply runs the
 * connection's state machine again on its next readiness event. Sockets are
 * registered for both directions, edge triggered, so either edge resumes it.
 */
#ifndef CSERVE_TLS_H
#define CSERVE_TLS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

#define TLS_WANT (-2) /* would block: try again on the next event */

/* TLS 1.2 or newer, ALPN http/1.1. Returns NULL and prints why on failure. */
SSL_CTX *tls_context(const char *cert_file, const char *key_file);

/* A server side session on a connected, non blocking socket. */
SSL *tls_session(SSL_CTX *ctx, int fd);

/* 1 when the handshake has completed, TLS_WANT, or -1 on failure. */
int tls_handshake(SSL *ssl);

/* Bytes read, 0 at a clean close_notify or EOF, TLS_WANT, or -1. */
ssize_t tls_read(SSL *ssl, void *buf, size_t len);

/* Bytes written (may be partial), TLS_WANT, or -1. */
ssize_t tls_write(SSL *ssl, const void *buf, size_t len);

/* Sends close_notify if possible and frees the session. Never blocks. */
void tls_close(SSL *ssl);

void tls_free_context(SSL_CTX *ctx);

#endif
