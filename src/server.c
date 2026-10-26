/*
 * server.c: the multi reactor core.
 *
 * Each worker thread owns:
 *   - its own listening socket, bound with SO_REUSEPORT so the kernel load
 *     balances new connections across workers (no shared accept lock, no
 *     thundering herd);
 *   - its own epoll instance, with client sockets registered edge triggered;
 *   - an LRU list of its connections, used to close idle keep alive clients.
 *
 * Nothing is shared between workers except read only configuration, so the
 * hot path takes no locks at all.
 *
 * With TLS, every connection carries an OpenSSL session. The state machine is
 * the same; reads and writes go through tls_read and tls_write, which return
 * TLS_WANT instead of blocking, and file bodies are encrypted in 16 KB chunks
 * (one TLS record each) instead of going out through sendfile.
 */
#include "server.h"
#include "http.h"
#include "tls.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <linux/tcp.h> /* the kernel tcp_info, which has tcpi_bytes_acked */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define HAVE_OPENAT2 1
#endif
#endif

#define RBUF_SIZE MAX_HEADERS_SIZE
#define WBUF_SIZE 1024
#define MAX_EVENTS 256
#define SENDFILE_CHUNK (1 << 20)
#define TLS_CHUNK 16384 /* the largest TLS record */

typedef struct conn {
    int fd;
    int file_fd;               /* file being streamed, or -1 */
    off_t file_off, file_end;
    size_t rlen;               /* bytes buffered in rbuf */
    size_t wlen, woff;         /* response head (or small error body) in wbuf */
    int keep_alive;            /* keep the connection after the current response */
    int eof;                   /* peer has closed its write side */
    int64_t last_active;        /* ms, monotonic */
    struct conn *prev, *next;  /* LRU list, most recently active first */
    uint64_t acked;            /* bytes the client had acknowledged at the last idle check */
    SSL *ssl;                  /* NULL for plain HTTP */
    int handshaked;
    char *tbuf;                /* TLS only: file bytes read but not yet fully encrypted and sent */
    size_t tlen, toff;
    char rbuf[RBUF_SIZE];
    char wbuf[WBUF_SIZE];
} conn;

typedef struct {
    int id, epfd, listen_fd;
    const server_config *cfg;
    conn *lru_head, *lru_tail;
    unsigned long long accepted, responses;
    pthread_t tid;
} worker;

static volatile sig_atomic_t g_running = 1;
static SSL_CTX *g_tls;
static int g_root_fd = -1;
static char g_root_real[PATH_MAX];
static size_t g_root_len;

static void on_signal(int sig) { (void)sig; g_running = 0; }

/* Milliseconds: whole seconds would let a connection touched at x.999 expire at x+1.001. */
static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---------- connection LRU ---------- */

static void lru_unlink(worker *w, conn *c) {
    if (c->prev) c->prev->next = c->next; else w->lru_head = c->next;
    if (c->next) c->next->prev = c->prev; else w->lru_tail = c->prev;
    c->prev = c->next = NULL;
}

static void lru_push_front(worker *w, conn *c) {
    c->prev = NULL;
    c->next = w->lru_head;
    if (w->lru_head) w->lru_head->prev = c;
    w->lru_head = c;
    if (!w->lru_tail) w->lru_tail = c;
}

static void conn_touch(worker *w, conn *c) {
    c->last_active = now_ms();
    if (w->lru_head != c) { lru_unlink(w, c); lru_push_front(w, c); }
}

static void conn_close(worker *w, conn *c) {
    lru_unlink(w, c);
    if (c->ssl) tls_close(c->ssl);
    free(c->tbuf);
    if (c->file_fd >= 0) close(c->file_fd);
    close(c->fd); /* also removes it from the epoll set */
    free(c);
}


/*
 * A connection in the middle of a large response can go a long time without an
 * event: the kernel send buffer autotunes to megabytes, and EPOLLOUT only fires
 * again once a good part of it has drained. The same is true after the last
 * write, when the server has nothing left to send but the kernel still holds
 * megabytes of the response. For a slow client that is still reading, neither
 * is idle. So an expired connection is judged by progress instead: if the
 * client has acknowledged more bytes since the last check, it is taking data
 * and the connection stays. A client that stops reading acknowledges nothing
 * and is reaped as before.
 *
 * The acknowledged byte count is used rather than the size of the send queue
 * because the queue is a sawtooth: the check runs one timeout after the last
 * refill, so it tends to sample the same point of the tooth and see the same
 * size even while the client reads steadily.
 */
static int made_progress(conn *c) {
    struct tcp_info ti;
    socklen_t len = sizeof ti;
    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) < 0) return 0;
    int progressed = ti.tcpi_bytes_acked != c->acked;
    c->acked = ti.tcpi_bytes_acked;
    return progressed;
}

/* Idle connections sit at the tail, so this is O(number expired). */
static void sweep_idle(worker *w) {
    int64_t now = now_ms();
    while (w->lru_tail && now - w->lru_tail->last_active >= (int64_t)w->cfg->idle_timeout_sec * 1000) {
        conn *c = w->lru_tail;
        if (made_progress(c)) conn_touch(w, c); /* a slow reader, not an idle one */
        else conn_close(w, c);
    }
}

/* ---------- safe file opening ---------- */

/*
 * Opens rel beneath the document root. With openat2 and RESOLVE_BENEATH the
 * kernel itself refuses any resolution (including via symlinks) that escapes
 * the root, failing with EXDEV. Older kernels fall back to checking the
 * resolved path of the opened descriptor.
 */
static int open_beneath(int dirfd, const char *rel) {
#ifdef HAVE_OPENAT2
    struct open_how how;
    memset(&how, 0, sizeof how);
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    int fd = (int)syscall(SYS_openat2, dirfd, rel, &how, sizeof how);
    if (fd >= 0 || errno != ENOSYS) return fd;
#endif
    int ffd = openat(dirfd, rel, O_RDONLY | O_CLOEXEC);
    if (ffd < 0) return -1;
    char link[64], real[PATH_MAX];
    snprintf(link, sizeof link, "/proc/self/fd/%d", ffd);
    ssize_t n = readlink(link, real, sizeof real - 1);
    if (n < 0) { close(ffd); errno = EACCES; return -1; }
    real[n] = '\0';
    if (g_root_len > 1 && (strncmp(real, g_root_real, g_root_len) != 0 ||
                           (real[g_root_len] != '/' && real[g_root_len] != '\0'))) {
        close(ffd);
        errno = EXDEV;
        return -1;
    }
    return ffd;
}

/* ---------- responses ---------- */

static void build_error(conn *c, int status, int keep_alive, int head_only, const char *extra) {
    char body[128];
    int blen = snprintf(body, sizeof body, "<html><body><h1>%d %s</h1></body></html>\n", status,
                        http_status_text(status));
    int n = http_format_head(c->wbuf, sizeof c->wbuf, status, "text/html; charset=utf-8", blen,
                             keep_alive, extra);
    if (n < 0) n = 0;
    if (!head_only && (size_t)n + (size_t)blen <= sizeof c->wbuf) {
        memcpy(c->wbuf + n, body, (size_t)blen);
        n += blen;
    }
    c->wlen = (size_t)n;
    c->woff = 0;
    c->keep_alive = keep_alive;
}

static int status_for_errno(int err) {
    switch (err) {
    case ENOENT: case ENOTDIR: return 404;
    case EACCES: case EPERM: case EXDEV: case ELOOP: return 403;
    case ENAMETOOLONG: return 414;
    default: return 500;
    }
}

static void build_response(conn *c, const http_request *req) {
    int head = req->method == M_HEAD;
    if (req->method == M_OTHER) {
        build_error(c, 405, 0, 0, "Allow: GET, HEAD\r\n");
        return;
    }
    if (req->content_length > 0) { /* a GET with a body: we do not read bodies, so close */
        build_error(c, 400, 0, head, NULL);
        return;
    }
    if (!http_path_is_safe(req->path)) {
        build_error(c, 403, req->keep_alive, head, NULL);
        return;
    }

    const char *rel = req->path + 1; /* strip the leading slash */
    if (*rel == '\0') rel = ".";
    int fd = open_beneath(g_root_fd, rel);
    if (fd < 0) { build_error(c, status_for_errno(errno), req->keep_alive, head, NULL); return; }

    struct stat st;
    int is_index = 0;
    if (fstat(fd, &st) < 0) { close(fd); build_error(c, 500, 0, head, NULL); return; }
    if (S_ISDIR(st.st_mode)) { /* serve the directory's index.html, never a listing */
        int idx = open_beneath(fd, "index.html");
        close(fd);
        if (idx < 0) { build_error(c, status_for_errno(errno), req->keep_alive, head, NULL); return; }
        fd = idx;
        is_index = 1;
        if (fstat(fd, &st) < 0) { close(fd); build_error(c, 500, 0, head, NULL); return; }
    }
    if (!S_ISREG(st.st_mode)) { close(fd); build_error(c, 404, req->keep_alive, head, NULL); return; }

    const char *type = http_mime_type(is_index ? "index.html" : req->path);

    /* Validators, sent with every file response. */
    char etag[96], lastmod[48], extra[384];
    if (http_format_etag(etag, sizeof etag, (unsigned long long)st.st_ino, (long long)st.st_size,
                         (long long)st.st_mtim.tv_sec, st.st_mtim.tv_nsec) < 0 ||
        http_format_date(lastmod, sizeof lastmod, (long long)st.st_mtim.tv_sec) < 0) {
        close(fd);
        build_error(c, 500, 0, head, NULL);
        return;
    }

    /* Conditional GET (RFC 9110 section 13): If-None-Match wins over If-Modified-Since. */
    int not_modified = 0;
    if (req->if_none_match[0]) {
        not_modified = http_etag_matches(req->if_none_match, etag);
    } else if (req->if_modified_since[0]) {
        long long since = http_parse_date(req->if_modified_since);
        not_modified = since >= 0 && (long long)st.st_mtim.tv_sec <= since;
    }
    if (not_modified) {
        close(fd);
        snprintf(extra, sizeof extra, "ETag: %s\r\nLast-Modified: %s\r\n", etag, lastmod);
        int n = http_format_head(c->wbuf, sizeof c->wbuf, 304, NULL, -1, req->keep_alive, extra);
        if (n < 0) { build_error(c, 500, 0, head, NULL); return; }
        c->wlen = (size_t)n;
        c->woff = 0;
        c->keep_alive = req->keep_alive;
        return;
    }

    /* Range (RFC 9110 section 14), one range per request. If-Range makes it conditional on the
     * client still holding this exact version: a strong ETag match, or the exact Last-Modified. */
    int status = 200;
    long long first = 0, last = (long long)st.st_size - 1;
    if (req->range[0]) {
        int use = 1;
        if (req->if_range[0])
            use = req->if_range[0] == '"' ? strcmp(req->if_range, etag) == 0 : strcmp(req->if_range, lastmod) == 0;
        int r = use ? http_parse_range(req->range, (long long)st.st_size, &first, &last) : 0;
        if (r < 0) {
            close(fd);
            char cr[64];
            snprintf(cr, sizeof cr, "Content-Range: bytes */%lld\r\n", (long long)st.st_size);
            build_error(c, 416, req->keep_alive, head, cr);
            return;
        }
        if (r > 0) status = 206;
        else { first = 0; last = (long long)st.st_size - 1; } /* ignored: the whole file */
    }

    int e = snprintf(extra, sizeof extra, "Accept-Ranges: bytes\r\nETag: %s\r\nLast-Modified: %s\r\n", etag,
                     lastmod);
    if (status == 206)
        snprintf(extra + e, sizeof extra - (size_t)e, "Content-Range: bytes %lld-%lld/%lld\r\n", first, last,
                 (long long)st.st_size);
    long long length = last - first + 1;
    int n = http_format_head(c->wbuf, sizeof c->wbuf, status, type, length, req->keep_alive, extra);
    if (n < 0) { close(fd); build_error(c, 500, 0, head, NULL); return; }
    c->wlen = (size_t)n;
    c->woff = 0;
    c->keep_alive = req->keep_alive;
    if (head || length == 0) {
        close(fd);
    } else {
        c->file_fd = fd;
        c->file_off = first;
        c->file_end = last + 1;
    }
}

/* ---------- socket I/O ---------- */

/* Reads until EAGAIN, EOF, or the buffer is full. Returns -1 on error. */
static int conn_read(conn *c) {
    while (c->rlen < RBUF_SIZE) {
        ssize_t n = c->ssl ? tls_read(c->ssl, c->rbuf + c->rlen, RBUF_SIZE - c->rlen)
                           : read(c->fd, c->rbuf + c->rlen, RBUF_SIZE - c->rlen);
        if (n > 0) { c->rlen += (size_t)n; continue; }
        if (n == 0) { c->eof = 1; return 0; }
        if (c->ssl) return n == TLS_WANT ? 0 : -1;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return 0;
}

/* One send of buffered bytes: >0 sent, TLS_WANT if the socket would block, -1 on error. */
static ssize_t conn_send(conn *c, const char *p, size_t n, int more) {
    if (c->ssl) return tls_write(c->ssl, p, n);
    for (;;) {
        /* MSG_MORE lets the kernel coalesce the head with the first file bytes. */
        ssize_t r = send(c->fd, p, n, MSG_NOSIGNAL | (more ? MSG_MORE : 0));
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        return errno == EAGAIN || errno == EWOULDBLOCK ? TLS_WANT : -1;
    }
}

/* TLS file bodies: read a record's worth of the file, encrypt and send it, repeat.
 * Returns 1 when the whole body is sent, 0 if the socket would block, -1 on error. */
static int flush_file_tls(conn *c) {
    while (c->toff < c->tlen || c->file_off < c->file_end) {
        if (c->toff == c->tlen) {
            if (!c->tbuf && !(c->tbuf = malloc(TLS_CHUNK))) return -1;
            size_t want = (size_t)(c->file_end - c->file_off);
            if (want > TLS_CHUNK) want = TLS_CHUNK;
            ssize_t r = pread(c->file_fd, c->tbuf, want, c->file_off);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return -1; /* error, or the file shrank underneath us */
            c->tlen = (size_t)r;
            c->toff = 0;
            c->file_off += r;
        }
        /* A partial or would-block write must be retried with the same bytes: they stay in tbuf. */
        ssize_t n = tls_write(c->ssl, c->tbuf + c->toff, c->tlen - c->toff);
        if (n > 0) { c->toff += (size_t)n; continue; }
        return n == TLS_WANT ? 0 : -1;
    }
    c->tlen = c->toff = 0;
    return 1;
}

/* Returns 1 when the response is fully sent, 0 if the socket would block, -1 on error. */
static int conn_flush(conn *c) {
    while (c->woff < c->wlen) {
        ssize_t n = conn_send(c, c->wbuf + c->woff, c->wlen - c->woff, c->file_fd >= 0);
        if (n > 0) { c->woff += (size_t)n; continue; }
        return n == TLS_WANT ? 0 : -1;
    }
    if (c->ssl && c->file_fd >= 0) {
        int r = flush_file_tls(c);
        if (r <= 0) return r;
    }
    while (c->file_fd >= 0 && c->file_off < c->file_end) {
        size_t chunk = (size_t)(c->file_end - c->file_off);
        if (chunk > SENDFILE_CHUNK) chunk = SENDFILE_CHUNK;
        /* Zero copy: the kernel moves page cache pages straight to the socket. */
        ssize_t n = sendfile(c->fd, c->file_fd, &c->file_off, chunk);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1; /* n == 0 means the file shrank underneath us */
    }
    if (c->file_fd >= 0) { close(c->file_fd); c->file_fd = -1; }
    c->wlen = c->woff = 0;
    return 1;
}

static int parse_status(parse_result pr) {
    switch (pr) {
    case PARSE_TOO_LARGE: return 431;
    case PARSE_URI_TOO_LONG: return 414;
    case PARSE_BAD_VERSION: return 505;
    default: return 400;
    }
}

/*
 * The per connection state machine, run on every readiness event. Because the
 * socket is edge triggered we must keep going until the kernel says EAGAIN;
 * otherwise we would never be woken for data that is already buffered.
 * The loop also handles pipelined requests: several requests may sit in rbuf.
 */
static void conn_handle(worker *w, conn *c) {
    conn_touch(w, c);
    if (c->ssl && !c->handshaked) {
        int r = tls_handshake(c->ssl);
        if (r == TLS_WANT) return; /* idle reaping also covers clients that stall mid handshake */
        if (r < 0) { conn_close(w, c); return; }
        c->handshaked = 1; /* carry on: the first request may already be waiting */
    }
    for (;;) {
        if (c->wlen > 0 || c->file_fd >= 0) {
            int r = conn_flush(c);
            if (r < 0) { conn_close(w, c); return; }
            if (r == 0) return; /* wait for EPOLLOUT */
            w->responses++;
            if (!c->keep_alive) { conn_close(w, c); return; }
        }
        if (!c->eof && c->rlen < RBUF_SIZE && conn_read(c) < 0) { conn_close(w, c); return; }
        if (c->rlen == 0) { if (c->eof) conn_close(w, c); return; }

        http_request req;
        parse_result pr = http_parse_request(c->rbuf, c->rlen, &req);
        if (pr == PARSE_INCOMPLETE) { if (c->eof) conn_close(w, c); return; }
        if (pr != PARSE_OK) {
            build_error(c, parse_status(pr), 0, 0, NULL);
            c->rlen = 0;
            continue;
        }
        c->rlen -= req.header_len;
        memmove(c->rbuf, c->rbuf + req.header_len, c->rlen);
        build_response(c, &req);
    }
}

static void accept_all(worker *w) {
    for (;;) {
        int fd = accept4(w->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK && !w->cfg->quiet) perror("accept4");
            return;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        conn *c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        c->file_fd = -1;
        if (g_tls && !(c->ssl = tls_session(g_tls, fd))) { close(fd); free(c); continue; }
        /* Register for both directions once. With EPOLLET we are only told
         * about transitions, so there is no busy wakeup for a writable socket. */
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = c};
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { close(fd); free(c); continue; }
        lru_push_front(w, c);
        c->last_active = now_ms();
        w->accepted++;
    }
}

static void *worker_main(void *arg) {
    worker *w = arg;
    struct epoll_event events[MAX_EVENTS];
    while (g_running) {
        int n = epoll_wait(w->epfd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL) accept_all(w);
            else conn_handle(w, events[i].data.ptr);
        }
        sweep_idle(w);
    }
    while (w->lru_head) conn_close(w, w->lru_head);
    return NULL;
}

static int make_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) < 0) { close(fd); return -1; }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                               .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, SOMAXCONN) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int server_run(const server_config *cfg) {
    if (!realpath(cfg->root, g_root_real)) { perror(cfg->root); return 1; }
    g_root_len = strlen(g_root_real);
    g_root_fd = open(g_root_real, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_root_fd < 0) { perror(cfg->root); return 1; }
    if (cfg->tls_cert && !(g_tls = tls_context(cfg->tls_cert, cfg->tls_key))) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); /* a peer closing mid sendfile must not kill us */

    worker *workers = calloc((size_t)cfg->threads, sizeof *workers);
    if (!workers) return 1;
    for (int i = 0; i < cfg->threads; i++) {
        worker *w = &workers[i];
        w->id = i;
        w->cfg = cfg;
        w->listen_fd = make_listener(cfg->port);
        w->epfd = epoll_create1(EPOLL_CLOEXEC);
        if (w->listen_fd < 0 || w->epfd < 0) {
            fprintf(stderr, "cserve: cannot listen on port %d: %s\n", cfg->port, strerror(errno));
            return 1;
        }
        /* The listener is level triggered: a burst we do not fully drain is reported again. */
        struct epoll_event ev = {.events = EPOLLIN, .data.ptr = NULL};
        epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->listen_fd, &ev);
    }
    if (!cfg->quiet)
        printf("cserve listening on :%d%s with %d worker%s, serving %s\n", cfg->port, g_tls ? " (TLS)" : "",
               cfg->threads, cfg->threads == 1 ? "" : "s", g_root_real);
    fflush(stdout);

    for (int i = 0; i < cfg->threads; i++)
        pthread_create(&workers[i].tid, NULL, worker_main, &workers[i]);

    unsigned long long accepted = 0, responses = 0;
    for (int i = 0; i < cfg->threads; i++) {
        pthread_join(workers[i].tid, NULL);
        accepted += workers[i].accepted;
        responses += workers[i].responses;
        close(workers[i].listen_fd);
        close(workers[i].epfd);
    }
    if (!cfg->quiet) printf("\ncserve stopped: %llu connections, %llu responses\n", accepted, responses);
    free(workers);
    close(g_root_fd);
    if (g_tls) tls_free_context(g_tls);
    return 0;
}
