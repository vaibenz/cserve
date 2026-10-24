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
 */
#include "server.h"
#include "http.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
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

typedef struct conn {
    int fd;
    int file_fd;               /* file being streamed, or -1 */
    off_t file_off, file_end;
    size_t rlen;               /* bytes buffered in rbuf */
    size_t wlen, woff;         /* response head (or small error body) in wbuf */
    int keep_alive;            /* keep the connection after the current response */
    int eof;                   /* peer has closed its write side */
    time_t last_active;
    struct conn *prev, *next;  /* LRU list, most recently active first */
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
static int g_root_fd = -1;
static char g_root_real[PATH_MAX];
static size_t g_root_len;

static void on_signal(int sig) { (void)sig; g_running = 0; }

static time_t now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
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
    c->last_active = now_sec();
    if (w->lru_head != c) { lru_unlink(w, c); lru_push_front(w, c); }
}

static void conn_close(worker *w, conn *c) {
    lru_unlink(w, c);
    if (c->file_fd >= 0) close(c->file_fd);
    close(c->fd); /* also removes it from the epoll set */
    free(c);
}

/* Idle connections sit at the tail, so this is O(number expired). */
static void sweep_idle(worker *w) {
    time_t now = now_sec();
    while (w->lru_tail && now - w->lru_tail->last_active >= w->cfg->idle_timeout_sec)
        conn_close(w, w->lru_tail);
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
    int n = http_format_head(c->wbuf, sizeof c->wbuf, 200, type, (long long)st.st_size,
                             req->keep_alive, NULL);
    if (n < 0) { close(fd); build_error(c, 500, 0, head, NULL); return; }
    c->wlen = (size_t)n;
    c->woff = 0;
    c->keep_alive = req->keep_alive;
    if (head || st.st_size == 0) {
        close(fd);
    } else {
        c->file_fd = fd;
        c->file_off = 0;
        c->file_end = st.st_size;
    }
}

/* ---------- socket I/O ---------- */

/* Reads until EAGAIN, EOF, or the buffer is full. Returns -1 on error. */
static int conn_read(conn *c) {
    while (c->rlen < RBUF_SIZE) {
        ssize_t n = read(c->fd, c->rbuf + c->rlen, RBUF_SIZE - c->rlen);
        if (n > 0) { c->rlen += (size_t)n; continue; }
        if (n == 0) { c->eof = 1; return 0; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return 0;
}

/* Returns 1 when the response is fully sent, 0 if the socket would block, -1 on error. */
static int conn_flush(conn *c) {
    while (c->woff < c->wlen) {
        /* MSG_MORE lets the kernel coalesce the head with the first file bytes. */
        int flags = MSG_NOSIGNAL | (c->file_fd >= 0 ? MSG_MORE : 0);
        ssize_t n = send(c->fd, c->wbuf + c->woff, c->wlen - c->woff, flags);
        if (n > 0) { c->woff += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
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
        /* Register for both directions once. With EPOLLET we are only told
         * about transitions, so there is no busy wakeup for a writable socket. */
        struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = c};
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { close(fd); free(c); continue; }
        lru_push_front(w, c);
        c->last_active = now_sec();
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
        printf("cserve listening on :%d with %d worker%s, serving %s\n", cfg->port, cfg->threads,
               cfg->threads == 1 ? "" : "s", g_root_real);
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
    return 0;
}
