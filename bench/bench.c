/*
 * bench.c: a closed loop HTTP/1.1 load generator.
 *
 * Each thread holds one keep alive connection and sends the next request as
 * soon as the previous response has been fully read, recording the latency of
 * every request in a per thread histogram (1 microsecond buckets up to 100 ms).
 *
 * usage: bench [-c connections] [-d seconds] [-p port] [-H host] path
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HIST_BUCKETS 100000 /* 1 us each, so 0 to 100 ms; slower requests land in the last bucket */

typedef struct {
    const char *host;
    int port;
    const char *path;
    double deadline;
    uint64_t requests, bytes, errors, non_200;
    uint64_t max_us;
    uint32_t *hist;
    pthread_t tid;
} worker;

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int connect_to(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

/* Reads one full response. Returns the HTTP status, or -1 on error. */
static int read_response(int fd, char *buf, size_t cap, uint64_t *bytes) {
    size_t len = 0;
    char *end = NULL;
    while (!end) {
        if (len == cap - 1) return -1;
        ssize_t n = recv(fd, buf + len, cap - 1 - len, 0);
        if (n <= 0) return -1;
        len += (size_t)n;
        buf[len] = '\0';
        end = strstr(buf, "\r\n\r\n");
    }
    int status = atoi(buf + 9);
    char *cl = strcasestr(buf, "\r\nContent-Length:");
    long long body = cl ? atoll(cl + 17) : 0;
    size_t head = (size_t)(end - buf) + 4;
    long long have = (long long)(len - head);
    *bytes += len;
    while (have < body) {
        ssize_t n = recv(fd, buf, cap, 0);
        if (n <= 0) return -1;
        have += n;
        *bytes += (uint64_t)n;
    }
    return status;
}

static void *run(void *arg) {
    worker *w = arg;
    char req[512], buf[65536];
    int rlen = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", w->path, w->host);
    int fd = connect_to(w->host, w->port);
    while (now() < w->deadline) {
        if (fd < 0) {
            w->errors++;
            usleep(1000);
            fd = connect_to(w->host, w->port);
            continue;
        }
        double t0 = now();
        int status = -1;
        if (send(fd, req, (size_t)rlen, MSG_NOSIGNAL) == rlen)
            status = read_response(fd, buf, sizeof buf, &w->bytes);
        if (status < 0) {
            w->errors++;
            close(fd);
            fd = connect_to(w->host, w->port);
            continue;
        }
        uint64_t us = (uint64_t)((now() - t0) * 1e6);
        if (us > w->max_us) w->max_us = us;
        w->hist[us < HIST_BUCKETS ? us : HIST_BUCKETS - 1]++;
        w->requests++;
        if (status != 200) w->non_200++;
    }
    if (fd >= 0) close(fd);
    return NULL;
}

static double percentile(const uint64_t *hist, uint64_t total, double p) {
    uint64_t target = (uint64_t)(p * (double)total), seen = 0;
    for (int i = 0; i < HIST_BUCKETS; i++) {
        seen += hist[i];
        if (seen > target) return i / 1000.0;
    }
    return HIST_BUCKETS / 1000.0;
}

int main(int argc, char **argv) {
    int conns = 32, secs = 10, port = 8080, opt;
    const char *host = "127.0.0.1";
    while ((opt = getopt(argc, argv, "c:d:p:H:")) != -1) {
        switch (opt) {
        case 'c': conns = atoi(optarg); break;
        case 'd': secs = atoi(optarg); break;
        case 'p': port = atoi(optarg); break;
        case 'H': host = optarg; break;
        default: goto usage;
        }
    }
    if (optind != argc - 1 || conns <= 0 || secs <= 0) {
    usage:
        fprintf(stderr, "usage: %s [-c connections] [-d seconds] [-p port] [-H host] path\n", argv[0]);
        return 2;
    }

    worker *ws = calloc((size_t)conns, sizeof *ws);
    double start = now();
    for (int i = 0; i < conns; i++) {
        ws[i] = (worker){.host = host, .port = port, .path = argv[optind], .deadline = start + secs,
                         .hist = calloc(HIST_BUCKETS, sizeof(uint32_t))};
        pthread_create(&ws[i].tid, NULL, run, &ws[i]);
    }

    uint64_t *hist = calloc(HIST_BUCKETS, sizeof(uint64_t));
    uint64_t reqs = 0, bytes = 0, errs = 0, bad = 0, max_us = 0;
    for (int i = 0; i < conns; i++) {
        pthread_join(ws[i].tid, NULL);
        reqs += ws[i].requests;
        bytes += ws[i].bytes;
        errs += ws[i].errors;
        bad += ws[i].non_200;
        if (ws[i].max_us > max_us) max_us = ws[i].max_us;
        for (int b = 0; b < HIST_BUCKETS; b++) hist[b] += ws[i].hist[b];
        free(ws[i].hist);
    }
    double elapsed = now() - start;
    printf("%d connections, %.1f s, path %s\n", conns, elapsed, argv[optind]);
    printf("  requests     %llu (%llu errors, %llu non 200)\n", (unsigned long long)reqs,
           (unsigned long long)errs, (unsigned long long)bad);
    printf("  throughput   %.0f req/s, %.1f MB/s\n", reqs / elapsed, bytes / elapsed / 1e6);
    printf("  latency ms   p50 %.3f  p90 %.3f  p99 %.3f  max %.3f\n", percentile(hist, reqs, 0.50),
           percentile(hist, reqs, 0.90), percentile(hist, reqs, 0.99), max_us / 1000.0);
    free(hist);
    free(ws);
    return errs || bad ? 1 : 0;
}
