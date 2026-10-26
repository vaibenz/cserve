#include "server.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [-p port] [-r root] [-t threads] [-i idle_sec] [-H header_sec] [-m max_conns]\n"
            "       [-c cert.pem -k key.pem] [-q]\n"
            "  -p  port to listen on (default 8080)\n"
            "  -r  directory to serve (default ./www)\n"
            "  -t  worker threads, each with its own epoll loop (default: CPU count)\n"
            "  -i  seconds before an idle keep alive connection is closed (default 30)\n"
            "  -H  seconds a client has to send a complete request head, counted from\n"
            "      the connection (with TLS, the handshake too) or from the first byte\n"
            "      of a later request; then 408 and close (default 10)\n"
            "  -m  most open connections; past it the longest idle keep alive one is\n"
            "      closed to make room, or the new one refused (default 10000)\n"
            "  -c  PEM certificate chain, and with -k serve HTTPS (TLS 1.2 or newer)\n"
            "  -k  PEM private key for -c\n"
            "  -q  quiet, no startup or shutdown output\n",
            prog);
}

int main(int argc, char **argv) {
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    server_config cfg = {.root = "./www", .port = 8080, .threads = cpus > 0 ? (int)cpus : 1,
                         .idle_timeout_sec = 30, .header_timeout_sec = 10, .max_conns = 10000,
                         .quiet = 0};
    int opt;
    while ((opt = getopt(argc, argv, "p:r:t:i:H:m:c:k:qh")) != -1) {
        switch (opt) {
        case 'p': cfg.port = atoi(optarg); break;
        case 'r': cfg.root = optarg; break;
        case 't': cfg.threads = atoi(optarg); break;
        case 'i': cfg.idle_timeout_sec = atoi(optarg); break;
        case 'H': cfg.header_timeout_sec = atoi(optarg); break;
        case 'm': cfg.max_conns = atoi(optarg); break;
        case 'c': cfg.tls_cert = optarg; break;
        case 'k': cfg.tls_key = optarg; break;
        case 'q': cfg.quiet = 1; break;
        default: usage(argv[0]); return opt == 'h' ? 0 : 2;
        }
    }
    if (cfg.port <= 0 || cfg.port > 65535 || cfg.threads <= 0 || cfg.threads > 1024 ||
        cfg.idle_timeout_sec <= 0 || cfg.header_timeout_sec <= 0 || cfg.max_conns <= 0 ||
        !cfg.tls_cert != !cfg.tls_key) {
        usage(argv[0]);
        return 2;
    }
    return server_run(&cfg);
}
