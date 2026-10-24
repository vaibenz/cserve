#ifndef CSERVE_SERVER_H
#define CSERVE_SERVER_H

typedef struct {
    const char *root;      /* directory to serve */
    int port;
    int threads;           /* number of worker event loops */
    int idle_timeout_sec;  /* close keep alive connections idle this long */
    int quiet;
} server_config;

/* Runs until SIGINT or SIGTERM. Returns 0 on clean shutdown. */
int server_run(const server_config *cfg);

#endif
