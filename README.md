# cserve

An event driven HTTP/1.1 static file server written from scratch in C for Linux, using non blocking sockets, edge triggered `epoll`, one event loop per worker thread, and zero copy `sendfile`.

On a 2 vCPU cloud VM it serves about **139,000 requests per second** for a small page, with the load generator competing for the same two CPUs, and throughput scales **1.87x** going from one worker to two.

## Features

* HTTP/1.1 persistent connections (keep alive) and request pipelining
* `GET` and `HEAD`, directory `index.html`, MIME types, `Date` header
* Multi reactor design: one `epoll` loop per thread, `SO_REUSEPORT` load balancing, no locks on the hot path
* Zero copy file transfer with `sendfile`, header coalescing with `MSG_MORE`
* Kernel enforced path containment with `openat2(RESOLVE_BENEATH)`, so `..` and symlink escapes are refused
* Strict, allocation free request parser with limits on header size (431) and URI length (414)
* Idle connection reaping in O(expired) using a per worker LRU list
* Graceful shutdown on `SIGINT` / `SIGTERM`
* 61 parser unit tests and 17 end to end tests, all run under AddressSanitizer and UndefinedBehaviorSanitizer

## Architecture

```
                        kernel (SO_REUSEPORT hashes each new connection to one listener)
                 ┌──────────────────────────┬──────────────────────────┐
                 ▼                          ▼                          ▼
        ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
        │ worker 0        │        │ worker 1        │        │ worker N        │
        │ listen socket   │        │ listen socket   │  ...   │ listen socket   │
        │ epoll instance  │        │ epoll instance  │        │ epoll instance  │
        │ connection LRU  │        │ connection LRU  │        │ connection LRU  │
        └─────────────────┘        └─────────────────┘        └─────────────────┘
```

Every worker thread owns its listening socket, its epoll instance and its connections. A connection is accepted, parsed and answered on the same thread for its whole life, so no state is shared between threads and no locks are needed.

### Life of a request

1. `epoll_wait` reports the listening socket readable; `accept_all` drains it with `accept4(SOCK_NONBLOCK)` and registers each client for `EPOLLIN | EPOLLOUT | EPOLLET` once.
2. On a readiness event, `conn_handle` runs the connection state machine:
   flush any pending output, read until `EAGAIN`, parse one request, build the response, and repeat. Repeating is what makes pipelining work, and reading until `EAGAIN` is required with edge triggering because the kernel only signals transitions.
3. The response head goes out with `send(MSG_MORE)` and the body with `sendfile`, so file bytes move from the page cache to the socket without passing through user space.
4. If the socket buffer fills, the state is kept and the loop returns. The next `EPOLLOUT` edge resumes exactly where it stopped.

## Design decisions

**Why one epoll loop per thread instead of a thread per connection?** Threads per connection cost a stack and a context switch each, and 10,000 idle keep alive clients would need 10,000 threads. An event loop multiplexes thousands of sockets on one thread and only does work when a socket is ready.

**Why `SO_REUSEPORT` instead of one acceptor thread?** A single acceptor that hands sockets to workers needs a queue and a lock, and becomes a bottleneck. With `SO_REUSEPORT` each worker has its own listening socket and the kernel spreads connections across them, which also avoids the thundering herd problem of many threads waiting on one socket.

**Why edge triggered?** With level triggering a writable socket would wake the loop on every iteration unless `EPOLLOUT` is constantly added and removed with extra `epoll_ctl` calls. Edge triggering lets each socket be registered once for both directions; the cost is the discipline of always draining to `EAGAIN`.

**Why `openat2(RESOLVE_BENEATH)`?** Checking for `..` in a string is not enough, because a symlink inside the document root can point anywhere. `RESOLVE_BENEATH` makes the kernel reject any path resolution that leaves the root, atomically and without a race between checking and opening. On kernels older than 5.6 the server falls back to verifying the opened descriptor's real path.

**Why a strict parser?** Bare `CR` or `LF`, duplicate `Host` or conflicting `Content-Length` headers are rejected, because request smuggling attacks rely on two parsers disagreeing about where a request ends. A static file server does not need request bodies, so `Transfer-Encoding` is refused outright.

## Build and run

Requires Linux, a C11 compiler and `make`.

```sh
make
./cserve -p 8080 -r ./www          # then open http://localhost:8080
./cserve -h                        # all options: port, root, threads, idle timeout
```

## Tests

```sh
make test          # parser unit tests + end to end tests, both under ASan and UBSan
```

The end to end suite (`tests/test_integration.py`, standard library only) starts the real binary and checks keep alive across 200 requests, pipelining, requests split across packets, slow readers forcing `EAGAIN` on a large file, SHA 256 integrity of an 8 MB transfer, 64 concurrent clients, idle reaping, the main error statuses, and four path traversal attempts including an encoded `%2e%2e` and a symlink pointing outside the root.

## Benchmarks

```sh
make bench         # or: THREADS=1 CONNS=64 DUR=10 ./bench/run.sh
```

`bench/bench.c` is a closed loop load generator: each thread keeps one connection alive and records every request's latency in a 1 µs histogram.

Results on a 2 vCPU Linux cloud VM (kernel 6.18), client and server on the same machine:

| Workload | Workers | Connections | Throughput | p50 latency |
|---|---|---|---|---|
| 1.4 KB page | 1 | 64 | 77,500 req/s | |
| 1.4 KB page | 2 | 64 | 138,700 req/s | 0.011 ms |
| 1 MB file | 2 | 16 | 3,750 req/s (3.9 GB/s) | 3.9 ms |

Because the load generator shares the same two CPUs, these numbers understate what the server can do on dedicated hardware.

## Limitations and next steps

* No TLS; in production it would sit behind a TLS terminating proxy
* No range requests, compression or conditional `If-Modified-Since` responses yet
* `accept4` failing with `EMFILE` is logged but not rate limited
* A file cache of open descriptors would save an `openat2` and `fstat` per request

## Layout

```
src/http.c      request parser and response helpers (pure, unit tested)
src/server.c    workers, epoll loop, connection state machine, file serving
src/main.c      command line options
tests/          unit tests (C) and end to end tests (Python)
bench/          load generator and benchmark script
```
