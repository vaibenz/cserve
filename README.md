# cserve

An event driven HTTP/1.1 and HTTPS static file server written from scratch in C for Linux: non blocking sockets, edge triggered `epoll`, one event loop per worker thread, zero copy `sendfile`, and TLS through OpenSSL on the same non blocking loop.

I wanted to see how far one small C program could get on plain Linux primitives, with no framework in between, and then how hard it is to make that program hold up against hostile clients. It's a server I can reason about end to end, from the socket all the way to the bytes on the wire.

On a 2 vCPU cloud VM it serves about 139,000 requests per second for a small page (plain HTTP, keep alive), with the load generator competing for the same two CPUs. The request parser has been fuzzed for over an hour with libFuzzer under ASan and UBSan, with six correctness properties checked on every input, and found nothing.

## What's in it

**HTTP**
* HTTP/1.1 keep alive and pipelining, `GET` and `HEAD`, directory `index.html`, MIME types
* Range requests (`206`, `416`, `If-Range`) and conditional GET (`ETag`, `Last-Modified`, `If-None-Match`, `If-Modified-Since`, `304`)
* A strict, allocation free request parser: bare `CR` or `LF`, duplicate `Host`, conflicting `Content-Length` and any `Transfer-Encoding` are refused, because request smuggling relies on two parsers disagreeing about where a request ends

**Performance**
* Multi reactor design: one `epoll` loop per thread, `SO_REUSEPORT` load balancing, no locks on the hot path
* Zero copy file transfer with `sendfile`, header coalescing with `MSG_MORE`

**TLS**
* TLS 1.2 and 1.3 with OpenSSL, ALPN `http/1.1`, no renegotiation, no compression
* Non blocking handshake, reads and writes driven by the same edge triggered events as plain HTTP

**Hostile clients**
* Kernel enforced path containment with `openat2(RESOLVE_BENEATH)`, so `..` and symlink escapes are refused
* Slowloris: a request head has a deadline that further bytes do not extend, then `408`
* Slow reads: a downloading client must take at least 1 KB/s, measured from what TCP has acknowledged
* A connection cap that evicts the longest idle keep alive connection, and no busy loop when out of file descriptors

**Testing**
* 95 parser unit checks, 49 end to end tests (plain, TLS and attacks), all under AddressSanitizer and UndefinedBehaviorSanitizer
* A libFuzzer harness with property checks, run in CI

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
        │ head FIFO       │        │ head FIFO       │        │ head FIFO       │
        └─────────────────┘        └─────────────────┘        └─────────────────┘
```

Every worker thread owns its listening socket, its epoll instance and its connections. A connection is accepted, parsed and answered on the same thread for its whole life, so no state is shared between threads and no locks are needed.

### Life of a request

1. `epoll_wait` reports the listening socket readable; `accept_all` drains it with `accept4(SOCK_NONBLOCK)` and registers each client for `EPOLLIN | EPOLLOUT | EPOLLET` once. The connection goes on the head FIFO: its first request (and with TLS, the handshake) is now on the clock.
2. On a readiness event, `conn_handle` runs the connection state machine: finish the TLS handshake if needed, flush any pending output, read until `EAGAIN`, parse one request, build the response, and repeat. Repeating is what makes pipelining work, and reading until `EAGAIN` is required with edge triggering because the kernel only signals transitions.
3. Plain HTTP: the response head goes out with `send(MSG_MORE)` and the body with `sendfile`, so file bytes move from the page cache to the socket without passing through user space. TLS: the body is read 16 KB (one record) at a time and encrypted by OpenSSL.
4. If the socket buffer fills, the state is kept and the loop returns. The next `EPOLLOUT` edge resumes exactly where it stopped.

## Design decisions

**Why one epoll loop per thread instead of a thread per connection?** Threads per connection cost a stack and a context switch each, and 10,000 idle keep alive clients would need 10,000 threads. An event loop multiplexes thousands of sockets on one thread and only does work when a socket is ready.

**Why `SO_REUSEPORT` instead of one acceptor thread?** A single acceptor that hands sockets to workers needs a queue and a lock, and becomes a bottleneck. With `SO_REUSEPORT` each worker has its own listening socket and the kernel spreads connections across them, which also avoids the thundering herd of many threads waiting on one socket.

**Why edge triggered?** With level triggering a writable socket would wake the loop on every iteration unless `EPOLLOUT` is constantly added and removed with extra `epoll_ctl` calls. Edge triggering lets each socket be registered once for both directions; the cost is the discipline of always draining to `EAGAIN`.

**How does TLS fit a non blocking loop?** `tls_read` and `tls_write` return `TLS_WANT` instead of blocking, and the loop simply runs the state machine again on the next event. The subtle part is that OpenSSL can need the opposite direction to the one being attempted: a read can need to write (a TLS 1.3 key update), a write can need to read. Because every socket is registered for both directions, either edge resumes it. The other rule is that a write that would block must be retried with exactly the same bytes, so file data stays in a per connection 16 KB buffer until OpenSSL has taken all of it.

**Why `openat2(RESOLVE_BENEATH)`?** Checking for `..` in a string is not enough, because a symlink inside the document root can point anywhere. `RESOLVE_BENEATH` makes the kernel reject any path resolution that leaves the root, atomically and without a race between checking and opening. On kernels older than 5.6 the server falls back to verifying the opened descriptor's real path.

**Why is a range or condition sometimes ignored?** RFC 9110 lets a server answer any `Range` with a full `200`, so a multi range request, another unit, a malformed value or two `Range` headers all get the whole file rather than an error. Ignoring is always safe; guessing is not. The same goes for a date in an obsolete format in `If-Modified-Since`. `ETag`s are strong and built from the inode, size and nanosecond modification time, so rewriting a file with the same size within the same second still changes its tag.

## Defending against hostile clients

An idle timeout alone does not protect a server, because the cheapest attacks are not idle.

**Slowloris** opens many connections and sends each request head one byte at a time. Every byte is activity, so an idle timeout never fires, and the server runs out of connections. Here a request head has its own deadline (`-H`, default 10 s), counted from the connection or from the first byte of a later request, and further bytes do not extend it. Since every deadline is "now plus the same timeout", appending to a FIFO keeps it sorted by deadline, and the sweep only ever looks at its front: no timer heap, O(expired) per sweep.

**Slow reads** are the mirror image: request a large file, then read it a trickle at a time. While a response is going out, events no longer count as activity. Instead, each idle check asks the kernel how many bytes the client has acknowledged (`TCP_INFO`, `tcpi_bytes_acked`) and requires at least 1 KB/s since the last check.

**Running out of connections**: past `-m` connections the longest idle keep alive connection is closed to make room. If even that one is in the middle of a request, the newcomer is refused instead, because closing a busy connection would hand the attacker a way to evict real clients.

**Running out of file descriptors**: the listener is level triggered, so a connection that `accept4` cannot take (`EMFILE`) is reported again at once, forever. Each worker keeps one spare descriptor: it gives it back, accepts and closes the waiting connection, and takes it again.

### Two bugs the tests found

Testing the TLS slow reader turned up a real bug in the idle reaper that predated TLS. A client downloading at around 800 KB/s with a 1 s idle timeout was closed as idle about 4 MB in, every time. The kernel send buffer autotunes to about 4 MB, and `EPOLLOUT` only fires again after a large part of it has drained, so the connection saw no event for longer than the timeout while data was flowing.

My first fix compared the size of the kernel send queue (`SIOCOUTQ`) between checks, and it did not work. The queue is a sawtooth: it fills when `EPOLLOUT` fires, then drains. The check runs one timeout after the last refill, so it kept sampling the same point of the tooth and saw the same size twice, even though the client was reading steadily. Counting acknowledged bytes, which only ever grows, fixed it. Moving the idle clock from seconds to milliseconds fixed a second, smaller problem: a connection touched at x.999 s could expire at x+1.001 s.

Adding the attack tests found the other one. Out of descriptors, `accept4` reports `EMFILE` before it looks at the backlog, so the spare descriptor loop must stop when the backlog is empty, or it spins forever.

Both have regression tests that fail on the old code.

## Fuzzing

```sh
make fuzz FUZZ_TIME=600     # needs clang
```

`fuzz/fuzz_http.c` is a libFuzzer harness built with ASan and UBSan. On top of "does not crash", every input is checked against properties the server depends on:

1. The verdict depends only on the request head: parsing exactly the head, or the head followed by the start of a pipelined request, gives the same result and the same fields.
2. A head is never judged before it is complete: every shorter prefix is `INCOMPLETE`.
3. An accepted request is well formed: absolute, NUL terminated path, HTTP/1.0 or 1.1, a head that ends in CRLFCRLF.
4. `http_path_is_safe` agrees with a separate, deliberately naive implementation of the same rule.
5. Percent decoding round trips.
6. A satisfiable `Range` always lies inside the file, and writing it back out parses to the same range.
7. Any date that parses is canonical: formatting it again gives back the exact input.

Two 30 minute campaigns (38.3 million and 20.9 million inputs, the second after ranges and dates were added) found nothing. CI runs it for 60 s on every push.

## Build and run it

Requires Linux, a C11 compiler, `make` and OpenSSL (`libssl-dev`).

```sh
make
./cserve -p 8080 -r ./www                              # http://localhost:8080
./cserve -p 8443 -r ./www -c cert.pem -k key.pem       # https://localhost:8443
./cserve -h                                            # all options
```

Options: `-t` worker threads, `-i` idle timeout, `-H` request head deadline, `-m` connection cap, `-c`/`-k` certificate and key.

## Tests

```sh
make test          # parser unit tests + end to end tests, both under ASan and UBSan
```

The end to end suite (`tests/test_integration.py`, standard library only) starts the real binary and checks:

* **HTTP**: keep alive, pipelining, requests split across packets, SHA 256 integrity of an 8 MB transfer, 64 concurrent clients, the error statuses, and path traversal attempts including an encoded `%2e%2e` and a symlink out of the root
* **Ranges and conditions**: every range form, unsatisfiable and ignored ranges, `If-None-Match` lists, `If-Modified-Since`, `If-Range`, an `ETag` that changes when only the nanosecond mtime does, and a download resumed over one keep alive connection
* **TLS**: handshake and ALPN, keep alive, pipelining, integrity, a range, a slow reader, 32 concurrent clients, a plaintext client dropped, an h2 only client refused, a stalled handshake reaped
* **Attacks**: Slowloris gets `408` at the deadline, 50 attackers at once do not stop service, eviction and refusal at the cap, a slow reader that is still taking data is kept, a trickle reader is reaped, a stalled reader is reaped, and 100 clients against 64 descriptors

## Benchmarks

```sh
make bench         # or: THREADS=1 CONNS=64 DUR=10 ./bench/run.sh
```

`bench/bench.c` is a closed loop load generator: each thread keeps one connection alive (or with `-n`, opens a new one per request) and records every request's latency in a 1 µs histogram. `-s` speaks TLS, with session resumption off, so `-s -n` measures full handshakes.

Results on a 2 vCPU Linux cloud VM (kernel 6.18), client and server on the same machine, two workers. Plain HTTP, measured before TLS was added, on a quiet machine:

| Workload | Workers | Connections | Throughput | p50 latency |
|---|---|---|---|---|
| 1.4 KB page | 1 | 64 | 77,500 req/s | |
| 1.4 KB page | 2 | 64 | 138,700 req/s | 0.011 ms |
| 1 MB file | 2 | 16 | 3,750 req/s (3.9 GB/s) | 3.9 ms |

With TLS (OpenSSL 3.0), on a shared machine whose speed varied by up to 3x between runs. Each figure is the best of three interleaved 5 s runs, with plain HTTP from the same runs alongside for comparison:

| Workload | Connections | Plain HTTP | TLS |
|---|---|---|---|
| 1.4 KB page, keep alive | 64 | 82,300 req/s | 38,800 req/s |
| 1 MB file | 16 | 3,580 req/s (3.75 GB/s) | 1,260 req/s (1.3 GB/s) |
| New connection per request | 16 | 18,700 req/s | 820 full handshakes/s |

Because the load generator shares the same two CPUs, and for TLS does the same amount of cryptography as the server, these numbers understate what the server can do on dedicated hardware. That matters most for handshakes, where the client's half costs about as much as the server's.

## What I'd do next

* HTTP/2, which would need a different connection model (streams multiplexed on one connection)
* A cache of open file descriptors, saving an `openat2` and `fstat` per request
* kTLS, so the kernel encrypts and `sendfile` works again for HTTPS
* Per client address limits, so one address cannot take every connection slot

## Where things live

```
src/http.c      request parser, ranges, dates, ETags (pure, unit tested and fuzzed)
src/server.c    workers, epoll loop, connection state machine, file serving, defences
src/tls.c       OpenSSL on non blocking sockets
src/main.c      command line options
fuzz/           libFuzzer harness, seed corpus and dictionary
tests/          unit tests (C) and end to end tests (Python)
bench/          load generator and benchmark script
```

---

If something here is unclear, broken, or just wrong, feel free to open an issue. I'm always happy to chat about it.
