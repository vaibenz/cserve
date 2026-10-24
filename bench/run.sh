#!/usr/bin/env bash
# Benchmarks cserve with the bundled load generator.
# Override with env vars: THREADS, CONNS, DUR, PORT.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-18080}
THREADS=${THREADS:-$(nproc)}
CONNS=${CONNS:-64}
DUR=${DUR:-10}

root=$(mktemp -d)
head -c 1024 /dev/urandom | base64 > "$root/index.html"     # ~1.4 KB page
head -c 1048576 /dev/urandom > "$root/1mb.bin"               # 1 MB file

./cserve -p "$PORT" -r "$root" -t "$THREADS" -q &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -rf "$root"' EXIT
sleep 0.5

echo "cserve with $THREADS worker threads on $(nproc) CPUs"
echo
echo "Small file (keep alive, $CONNS connections)"
./bench/bench -c "$CONNS" -d "$DUR" -p "$PORT" /index.html
echo
echo "1 MB file (sendfile, 16 connections)"
./bench/bench -c 16 -d "$DUR" -p "$PORT" /1mb.bin
