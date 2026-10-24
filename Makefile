CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow -pthread
SAN     := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
SRC     := src/main.c src/server.c src/http.c
HDR     := src/http.h src/server.h

.PHONY: all test unit integration bench clean

all: cserve bench/bench

cserve: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

# Same server built with AddressSanitizer and UndefinedBehaviorSanitizer for tests.
cserve-asan: $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SAN) -o $@ $(SRC)

bench/bench: bench/bench.c
	$(CC) $(CFLAGS) -o $@ $<

tests/test_http: tests/test_http.c src/http.c src/http.h
	$(CC) $(CFLAGS) $(SAN) -o $@ tests/test_http.c src/http.c

test: unit integration

unit: tests/test_http
	./tests/test_http

integration: cserve-asan
	python3 tests/test_integration.py ./cserve-asan

bench: cserve bench/bench
	./bench/run.sh

clean:
	rm -f cserve cserve-asan bench/bench tests/test_http
