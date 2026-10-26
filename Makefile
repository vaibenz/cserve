CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow -pthread
SAN     := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
SRC     := src/main.c src/server.c src/http.c src/tls.c
HDR     := src/http.h src/server.h src/tls.h
LIBS    := -lssl -lcrypto

.PHONY: all test unit integration bench fuzz clean

all: cserve bench/bench

cserve: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

# Same server built with AddressSanitizer and UndefinedBehaviorSanitizer for tests.
cserve-asan: $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SAN) -o $@ $(SRC) $(LIBS)

bench/bench: bench/bench.c
	$(CC) $(CFLAGS) -o $@ $<

tests/test_http: tests/test_http.c src/http.c src/http.h
	$(CC) $(CFLAGS) $(SAN) -o $@ tests/test_http.c src/http.c

test: unit integration

unit: tests/test_http
	./tests/test_http

integration: cserve-asan
	python3 tests/test_integration.py ./cserve-asan

# Coverage guided fuzzing with libFuzzer (needs clang): make fuzz FUZZ_TIME=60
FUZZ_TIME ?= 60
fuzz/fuzz_http: fuzz/fuzz_http.c src/http.c src/http.h
	clang -std=c11 -D_GNU_SOURCE -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
		-o $@ fuzz/fuzz_http.c src/http.c

fuzz: fuzz/fuzz_http
	mkdir -p fuzz/work
	./fuzz/fuzz_http -max_total_time=$(FUZZ_TIME) -dict=fuzz/http.dict -max_len=4096 -print_final_stats=1 \
		fuzz/work fuzz/corpus

bench: cserve bench/bench
	./bench/run.sh

clean:
	rm -f cserve cserve-asan bench/bench tests/test_http fuzz/fuzz_http
