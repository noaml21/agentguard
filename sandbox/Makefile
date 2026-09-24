# AgentGuard V2 sandbox build.
# Kept small and readable: one binary from src/, headers in include/.

CC      ?= cc
CSTD    ?= -std=c11
WARN    := -Wall -Wextra -Werror -Wshadow -Wconversion -Wpointer-arith \
           -Wwrite-strings -Wvla
CFLAGS  ?= -O2 -g
CPPFLAGS += -Iinclude
BUILDDIR := build

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(BUILDDIR)/%.o,$(SRC))
BIN := $(BUILDDIR)/agentguard-run

.PHONY: all clean check check-asan

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJ)

$(BUILDDIR)/%.o: src/%.c | $(BUILDDIR)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# ASan/UBSan build in a separate directory, then run the integration tests.
check-asan:
	$(MAKE) clean
	$(MAKE) all CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
	AGENTGUARD_RUN=$(abspath $(BIN)) ASAN_OPTIONS=detect_leaks=1 bash tests/run_tests.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) ASAN_OPTIONS=detect_leaks=1 bash tests/contract_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) ASAN_OPTIONS=detect_leaks=1 python3 tests/tty_test.py
	$(MAKE) clean

check: all
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/run_tests.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/contract_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) python3 tests/tty_test.py

clean:
	rm -rf $(BUILDDIR)
