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
DEP := $(OBJ:.o=.d)
BIN := $(BUILDDIR)/agentguard-run

.PHONY: all clean check check-asan

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJ)

# -MMD -MP generates per-object header dependency files so a header change
# rebuilds every dependent object (avoids stale-object ABI mismatches).
$(BUILDDIR)/%.o: src/%.c | $(BUILDDIR)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

-include $(DEP)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# ASan/UBSan build in a separate directory: never clean the normal build or
# caller-owned build output, and use the same suite list as the normal gate.
check-asan:
	ASAN_OPTIONS=detect_leaks=1 $(MAKE) check BUILDDIR=build/asan \
	    CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

check: all
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/run_tests.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/contract_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/landlock_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/seccomp_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/network_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/resource_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/policy_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) bash tests/hostipc_test.sh
	AGENTGUARD_RUN=$(abspath $(BIN)) python3 tests/hostipc_extended_test.py
	AGENTGUARD_RUN=$(abspath $(BIN)) python3 tests/tty_test.py

clean:
	rm -rf $(BUILDDIR)
