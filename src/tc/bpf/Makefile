# Makefile for compiling GUT v1 TC eBPF programs
#
# Requirements:
#   - clang with BPF target support (clang-11+)
#   - kernel headers (/usr/include/linux)
#   - libbpf headers (/usr/include/bpf)
#
# Output: tc_gut_egress.o, xdp_gut_ingress.o

CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# BPF target architecture (x86_64, aarch64, etc.)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-D__BPF_TRACING__ \
	-I/usr/include \
	-I/usr/include/$(shell uname -m)-linux-gnu

# Check for kernel headers
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
ifeq ($(wildcard $(KERNEL_HEADERS)),)
	KERNEL_HEADERS := /lib/modules/$(shell uname -r)/build
endif

ifneq ($(wildcard $(KERNEL_HEADERS)),)
	BPF_CFLAGS += -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/arch/$(ARCH)/include
endif

# Disable some warnings that are common in eBPF code
BPF_CFLAGS += -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

TARGETS := tc_gut_egress.o xdp_gut_ingress.o

.PHONY: all clean

all: $(TARGETS)

tc_gut_egress.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(TARGETS)

# Verification target - use bpftool to verify loaded programs
verify: $(TARGETS)
	@echo "BPF object files compiled successfully"
	@for obj in $(TARGETS); do \
		echo "=== $$obj ==="; \
		llvm-objdump -d $$obj | head -20; \
	done
