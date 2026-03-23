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

QUIC_TARGETS := tc_gut_egress.o xdp_gut_ingress.o
GOST_TARGETS := tc_gut_egress_gost.o xdp_gut_ingress_gost.o
SYSLOG_TARGETS := tc_gut_egress_syslog.o xdp_gut_ingress_syslog.o
TARGETS := $(QUIC_TARGETS) $(GOST_TARGETS) $(SYSLOG_TARGETS)

.PHONY: all clean debug verify

all: $(TARGETS)

# ── QUIC mode (default) ──
tc_gut_egress.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── Gost mode ──
tc_gut_egress_gost.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_GOST -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress_gost.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_GOST -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── Syslog mode ──
tc_gut_egress_syslog.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SYSLOG -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress_syslog.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SYSLOG -c $< -o $@
	$(LLVM_STRIP) -g $@

# Debug build: enables bpf_debug() → bpf_printk traces visible in trace_pipe.
# Usage: make debug  (then: sudo cat /sys/kernel/debug/tracing/trace_pipe)
debug: BPF_CFLAGS += -DBPF_DEBUG
debug: $(TARGETS)
	rm -f $(TARGETS)

# Verification target - load programs into kernel verifier via bpftool
# Usage: make verify   (requires sudo / CAP_BPF)
verify: $(TARGETS)
	@echo "=== Verifying XDP ingress (QUIC) ==="
	sudo bpftool prog load xdp_gut_ingress.o /sys/fs/bpf/gut_verify_xdp type xdp \
		&& echo "xdp_gut_ingress: PASS" || { echo "xdp_gut_ingress: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (QUIC) ==="
	sudo bpftool prog load tc_gut_egress.o /sys/fs/bpf/gut_verify_tc \
		&& echo "tc_gut_egress: PASS" || { echo "tc_gut_egress: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP ingress (Gost) ==="
	sudo bpftool prog load xdp_gut_ingress_gost.o /sys/fs/bpf/gut_verify_xdp type xdp \
		&& echo "xdp_gut_ingress_gost: PASS" || { echo "xdp_gut_ingress_gost: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (Gost) ==="
	sudo bpftool prog load tc_gut_egress_gost.o /sys/fs/bpf/gut_verify_tc \
		&& echo "tc_gut_egress_gost: PASS" || { echo "tc_gut_egress_gost: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP ingress (Syslog) ==="
	sudo bpftool prog load xdp_gut_ingress_syslog.o /sys/fs/bpf/gut_verify_xdp type xdp \
		&& echo "xdp_gut_ingress_syslog: PASS" || { echo "xdp_gut_ingress_syslog: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (Syslog) ==="
	sudo bpftool prog load tc_gut_egress_syslog.o /sys/fs/bpf/gut_verify_tc \
		&& echo "tc_gut_egress_syslog: PASS" || { echo "tc_gut_egress_syslog: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
