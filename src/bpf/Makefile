# Makefile for compiling GUT v1 TC eBPF programs
#
# Requirements:
#   - clang with BPF target support (clang-11+)
#   - kernel headers (/usr/include/linux)
#   - libbpf headers (/usr/include/bpf)
#
# Output: tc_gut_egress.o, xdp_gut_ingress.o (GUT mode, default)
#         tc_gut_egress_quic.o, xdp_gut_ingress_quic.o (QUIC mode)
#         tc_gut_egress_syslog.o, xdp_gut_ingress_syslog.o (Syslog mode)
#         tc_gut_egress_sip.o, xdp_gut_ingress_sip.o (SIP mode)

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

GUT_TARGETS := tc_gut_egress.o xdp_gut_ingress.o
QUIC_TARGETS := tc_gut_egress_quic.o xdp_gut_ingress_quic.o
SYSLOG_TARGETS := tc_gut_egress_syslog.o xdp_gut_ingress_syslog.o
SIP_TARGETS := tc_gut_egress_sip.o xdp_gut_ingress_sip.o
DISPATCHER := xdp_dispatcher.o
TARGETS := $(GUT_TARGETS) $(QUIC_TARGETS) $(SYSLOG_TARGETS) $(SIP_TARGETS) $(DISPATCHER)

.PHONY: all clean debug verify

all: $(TARGETS)

# ── GUT mode (default, simple random UDP) ──
tc_gut_egress.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_GUT -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_GUT -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── QUIC mode ──
tc_gut_egress_quic.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress_quic.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── Syslog mode ──
tc_gut_egress_syslog.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SYSLOG -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress_syslog.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SYSLOG -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── SIP mode ──
tc_gut_egress_sip.o: tc_gut_egress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SIP -c $< -o $@
	$(LLVM_STRIP) -g $@

xdp_gut_ingress_sip.o: xdp_gut_ingress.bpf.c gut_common.h
	$(CLANG) $(BPF_CFLAGS) -DGUT_MODE_SIP -c $< -o $@
	$(LLVM_STRIP) -g $@

# ── XDP dispatcher (multi-peer port router) ──
xdp_dispatcher.o: xdp_dispatcher.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Debug build: enables bpf_debug() → bpf_printk traces visible in trace_pipe.
# Usage: make debug  (then: sudo cat /sys/kernel/debug/tracing/trace_pipe)
debug: BPF_CFLAGS += -DBPF_DEBUG
debug: $(TARGETS)
	rm -f $(TARGETS)

# Verification target - load programs into kernel verifier via bpftool
# Usage: make verify   (requires sudo / CAP_BPF)
verify: $(TARGETS)
	@echo "=== Verifying XDP ingress (GUT) ==="
	sudo bpftool prog load xdp_gut_ingress.o /sys/fs/bpf/gut_verify_xdp type xdp \
	&& echo "xdp_gut_ingress: PASS" || { echo "xdp_gut_ingress: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (GUT) ==="
	sudo bpftool prog load tc_gut_egress.o /sys/fs/bpf/gut_verify_tc \
	&& echo "tc_gut_egress: PASS" || { echo "tc_gut_egress: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP ingress (QUIC) ==="
	sudo bpftool prog load xdp_gut_ingress_quic.o /sys/fs/bpf/gut_verify_xdp type xdp \
	&& echo "xdp_gut_ingress_quic: PASS" || { echo "xdp_gut_ingress_quic: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (QUIC) ==="
	sudo bpftool prog load tc_gut_egress_quic.o /sys/fs/bpf/gut_verify_tc \
	&& echo "tc_gut_egress_quic: PASS" || { echo "tc_gut_egress_quic: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP ingress (Syslog) ==="
	sudo bpftool prog load xdp_gut_ingress_syslog.o /sys/fs/bpf/gut_verify_xdp type xdp \
	&& echo "xdp_gut_ingress_syslog: PASS" || { echo "xdp_gut_ingress_syslog: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (Syslog) ==="
	sudo bpftool prog load tc_gut_egress_syslog.o /sys/fs/bpf/gut_verify_tc \
	&& echo "tc_gut_egress_syslog: PASS" || { echo "tc_gut_egress_syslog: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP ingress (SIP) ==="
	sudo bpftool prog load xdp_gut_ingress_sip.o /sys/fs/bpf/gut_verify_xdp type xdp \
	&& echo "xdp_gut_ingress_sip: PASS" || { echo "xdp_gut_ingress_sip: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp
	@echo "=== Verifying TC egress (SIP) ==="
	sudo bpftool prog load tc_gut_egress_sip.o /sys/fs/bpf/gut_verify_tc \
	&& echo "tc_gut_egress_sip: PASS" || { echo "tc_gut_egress_sip: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_tc
	@echo "=== Verifying XDP dispatcher ==="
	sudo bpftool prog load xdp_dispatcher.o /sys/fs/bpf/gut_verify_xdp type xdp \
	&& echo "xdp_dispatcher: PASS" || { echo "xdp_dispatcher: FAIL"; exit 1; }
	sudo rm -f /sys/fs/bpf/gut_verify_xdp

clean:
	rm -f $(TARGETS)
