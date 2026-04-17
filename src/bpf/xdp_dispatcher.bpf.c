/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP Dispatcher — routes incoming packets to the correct per-peer
 * XDP ingress program based on UDP destination port.
 *
 * Architecture:
 *   NIC → xdp_dispatcher (this file)
 *           │  parse UDP dst_port
 *           │  port_map[dst_port] → peer_idx
 *           └─ tail-call xdp_peer_progs[peer_idx]
 *                 └─ peer's xdp_gut_ingress (mode-specific .o)
 *
 * Non-UDP and non-GUT packets pass through (XDP_PASS).
 * If tail-call fails (should never happen), default_xdp_action applies.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifdef BPF_DEBUG
#define bpf_debug(fmt, ...) bpf_printk("DISP: " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) \
    do                      \
    {                       \
    } while (0)
#endif

char LICENSE[] SEC("license") = "GPL";

#define MAX_PEERS 8

/* port_map: UDP dst_port (host order) → peer_idx in xdp_peer_progs.
 * Populated by Rust loader when each peer is registered. */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64); /* 8 peers × up to 6 ports each */
    __type(key, __u16);      /* dst_port (host order) */
    __type(value, __u32);    /* peer_idx */
} port_map SEC(".maps");

/* Per-peer XDP ingress programs.  Loader inserts each peer's
 * xdp_gut_ingress prog FD at xdp_peer_progs[peer_idx]. */
struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_PEERS);
    __type(key, __u32);
    __type(value, __u32);
} xdp_peer_progs SEC(".maps");

SEC("xdp")
int xdp_dispatch(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    __u32 ip_off = sizeof(*eth);

    /* VLAN (802.1Q) */
    if (proto == bpf_htons(ETH_P_8021Q))
    {
        if ((void *)((char *)data + ip_off + 4) > data_end)
            return XDP_PASS;
        proto = *(__be16 *)((char *)data + ip_off + 2);
        ip_off += 4;
    }

    __u32 udp_off;

    if (proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = (void *)((char *)data + ip_off);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        if (iph->protocol != IPPROTO_UDP)
            return XDP_PASS;
        udp_off = ip_off + (iph->ihl * 4);
    }
    else if (proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = (void *)((char *)data + ip_off);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        udp_off = ip_off + 40;
    }
    else
    {
        return XDP_PASS;
    }

    struct udphdr *udp = (void *)((char *)data + udp_off);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dst_port = bpf_ntohs(udp->dest);

    __u32 *peer_idx = bpf_map_lookup_elem(&port_map, &dst_port);
    if (!peer_idx)
    {
        bpf_debug("port %u not in port_map", dst_port);
        return XDP_PASS; /* not a GUT port — pass to kernel */
    }

    bpf_debug("port %u → peer_idx %u, tail-call", dst_port, *peer_idx);
    bpf_tail_call(ctx, &xdp_peer_progs, *peer_idx);

    /* Tail-call failed (should not happen) — pass to kernel */
    bpf_debug("tail-call FAILED for peer_idx %u", *peer_idx);
    return XDP_PASS;
}
