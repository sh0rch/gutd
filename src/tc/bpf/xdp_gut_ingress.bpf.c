#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "gut_common.h"

char LICENSE[] SEC("license") = "GPL";

#define WG_MIN_PACKET 32

struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tx_devmap SEC(".maps");

static __always_inline __u32 wg_nonce32(const __u8 *wg)
{
    __u32 n0 = (__u32)wg[16] | ((__u32)wg[17] << 8) | ((__u32)wg[18] << 16) | ((__u32)wg[19] << 24);
    __u32 n1 = (__u32)wg[20] | ((__u32)wg[21] << 8) | ((__u32)wg[22] << 16) | ((__u32)wg[23] << 24);
    __u32 n2 = (__u32)wg[24] | ((__u32)wg[25] << 8) | ((__u32)wg[26] << 16) | ((__u32)wg[27] << 24);
    __u32 n3 = (__u32)wg[28] | ((__u32)wg[29] << 8) | ((__u32)wg[30] << 16) | ((__u32)wg[31] << 24);
    return n0 ^ n1 ^ n2 ^ n3;
}

static __always_inline void xor16(__u8 *p, const __u8 *k)
{
#pragma unroll
    for (int i = 0; i < 16; i++)
        p[i] ^= k[i];
}

static __always_inline int gut_xdp_core(struct xdp_md *ctx)
{
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    __u32 zero = 0;
    struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return -1;

    struct gut_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (!stats)
        return -1;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u32 ip_off = 14;
    __u32 udp_off;
    __u8 ipver;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph + 1) > data_end)
            return -1;
        if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
            return -1;
        udp_off = ip_off + 20;
        ipver = 4;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        if ((void *)(ip6h + 1) > data_end)
            return -1;
        if (ip6h->nexthdr != IPPROTO_UDP)
            return -1;
        udp_off = ip_off + 40;
        ipver = 6;
    }
    else
    {
        return -1;
    }

    struct udphdr *udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return -1;

    __u16 dst_port = bpf_ntohs(udph->dest);
    if (!is_gut_port(dst_port, cfg))
        return -1;

    __u16 udp_len = bpf_ntohs(udph->len);
    if (udp_len < 8 + WG_MIN_PACKET + GUT_L4_META_SIZE)
        return -1;

    __u32 wg_off = udp_off + 8;
    __u32 wg_len = udp_len - 8;
    __u8 *wg = (__u8 *)data + wg_off;
    if (wg + wg_len > (__u8 *)data_end)
        return -1;
    if (wg + WG_MIN_PACKET > (__u8 *)data_end)
        return -1;

    __u32 nonce = wg_nonce32(wg);
    __u32 ks0[16];
    chacha_block(ks0, cfg->chacha_init, 0, nonce);
    const __u8 *ks0b = (const __u8 *)ks0;
    xor16(wg, (const __u8 *)ks0);

    __u8 wg_type = wg[0] & 0x1F;
    __u32 ballast_len = wg[1];
    wg[1] = 0;

    if (wg_type == 1 && wg_len >= 148 && wg + 148 <= (__u8 *)data_end)
    {
        xor16(wg + 132, ks0b + 16);
    }
    else if (wg_type == 2 && wg_len >= 92 && wg + 92 <= (__u8 *)data_end)
    {
        xor16(wg + 76, ks0b + 16);
    }

    if (ballast_len > 63 || ballast_len > wg_len)
        return -1;

    __u32 tail_total = ballast_len + GUT_L4_META_SIZE;
    if (wg_len < tail_total || wg_len - tail_total < WG_MIN_PACKET)
        return -1;

    __u32 meta_off = wg_len - tail_total;
    FORCE_BOUNDS_CHECK(meta_off, MAX_PACKET_SIZE);
    __u8 *meta = wg + meta_off;
    if (meta + GUT_L4_META_SIZE > (__u8 *)data_end)
        return -1;
    __u16 src_port = ((__u16)(meta[0] ^ ks0b[0]) << 8) | (__u16)(meta[1] ^ ks0b[1]);
    __u16 dst_port_inner = ((__u16)(meta[2] ^ ks0b[2]) << 8) | (__u16)(meta[3] ^ ks0b[3]);
    udph->source = bpf_htons(src_port);
    udph->dest = bpf_htons(dst_port_inner);

    __u16 new_udp_len = (__u16)(udp_len - tail_total);
    udph->len = bpf_htons(new_udp_len);

    if (ipver == 4)
    {
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        iph->tot_len = bpf_htons((__u16)(20 + new_udp_len));
        if (cfg->tun_peer_ip4 && cfg->tun_local_ip4)
        {
            iph->saddr = cfg->tun_peer_ip4;  /* looks like it came from gut0 peer */
            iph->daddr = cfg->tun_local_ip4; /* addressed to local gut0 IP */
        }
    }
    else
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        ip6h->payload_len = bpf_htons(new_udp_len);
        /* rewrite only if tun IPv6 are configured (check first word non-zero) */
        __u32 tun_peer6_w0, tun_local6_w0;
        __builtin_memcpy(&tun_peer6_w0, cfg->tun_peer_ip6, 4);
        __builtin_memcpy(&tun_local6_w0, cfg->tun_local_ip6, 4);
        if (tun_peer6_w0 && tun_local6_w0)
        {
            __builtin_memcpy(&ip6h->saddr, cfg->tun_peer_ip6, 16);
            __builtin_memcpy(&ip6h->daddr, cfg->tun_local_ip6, 16);
        }
    }

    if (tail_total > 0)
    {
        if (bpf_xdp_adjust_tail(ctx, -(int)tail_total) < 0)
        {
            stats->packets_dropped++;
            return -1;
        }
        data = (void *)(__u64)ctx->data;
        data_end = (void *)(__u64)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return -1;
    }

    data = (void *)(__u64)ctx->data;
    data_end = (void *)(__u64)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u32 inner_new_len = (ipver == 6) ? (40 + (__u32)new_udp_len) : (20 + (__u32)new_udp_len);
    if ((__u8 *)data + ip_off + inner_new_len > (__u8 *)data_end)
        return -1;

    if (ipver == 4)
    {
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        struct udphdr *udp = (void *)((__u8 *)data + udp_off);
        if ((void *)(iph + 1) > data_end || (void *)(udp + 1) > data_end)
            return -1;

        iph->check = 0;
        __u64 ip_csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0);
        iph->check = csum_fold(ip_csum);

        udp->check = 0;
    }
    else
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        struct udphdr *udp = (void *)((__u8 *)data + udp_off);
        if ((void *)(ip6h + 1) > data_end || (void *)(udp + 1) > data_end)
            return -1;

        udp->check = 0;
    }

    __builtin_memcpy(eth->h_dest, cfg->tun_mac, 6);
    __builtin_memcpy(eth->h_source, cfg->src_mac, 6);
    eth->h_proto = bpf_htons(ipver == 6 ? ETH_P_IPV6 : ETH_P_IP);

    stats->mask_count++;
    stats->packets_processed++;
    stats->bytes_processed += (__u64)((__u8 *)data_end - (__u8 *)data);

    return 0;
}

SEC("xdp")
int xdp_gut_ingress(struct xdp_md *ctx)
{
    if (gut_xdp_core(ctx) != 0)
    {
        __u32 zero = 0;
        struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
        if (cfg && cfg->default_xdp_action == 1)
            return XDP_DROP;
        return XDP_PASS;
    }

    __u32 zero = 0;
    return bpf_redirect_map(&tx_devmap, zero, 0);
}

SEC("xdp")
int xdp_veth_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}
