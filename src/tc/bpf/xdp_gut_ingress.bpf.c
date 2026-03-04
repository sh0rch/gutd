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

static __always_inline int gut_xdp_core(struct xdp_md *ctx, struct gut_config *cfg)
{
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    __u32 zero = 0;
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
    if (udp_len < 8 + WG_MIN_PACKET)
        return -1;

    __u32 wg_off = udp_off + 8;
    __u32 wg_len = udp_len - 8;
    __u8 *wg = (__u8 *)data + wg_off;
    if (wg_len < WG_MIN_PACKET || wg + WG_MIN_PACKET > (__u8 *)data_end || wg + wg_len > (__u8 *)data_end)
        return -1;

    __u32 quic_hdr_len = 0;
    if (wg[0] == 0x40)
    {
        quic_hdr_len = GUT_QUIC_SHORT_HEADER_SIZE;
    }
    else if (wg[0] >= 0xC0)
    {
        if (!is_quic_server(cfg))
            return -1; // Client does not accept Long Headers
        quic_hdr_len = GUT_QUIC_LONG_HEADER_SIZE;
    }
    else
    {
        return -1;
    }

    __u32 pad_len = wg[quic_hdr_len - 1] & 0x3F;
    pad_len |= 1;
    __u32 ballast_len = pad_len;

    wg += quic_hdr_len;
    wg_len -= quic_hdr_len;

    if (wg + WG_MIN_PACKET > (__u8 *)data_end)
        return -1;

    __u32 nonce = wg_nonce32(wg);
    __u32 ks0[16];
    chacha_block(ks0, cfg->chacha_init, 0, nonce);

    __u32 ks47[16];
    chacha_block(ks47, cfg->chacha_init, 47, nonce);

    xor16(wg, (const __u8 *)ks47);
    __u8 wg_type = wg[0] & 0x1F;

    __u32 wg_idx = 0;
    if (wg_type == 1)
    {
        __builtin_memcpy(&wg_idx, wg + 4, 4);
    }
    else
    {
        __builtin_memcpy(&wg_idx, wg + 8, 4);
    }

    __u32 expected_dcid = feistel32(wg_idx, cfg->feistel_rk);
    __u32 expected_ppn = ks47[10];

    __u8 *quic = wg - quic_hdr_len;
    if (quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE)
    {
        __u32 pkt_dcid = 0;
        __builtin_memcpy(&pkt_dcid, quic + 1, 4);
        if (pkt_dcid != expected_dcid)
            return -1;

        __u32 pkt_ppn = 0;
        __builtin_memcpy(&pkt_ppn, quic + 5, 4);
        if (pkt_ppn != expected_ppn)
            return -1;
    }
    else
    {
        __u32 pkt_dcid = 0;
        __builtin_memcpy(&pkt_dcid, quic + 6, 4);
        if (pkt_dcid != expected_dcid)
            return -1;

        __u32 pkt_ppn = 0;
        __builtin_memcpy(&pkt_ppn, quic + 26, 4);
        if (pkt_ppn != expected_ppn)
            return -1;
    }

    if (wg_type == 1 && wg_len >= 148 && wg + 148 <= (__u8 *)data_end)
    {
        xor16(wg + 132, (const __u8 *)ks47 + 16);
    }
    else if (wg_type == 2 && wg_len >= 92 && wg + 92 <= (__u8 *)data_end)
    {
        xor16(wg + 76, (const __u8 *)ks47 + 16);
    }

    if (ballast_len > 63 || ballast_len > wg_len)
        return -1;

    __u32 tail_total = ballast_len;
    if (wg_len < tail_total || wg_len - tail_total < WG_MIN_PACKET)
        return -1;

    // "нам ничего не надо считать от конца пакета!!" -> we removed meta extraction.

    __u16 new_udp_len = (__u16)(udp_len - tail_total - quic_hdr_len);
    udph->len = bpf_htons(new_udp_len);
    udph->check = 0;

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

static __always_inline int handle_quic_probe(struct xdp_md *ctx)
{
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 ip_off = 14;
    __u32 udp_off;
    __u8 ipver = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph_v4 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v4 + 1) > data_end) return XDP_PASS;
        if (iph_v4->protocol != IPPROTO_UDP || iph_v4->ihl != 5) return XDP_PASS;
        udp_off = ip_off + 20;
        ipver = 4;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *iph_v6 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v6 + 1) > data_end) return XDP_PASS;
        if (iph_v6->nexthdr != IPPROTO_UDP) return XDP_PASS;
        udp_off = ip_off + 40;
        ipver = 6;
    }
    else
    {
        return XDP_PASS;
    }

    struct udphdr *udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;

    __u32 quic_off = udp_off + 8;
    __u8 *quic = (__u8 *)data + quic_off;

    /* Ensure we can read up to DCID length */
    if (quic + 6 > (__u8 *)data_end) return XDP_PASS;

    /* Check for QUIC Initial (Long Header: 11xxxxxx) */
    if ((quic[0] & 0xC0) != 0xC0) return XDP_PASS;

    __u8 dcid_len = quic[5];
    if (dcid_len > 20) return XDP_PASS;

    __u32 scid_off = quic_off + 6 + dcid_len;
    if ((__u8 *)data + scid_off + 1 > (__u8 *)data_end) return XDP_PASS;

    __u8 scid_len = ((__u8 *)data)[scid_off];
    if (scid_len > 20) return XDP_PASS;

    if ((__u8 *)data + scid_off + 1 + scid_len > (__u8 *)data_end) return XDP_PASS;

    /* Extract connection IDs before we modify the tail and reset pointers */
    __u8 orig_q0 = quic[0];
    __u8 orig_dcid[20] = {};
    __u8 orig_scid[20] = {};

#pragma unroll
    for (int i = 0; i < 20; i++)
    {
        if (i < dcid_len) orig_dcid[i] = ((__u8 *)data)[quic_off + 6 + i];
        if (i < scid_len) orig_scid[i] = ((__u8 *)data)[scid_off + 1 + i];
    }

    /* Target length of new QUIC version negotiation packet:
       1(Header) + 4(Version) + 1(DCID_Len) + SCID + 1(SCID_Len) + DCID + 4(Supported version) */
    __u32 new_quic_len = 1 + 4 + 1 + scid_len + 1 + dcid_len + 4;
    __u32 new_udp_len = 8 + new_quic_len;
    __u32 new_pkt_len = udp_off + new_udp_len;

    int delta = new_pkt_len - (__u32)((__u8 *)data_end - (__u8 *)data);
    if (bpf_xdp_adjust_tail(ctx, delta))
        return XDP_PASS;

    /* Recompute pointers after tail adjustment */
    data = (void *)(__u64)ctx->data;
    data_end = (void *)(__u64)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;

    __u8 *q = (__u8 *)data + quic_off;
    if (q + 70 > (__u8 *)data_end) return XDP_PASS; /* generous bounds check for verifier */

    q[0] = orig_q0 | 0x80;
    q[1] = 0; q[2] = 0; q[3] = 0; q[4] = 0;
    q[5] = scid_len;

    int offset = 6;
#pragma unroll
    for (int i = 0; i < 20; i++)
    {
        if (i < scid_len) { q[offset & 0x3F] = orig_scid[i]; offset++; }
    }

    q[offset & 0x3F] = dcid_len;
    offset++;

#pragma unroll
    for (int i = 0; i < 20; i++)
    {
        if (i < dcid_len) { q[offset & 0x3F] = orig_dcid[i]; offset++; }
    }

    q[(offset++) & 0x3F] = 0x6b;
    q[(offset++) & 0x3F] = 0x33;
    q[(offset++) & 0x3F] = 0x43;
    q[(offset++) & 0x3F] = 0xcf;

    /* Swap MAC addresses */
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    /* Update IP addresses and lengths, clear IP checksum */
    __u32 csum = 0;
    if (ipver == 4)
    {
        struct iphdr *iph_v4 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v4 + 1) > data_end) return XDP_PASS;
        __u32 tmp_ip = iph_v4->daddr;
        iph_v4->daddr = iph_v4->saddr;
        iph_v4->saddr = tmp_ip;
        iph_v4->tot_len = bpf_htons(new_pkt_len - ip_off);
        iph_v4->check = 0;
        iph_v4->check = csum_fold(bpf_csum_diff(0, 0, (__be32 *)iph_v4, sizeof(struct iphdr), 0));

        csum = bpf_csum_diff(0, 0, &iph_v4->saddr, 8, csum);
    }
    else
    {
        struct ipv6hdr *iph_v6 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v6 + 1) > data_end) return XDP_PASS;
        __u8 tmp_ipv6[16];
        __builtin_memcpy(tmp_ipv6, iph_v6->daddr.s6_addr, 16);
        __builtin_memcpy(iph_v6->daddr.s6_addr, iph_v6->saddr.s6_addr, 16);
        __builtin_memcpy(iph_v6->saddr.s6_addr, tmp_ipv6, 16);
        iph_v6->payload_len = bpf_htons(new_udp_len);

        csum = bpf_csum_diff(0, 0, (__be32 *)&iph_v6->saddr, 32, csum);
    }

    /* Swap UDP ports */
    __u16 tmp_port = udph->dest;
    udph->dest = udph->source;
    udph->source = tmp_port;
    udph->len = bpf_htons(new_udp_len);
    udph->check = 0;

    /* Compute UDP checksum */
    __u32 ph = bpf_htonl((IPPROTO_UDP << 16) | new_udp_len);
    csum = bpf_csum_diff(0, 0, &ph, 4, csum);
    csum = calc_payload_csum(udph, data_end, new_udp_len, csum);
    udph->check = csum_fold(csum);

    bpf_printk("XDP_TX QUIC VerNeg, new_len=%d", new_pkt_len);
    return XDP_TX;
}


SEC("xdp")
int xdp_gut_ingress(struct xdp_md *ctx)
{
    bpf_printk("XDP ingress: pkt size=%d", ctx->data_end - ctx->data);
    __u32 zero = 0;
    struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return XDP_PASS;
        
    if (gut_xdp_core(ctx, cfg) != 0)
    {
        if (cfg->own_http3 == 1)
        {
            if (handle_quic_probe(ctx) == XDP_TX)
                return XDP_TX;
        }
        if (cfg->default_xdp_action == 1)
            return XDP_DROP;
        return XDP_PASS;
    }

    return bpf_redirect_map(&tx_devmap, zero, 0);
}

SEC("xdp")
int xdp_veth_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
