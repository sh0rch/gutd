#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "gut_common.h"

char LICENSE[] SEC("license") = "GPL";

#define WG_MIN_PACKET 32

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

SEC("tc/egress")
int gut_egress(struct __sk_buff *skb)
{
    __u32 zero = 0;

    struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return TC_ACT_OK;

    struct gut_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (!stats)
        return TC_ACT_OK;

    struct gut_counters *counters = bpf_map_lookup_elem(&counters_map, &zero);
    if (!counters)
        return TC_ACT_OK;

    /* Scratch buffer (per-CPU, 4 KiB) reused for both the combined
     * meta+ballast write and the later checksum computation.        */
    __u8 *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch)
        return TC_ACT_OK;

    if (skb->len < 14 + 20 + 8 + WG_MIN_PACKET)
        return TC_ACT_OK;

    /* No pull_data here: wg_head is read via bpf_skb_load_bytes below,
     * which works on non-linearized skbs.  pull_data is deferred until
     * after bpf_skb_change_tail so we only linearize once.           */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_off = 14;
    __u32 udp_off;
    __u32 wg_off;
    __u32 wg_len;
    __u8 ipver;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto == ETH_P_IP)
    {
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
            return TC_ACT_OK;
        udp_off = ip_off + 20;
        ipver = 4;
    }
    else if (h_proto == ETH_P_IPV6)
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        if ((void *)(ip6h + 1) > data_end)
            return TC_ACT_OK;
        if (ip6h->nexthdr != IPPROTO_UDP)
            return TC_ACT_OK;
        udp_off = ip_off + 40;
        ipver = 6;
    }
    else
    {
        return TC_ACT_OK;
    }

    struct udphdr *udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    __u16 inner_src_port = udph->source;
    __u16 inner_dst_port = udph->dest;

    __u16 udp_len = bpf_ntohs(udph->len);
    if (udp_len < 8 + WG_MIN_PACKET)
        return TC_ACT_OK;

    wg_off = udp_off + 8;
    wg_len = udp_len - 8;
    /* Use skb->len (total including non-linear fragments) instead of
     * data_end (linear headroom only).  Packets forwarded through the
     * kernel stack from a physical NIC may have a non-linear skb where
     * data_end covers only ~128-256 bytes of headroom.  The WG payload
     * is read via bpf_skb_load_bytes (handles non-linear) and the skb
     * is linearized later by bpf_skb_pull_data before direct writes. */
    if (wg_off + wg_len > skb->len)
        return TC_ACT_OK;

    __u8 wg_head[WG_MIN_PACKET] = {};
    if (bpf_skb_load_bytes(skb, wg_off, wg_head, WG_MIN_PACKET) < 0)
        return TC_ACT_OK;
    __u8 wg_type = wg_head[0] & 0x1F;

    /* WireGuard signature: type 1..4, reserved bytes [1]=0 [2]=0.
     * Non-WG UDP passes through transparently.                    */
    if (wg_type < 1 || wg_type > 4 || wg_head[1] != 0 || wg_head[2] != 0)
        return TC_ACT_OK;

    __u32 nonce = wg_nonce32(wg_head);

    __u32 seq = counters->seq;
    if (seq == 0)
        seq = 1;
    counters->seq = seq + 1;

    __u16 tunnel_port = select_port(seq, cfg);
    if (tunnel_port == 0)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }

    if (wg_type == 4 && wg_len == WG_MIN_PACKET)
    {
        __u32 p = cfg->keepalive_drop_percent;
        if (p > 100)
            p = 100;
        if ((seq % 100) < p)
        {
            stats->packets_dropped++;
            return TC_ACT_SHOT;
        }
    }

    __u32 ballast_len = 0;
    __u32 ks[16]; /* single 64-byte array reused for block-1 then block-0 */

    /* Block-1: produces ballast length and content.
     * OR-1 trick keeps verifier range [1,63] at store_bytes call site. */
    chacha_block(ks, cfg->chacha_init, 1, nonce);
    {
        const __u8 *ks1b = (const __u8 *)ks;
        if (wg_len < BALLAST_THRESHOLD)
            ballast_len = ((__u32)ks1b[63] & 0x3F) | 1;
        /* Fill ballast payload into scratch while ks == block-1.      */
#pragma unroll
        for (int j = 0; j < BALLAST_MAX; j++)
            scratch[GUT_L4_META_SIZE + j] = ks1b[j];
        /* Save ks1b[63] for inline OR-1 at store_bytes (no stack spill). */
        scratch[GUT_L4_META_SIZE + BALLAST_MAX] = ks1b[BALLAST_MAX];
    }

    /* Block-0: meta XOR key + WG header mask.  Overwrite ks[]. */
    chacha_block(ks, cfg->chacha_init, 0, nonce);
    const __u8 *ks0b = (const __u8 *)ks;
    {
        __u16 src_h = bpf_ntohs(inner_src_port);
        __u16 dst_h = bpf_ntohs(inner_dst_port);
        scratch[0] = (__u8)(src_h >> 8) ^ ks0b[0];
        scratch[1] = (__u8)(src_h & 0xFF) ^ ks0b[1];
        scratch[2] = (__u8)(dst_h >> 8) ^ ks0b[2];
        scratch[3] = (__u8)(dst_h & 0xFF) ^ ks0b[3];
    }

    __u32 extra_tail = GUT_L4_META_SIZE + ballast_len;
    if (bpf_skb_change_tail(skb, skb->len + extra_tail, 0) < 0)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    /* First (and only pre-write) linearise: covers the enlarged packet. */
    if (bpf_skb_pull_data(skb, skb->len) < 0)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    udp_off = ip_off + (ipver == 6 ? 40 : 20);
    wg_off = udp_off + 8;
    if ((__u8 *)data + wg_off + wg_len + extra_tail > (__u8 *)data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }

    /* ── Direct writes while data pointer is valid ─────────────────────
     * xor16 and wg[1] write before the combined store_bytes that will
     * invalidate the pointer.                                          */
    __u8 *wg = (__u8 *)data + wg_off;
    if (wg + WG_MIN_PACKET > (__u8 *)data_end || wg + wg_len + extra_tail > (__u8 *)data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }

    wg[1] = (__u8)ballast_len;
    xor16(wg, ks0b);
    if (wg_type == 1 && wg_len >= 148 && wg + 148 <= (__u8 *)data_end)
        xor16(wg + 132, ks0b + 16);
    else if (wg_type == 2 && wg_len >= 92 && wg + 92 <= (__u8 *)data_end)
        xor16(wg + 76, ks0b + 16);

    /* ── Combined meta+ballast: single bpf_skb_store_bytes from scratch ──
     * scratch[0..3]   = XOR'd meta (set above)
     * scratch[4..66]  = ballast keystream (set above)
     * Size = GUT_L4_META_SIZE + ((ks[63]&0x3F)|1) ∈ [5,67]; inline
     * expression prevents verifier stack-spill zero-read rejection.  */
    if (ballast_len > 0)
    {
        /* Re-derive length from scratch[GUT_L4_META_SIZE+BALLAST_MAX] (the
         * saved ks1b[63]): map-value byte in [0,255] → AND → [0,63] →
         * OR-1 → [1,63] in register, no stack spill → verifier accepts. */
        if (bpf_skb_store_bytes(skb, wg_off + wg_len, scratch,
                                GUT_L4_META_SIZE + (((__u32)scratch[GUT_L4_META_SIZE + BALLAST_MAX] & 0x3F) | 1), 0) < 0)
        {
            stats->packets_dropped++;
            return TC_ACT_OK;
        }
    }
    else
    {
        if (bpf_skb_store_bytes(skb, wg_off + wg_len, scratch,
                                GUT_L4_META_SIZE, 0) < 0)
        {
            stats->packets_dropped++;
            return TC_ACT_OK;
        }
    }

    /* ── Re-linearise once after the store (invalidated pointer) ────── */
    if (bpf_skb_pull_data(skb, skb->len) < 0)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    udp_off = ip_off + (ipver == 6 ? 40 : 20);
    wg_off = udp_off + 8;
    if ((__u8 *)data + wg_off + wg_len + extra_tail > (__u8 *)data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }

    __u16 new_udp_len = (__u16)(8 + wg_len + extra_tail);

    if ((__u8 *)data + udp_off + sizeof(struct udphdr) > (__u8 *)data_end)
    {
        stats->packets_dropped++;
        return TC_ACT_OK;
    }
    udph = (void *)((__u8 *)data + udp_off);
    udph->source = bpf_htons(tunnel_port);
    udph->dest = bpf_htons(tunnel_port);
    udph->len = bpf_htons(new_udp_len);

    if (ipver == 4)
    {
        if ((__u8 *)data + ip_off + sizeof(struct iphdr) > (__u8 *)data_end)
        {
            stats->packets_dropped++;
            return TC_ACT_OK;
        }
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        iph->tot_len = bpf_htons((__u16)(20 + new_udp_len));
        iph->saddr = cfg->bind_ip;
        iph->daddr = cfg->peer_ip;
    }
    else
    {
        if ((__u8 *)data + ip_off + sizeof(struct ipv6hdr) > (__u8 *)data_end)
        {
            stats->packets_dropped++;
            return TC_ACT_OK;
        }
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        ip6h->payload_len = bpf_htons(new_udp_len);
        __builtin_memcpy(&ip6h->saddr, cfg->bind_ip6, 16);
        __builtin_memcpy(&ip6h->daddr, cfg->peer_ip6, 16);
    }

    __builtin_memcpy(eth->h_dest, cfg->dst_mac, 6);
    __builtin_memcpy(eth->h_source, cfg->src_mac, 6);
    eth->h_proto = bpf_htons(ipver == 6 ? ETH_P_IPV6 : ETH_P_IP);

    /* ── Checksum fixup ──────────────────────────────────────────────── */
    if (ipver == 4)
    {
        /* IPv4 fast path: recompute 20-byte IP header checksum inline
         * via bpf_csum_diff, zero UDP checksum (RFC 768 — optional for
         * IPv4).  Avoids the expensive scratch-load + bpf_loop L4
         * checksum iteration over ~1400 bytes per packet.             */
        struct iphdr *iph_cs = (void *)((__u8 *)data + ip_off);
        struct udphdr *udp_cs = (void *)((__u8 *)data + udp_off);
        if ((void *)(iph_cs + 1) > data_end || (void *)(udp_cs + 1) > data_end)
            goto out_stats;

        iph_cs->check = 0;
        __u64 ip_csum = bpf_csum_diff(0, 0, (__be32 *)iph_cs,
                                      sizeof(struct iphdr), 0);
        iph_cs->check = csum_fold(ip_csum);
        udp_cs->check = 0;
    }
    else if (scratch)
    {
        /* IPv6: UDP checksum is mandatory — use scratch buffer + bpf_loop */
        __u32 inner_new_len = 40 + (__u32)new_udp_len;
        __u32 load_len = inner_new_len;
        if (load_len > MAX_INNER_TECH_LIMIT)
            load_len = MAX_INNER_TECH_LIMIT;
        if (load_len < 48)
            goto out_stats;
        barrier_var(load_len);
        if (bpf_skb_load_bytes(skb, ip_off, scratch + GUT_BODY_HDR_SIZE, load_len) == 0)
        {
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            __u8 *ip_base2 = (__u8 *)data + ip_off;
            if (ip_base2 + 48 > (__u8 *)data_end)
                goto out_stats;
            fix_l4_checksum_v6(scratch, load_len);
            ip_base2[46] = scratch[GUT_BODY_HDR_SIZE + 46];
            ip_base2[47] = scratch[GUT_BODY_HDR_SIZE + 47];
        }
    }

out_stats:

    stats->mask_count++;
    stats->packets_processed++;
    stats->bytes_processed += skb->len;

    return bpf_redirect(cfg->egress_ifindex, 0);
}
