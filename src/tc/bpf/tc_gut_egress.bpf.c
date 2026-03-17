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

#define WG_MIN_PACKET 32

static __always_inline __u32 wg_nonce32(const __u8 *wg)
{
    __u32 n0 = (__u32)wg[16] | ((__u32)wg[17] << 8) | ((__u32)wg[18] << 16) | ((__u32)wg[19] << 24);
    __u32 n1 = (__u32)wg[20] | ((__u32)wg[21] << 8) | ((__u32)wg[22] << 16) | ((__u32)wg[23] << 24);
    __u32 n2 = (__u32)wg[24] | ((__u32)wg[25] << 8) | ((__u32)wg[26] << 16) | ((__u32)wg[27] << 24);
    __u32 n3 = (__u32)wg[28] | ((__u32)wg[29] << 8) | ((__u32)wg[30] << 16) | ((__u32)wg[31] << 24);
    return n0 ^ n1 ^ n2 ^ n3;
}

SEC("tc")
int gut_egress(struct __sk_buff *skb)
{
    bpf_debug("TC egress: processing packet len=%d", skb->len);
    __u32 zero = 0;
    struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return TC_ACT_OK;

    struct gut_counters *counters = bpf_map_lookup_elem(&counters_map, &zero);
    if (!counters)
        return TC_ACT_OK;

    __u8 *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch)
        return TC_ACT_OK;

    if (skb->len < 14 + 20 + 8 + WG_MIN_PACKET)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_off = 14;
    __u32 udp_off = 0;
    __u16 ipver = 0;

    struct iphdr *iph = (void *)((__u8 *)data + ip_off);
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        if (iph->protocol != IPPROTO_UDP)
            return TC_ACT_OK;
        udp_off = ip_off + iph->ihl * 4;
        ipver = 4;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = (void *)iph;
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

    __u32 wg_off = udp_off + sizeof(struct udphdr);
    __u32 wg_len = bpf_ntohs(udph->len) - sizeof(struct udphdr);

    if (wg_off + wg_len > skb->len || wg_len < WG_MIN_PACKET)
        return TC_ACT_OK;

    __u8 *wg_head = scratch + 0;
    if (bpf_skb_load_bytes(skb, wg_off, wg_head, WG_MIN_PACKET) < 0)
        return TC_ACT_OK;

    __u8 wg_type = wg_head[0] & 0x1F;
    if (wg_type < 1 || wg_type > 4 || wg_head[1] != 0 || wg_head[2] != 0)
        return TC_ACT_OK;

    /* Save inner UDP ports BEFORE bpf_skb_adjust_room invalidates SKB pointers.
     * Pack sport:dport into a u32, XOR with FEISTEL_SALT_PORTS for domain separation,
     * then encrypt with feistel32 using the shared round keys.  XDP ingress decrypts
     * with feistel32_inv to recover the original WireGuard port numbers. */
    __u32 plain_ports = (((__u32)bpf_ntohs(udph->source)) << 16) |
                        ((__u32)bpf_ntohs(udph->dest));
    __u32 enc_ports = feistel32(plain_ports ^ FEISTEL_SALT_PORTS, cfg->feistel_rk);

    __u32 nonce = wg_nonce32(wg_head);

    __u32 seq = counters->seq;
    if (seq == 0)
        seq = 1;
    counters->seq = seq + 1;

    __u16 tunnel_port = select_port(seq, cfg);
    if (tunnel_port == 0)
        return TC_ACT_OK;

    __u8 is_server = is_quic_server(cfg);
    __u32 quic_hdr_len;
    if (wg_type == 3)
    {
        /* Cookie Reply → QUIC Retry long header (must never be dropped) */
        quic_hdr_len = GUT_QUIC_LONG_HEADER_SIZE;
    }
    else if (is_server)
    {
        quic_hdr_len = GUT_QUIC_SHORT_HEADER_SIZE;
    }
    else
    {
        quic_hdr_len = (wg_type == 1) ? GUT_QUIC_LONG_HEADER_SIZE : GUT_QUIC_SHORT_HEADER_SIZE;
    }

    __u32 *ks69 = (__u32 *)(scratch + 64);
    chacha_block(ks69, cfg->chacha_init, 69, nonce);
    __u8 *pad_block = (__u8 *)ks69;

    // Extract index before masking for stable connection IDs
    __u32 wg_idx = 0;
    if (wg_type == 2)
        __builtin_memcpy(&wg_idx, wg_head + 8, 4);
    else
        __builtin_memcpy(&wg_idx, wg_head + 4, 4);

    /* ── Multi-client dynamic peer: session bridging & routing ─────
     * TC egress sees raw (unmasked) WG on the veth.
     *   Type 1 (init): sender_index [4..8] only.
     *   Type 2 (resp): sender=S_idx [4..8], receiver=C_idx [8..12].
     *   Type 4 (data): receiver=C_idx [4..8].
     */
    __u32 c_idx = wg_idx;
    if (cfg->dynamic_peer)
    {
        if (wg_type == 1)
            return TC_ACT_OK; /* drop server-initiated rekey; client will retry */

        if (wg_type == 4 || wg_type == 3)
        {
            __builtin_memcpy(&c_idx, wg_head + 4, 4);
        }

        if (wg_type == 2)
        {
            __u32 s_idx = 0;
            __builtin_memcpy(&s_idx, wg_head + 4, 4);
            bpf_map_update_elem(&session_map, &s_idx, &c_idx, BPF_ANY);
        }
    }

    __u8 use_gost = cfg->obfs_gost;
    if (cfg->dynamic_peer)
    {
        struct peer_endpoint *gost_ep = bpf_map_lookup_elem(&client_map, &c_idx);
        if (gost_ep && gost_ep->valid)
            use_gost = gost_ep->obfs_gost;
    }

    __u32 pad_len = 0;
    if (use_gost)
    {
        /* 16-byte alignment padding (Kuznyechik/AES block size emulation). */
        __u32 base_udp_size = 8 + quic_hdr_len + wg_len;
        __u32 remainder = base_udp_size % 16;
        if (remainder != 0)
        {
            pad_len = 16 - remainder; /* [1..15] */
        }
    }
    else
    {
        /* Plain QUIC mode: random ballast [1..64] for small packets */
        if (wg_len < 220)
        {
            __u32 raw = pad_block[63] & 0x3F; /* [0..63] uniform */
            pad_len = raw + 1;                /* [1..64] */
        }
    }

    if (pad_len > 0)
    {
        if (bpf_skb_change_tail(skb, skb->len + pad_len, 0) < 0)
            return TC_ACT_OK;
        /* Re-establish bounds for verifier. */
        if (pad_len > 64)
            return TC_ACT_OK;
        if (bpf_skb_store_bytes(skb, skb->len - pad_len, pad_block, pad_len, 0) < 0)
            return TC_ACT_OK;
    }

    __u32 *ks47 = (__u32 *)(scratch + 128);
    chacha_block(ks47, cfg->chacha_init, 47, nonce);
    __u8 *ks47_b = (__u8 *)ks47;

    // Extract Protected Packet Number (PPN) from unused 47th block keystream
    __u32 ppn = ks47[10];

    for (int i = 0; i < 16; i++)
    {
        wg_head[i] ^= ks47_b[i];
    }
    if (bpf_skb_store_bytes(skb, wg_off, wg_head, 16, 0) < 0)
        return TC_ACT_OK;

    if (wg_type == 1 && wg_len >= 148)
    {
        __u8 *mac2 = scratch + 192;
        if (bpf_skb_load_bytes(skb, wg_off + 132, mac2, 16) == 0)
        {
            for (int i = 0; i < 16; i++)
                mac2[i] ^= ks47_b[16 + i];
            bpf_skb_store_bytes(skb, wg_off + 132, mac2, 16, 0);
        }
    }
    else if (wg_type == 2 && wg_len >= 92)
    {
        __u8 *mac2 = scratch + 192;
        if (bpf_skb_load_bytes(skb, wg_off + 76, mac2, 16) == 0)
        {
            for (int i = 0; i < 16; i++)
                mac2[i] ^= ks47_b[16 + i];
            bpf_skb_store_bytes(skb, wg_off + 76, mac2, 16, 0);
        }
    }

    if (bpf_skb_adjust_room(skb, quic_hdr_len, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    __u32 shift_len = (ipver == 4) ? 20 + 8 : 40 + 8;
    if (shift_len > 60)
        return TC_ACT_OK; // limit for verifier

    if ((__u8 *)data + 14 + quic_hdr_len + shift_len > (__u8 *)data_end)
        return TC_ACT_OK;

#pragma unroll
    for (int i = 0; i < 60; i++)
    {
        if (i >= shift_len)
            break;
        scratch[256 + i] = ((__u8 *)data)[14 + quic_hdr_len + i];
    }
#pragma unroll
    for (int i = 0; i < 60; i++)
    {
        if (i >= shift_len)
            break;
        ((__u8 *)data)[14 + i] = scratch[256 + i];
    }

    __u32 new_quic_off = 14 + shift_len;
    __u8 *quic = (__u8 *)data + new_quic_off;

    if (quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE)
    {
        if ((__u8 *)quic + GUT_QUIC_SHORT_HEADER_SIZE > (__u8 *)data_end)
            return TC_ACT_OK;
        quic[0] = 0x40; // Short

        // Generate stable DCID from feistel
        __u32 dcid = feistel32(wg_idx, cfg->feistel_rk);
        __builtin_memcpy((__u8 *)quic + 1, &dcid, 4);

        // Inject 4-byte PPN
        __builtin_memcpy((__u8 *)quic + 5, &ppn, 4);

        // Bytes 9-12: feistel-encrypted ports (sport<<16|dport); XDP decrypts with feistel32_inv
        __builtin_memcpy((__u8 *)quic + 9, &enc_ports, 4);
    }
    else
    {
        if ((__u8 *)quic + GUT_QUIC_LONG_HEADER_SIZE > (__u8 *)data_end)
            return TC_ACT_OK;
        /* 0xC0 = QUIC Initial (client Type 1), 0xF0 = QUIC Retry (Cookie Reply Type 3) */
        quic[0] = (wg_type == 3) ? 0xF0 : 0xC0;

        __u32 time_gost = feistel32((__u32)bpf_ktime_get_ns(), cfg->feistel_rk);
        __u8 *gost_b = (__u8 *)&time_gost;

#pragma unroll
        for (int i = 1; i < 90; i++)
            quic[i] = pad_block[(i * 7) & 0x3F] ^ gost_b[i & 3]; // fill with PRNG gost

        // Version (QUICv2 = 0x6b3343cf)
        quic[1] = 0x6b;
        quic[2] = 0x33;
        quic[3] = 0x43;
        quic[4] = 0xcf;

        // Generate stable pseudo-random IDs
        __u32 dcid = feistel32(wg_idx, cfg->feistel_rk);
        __u32 dcid2 = feistel32(wg_idx ^ 0xDEADBEEF, cfg->feistel_rk);
        __u32 scid = feistel32(wg_idx ^ 0xCAFEBABE, cfg->feistel_rk);
        __u32 scid2 = feistel32(wg_idx ^ 0x12345678, cfg->feistel_rk);

        quic[5] = 0x08; // DCID Len 8
        __builtin_memcpy((__u8 *)quic + 6, &dcid, 4);
        __builtin_memcpy((__u8 *)quic + 10, &dcid2, 4);

        quic[14] = 0x08; // SCID Len 8
        __builtin_memcpy((__u8 *)quic + 15, &scid, 4);
        __builtin_memcpy((__u8 *)quic + 19, &scid2, 4);

        quic[23] = 0x00; // token len 0
        quic[24] = 0x40; // length (approx)
        quic[25] = 0x00;

        // 4-byte PPN
        __builtin_memcpy((__u8 *)quic + 26, &ppn, 4);

        // Bytes 30-33: feistel-encrypted ports (sport<<16|dport); XDP decrypts with feistel32_inv
        __builtin_memcpy((__u8 *)quic + 30, &enc_ports, 4);

        // Keep the rest filled with the PRNG gost generated above. No open text SNI!
    }
    /* Encode ballast info in the last QUIC header byte:
     *   0x00           = no ballast (large packet path, pad_len==0)
     *   0x40 | raw     = has ballast; actual len = (raw & 0x3F) + 1 → [1..64] */
    quic[quic_hdr_len - 1] = (!use_gost && pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;

    /* Gost mode: XOR first 6 bytes with bytes [6..12] to hide QUIC signatures */
    if (use_gost)
    {
#pragma unroll
        for (int i = 0; i < 6; i++)
            quic[i] ^= quic[6 + i];
    }

    if (ipver == 4)
    {
        iph = (void *)((__u8 *)data + 14);
        udph = (void *)((__u8 *)data + 14 + 20);

        __u32 new_udp_len = wg_len + quic_hdr_len + pad_len + sizeof(struct udphdr);
        __u32 new_ip_len = new_udp_len + 20;

        iph->tot_len = bpf_htons(new_ip_len);
        udph->len = bpf_htons(new_udp_len);

        udph->source = bpf_htons(tunnel_port);
        udph->dest = bpf_htons(tunnel_port);

        iph->frag_off = 0; // Clear DF (Don't Fragment) flag
        iph->check = 0;

        /* Dynamic peer: read destination from client_map keyed by c_idx.
         * For Type 2, c_idx = wg_idx = bytes[8..12] = receiver_index.
         * For Type 4, c_idx = bytes[4..8] = receiver_index (extracted above). */
        if (cfg->dynamic_peer)
        {
            struct peer_endpoint *ep = bpf_map_lookup_elem(&client_map, &c_idx);
            if (!ep || !ep->valid)
            {
                bpf_debug("TC: drop wg_type=%u c_idx=%u: no entry in client_map", wg_type, c_idx);
                return TC_ACT_OK; /* no endpoint learned yet — drop silently */
            }

            if (ep->server_ip4 != 0)
            {
                __builtin_memcpy(&iph->saddr, &ep->server_ip4, 4);
            }
            else
            {
                __builtin_memcpy(&iph->saddr, &cfg->bind_ip, 4);
            }
            __builtin_memcpy(&iph->daddr, &ep->ip4, 4);
            udph->dest = bpf_htons(ep->port);
            if (ep->server_port != 0)
            {
                udph->source = bpf_htons(ep->server_port);
            }
        }
        else
        {
            __builtin_memcpy(&iph->saddr, &cfg->bind_ip, 4);
            __builtin_memcpy(&iph->daddr, &cfg->peer_ip, 4);
        }

        __u64 ip_csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0);
        iph->check = csum_fold(ip_csum);

        udph->check = 0;
        __u32 csum = 0;
        csum = bpf_csum_diff(0, 0, &iph->saddr, 8, csum); // saddr and daddr are contiguous
        __u32 ph = bpf_htonl((IPPROTO_UDP << 16) | bpf_ntohs(udph->len));
        csum = bpf_csum_diff(0, 0, &ph, 4, csum);

        void *udp_start = (void *)udph;
        __u32 payload_len = bpf_ntohs(udph->len); // length of UDP header + payload
        csum = calc_payload_csum(udp_start, data_end, payload_len, csum);

        __u16 final_csum = csum_fold(csum);
        udph->check = final_csum ? final_csum : 0xFFFF; // apply pseudo header and payload csum
    }
    else if (ipver == 6)
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + 14);
        udph = (void *)((__u8 *)data + 14 + 40);

        __u32 new_udp_len = wg_len + quic_hdr_len + pad_len + sizeof(struct udphdr);

        ip6h->payload_len = bpf_htons(new_udp_len);
        udph->len = bpf_htons(new_udp_len);

        udph->source = bpf_htons(tunnel_port);
        udph->dest = bpf_htons(tunnel_port);

        if (cfg->dynamic_peer)
        {
            struct peer_endpoint *ep = bpf_map_lookup_elem(&client_map, &c_idx);
            if (!ep || !ep->valid)
            {
                bpf_debug("TC: drop wg_type=%u c_idx=%u: no entry in client_map (IPv6)", wg_type, c_idx);
                return TC_ACT_OK; /* no endpoint learned yet — drop silently */
            }

            // Check if server_ip6 is not all zeros
            __u64 s6_1 = ((__u64 *)ep->server_ip6)[0];
            __u64 s6_2 = ((__u64 *)ep->server_ip6)[1];
            if (s6_1 != 0 || s6_2 != 0)
            {
                __builtin_memcpy(&ip6h->saddr, ep->server_ip6, 16);
            }
            else
            {
                __builtin_memcpy(&ip6h->saddr, cfg->bind_ip6, 16);
            }

            __builtin_memcpy(&ip6h->daddr, ep->ip6, 16);
            udph->dest = bpf_htons(ep->port);
            if (ep->server_port != 0)
            {
                udph->source = bpf_htons(ep->server_port);
            }
        }
        else
        {
            __builtin_memcpy(&ip6h->saddr, cfg->bind_ip6, 16);
            __builtin_memcpy(&ip6h->daddr, cfg->peer_ip6, 16);
        }

        udph->check = 0;
        __u32 csum = 0;
        csum = bpf_csum_diff(0, 0, (__be32 *)&ip6h->saddr, 32, csum); // saddr and daddr are contiguous
        __u32 ph = bpf_htonl((IPPROTO_UDP << 16) | bpf_ntohs(udph->len));
        csum = bpf_csum_diff(0, 0, &ph, 4, csum);

        void *udp_start = (void *)udph;
        __u32 payload_len = bpf_ntohs(udph->len); // length of UDP header + payload
        csum = calc_payload_csum(udp_start, data_end, payload_len, csum);

        __u16 final_csum = csum_fold(csum);
        udph->check = final_csum ? final_csum : 0xFFFF; // apply pseudo header and payload csum
    }

    eth = data;
    __builtin_memcpy(eth->h_dest, cfg->dst_mac, 6);
    __builtin_memcpy(eth->h_source, cfg->src_mac, 6);

    bpf_debug("TC egress: wg_type=%d quic_len=%d pad=%d port=%d", wg_type, quic_hdr_len, pad_len, tunnel_port);
    return bpf_redirect(cfg->egress_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
