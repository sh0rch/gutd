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
    __u16 protocol = eth->h_proto;
    if (protocol == bpf_htons(ETH_P_8021Q))
    {
        struct vlan_hdr
        {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        protocol = vlan->h_vlan_encapsulated_proto;
        ip_off = 18;
    }

    __u32 udp_off = 0;
    __u16 ipver = 0;

    struct iphdr *iph = (void *)((__u8 *)data + ip_off);
    if (protocol == bpf_htons(ETH_P_IP))
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

#if defined(GUT_MODE_SIP)
    /* SIP mode: data pkts (type 4, size > 32) → RTP path; rest → SIP+b64 signaling */
    __u8 sip_is_rtp = (wg_type == 4 && wg_len > 32) ? 1 : 0;
    __u32 sip_hdr_len = 0;
#endif

#if defined(GUT_MODE_B64)
    /* Enforce MTU limit for base64 signaling path only.
     * SIP RTP data path bypasses b64 and has no MTU limit here. */
#if defined(GUT_MODE_SIP)
    if (!sip_is_rtp)
    {
#endif
        if (wg_len > GUT_B64_WG_MTU_MAX)
        {
            struct gut_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
            if (stats)
                __sync_fetch_and_add(&stats->packets_oversized, 1);
            bpf_debug("DROP oversized WG pkt %d > %d, set WG MTU ≤ 800",
                      wg_len, GUT_B64_WG_MTU_MAX);
            return TC_ACT_SHOT;
        }
#if defined(GUT_MODE_SIP)
    }
#endif
#endif

    /* Save inner UDP ports BEFORE bpf_skb_adjust_room invalidates SKB pointers.
     * enc_ports is computed after ks47 is ready (plain_ports ^ ks47[11]).
     * XDP ingress recovers them symmetrically: enc_ports ^ ks47[11]. */
    __u32 plain_ports = (((__u32)bpf_ntohs(udph->source)) << 16) |
                        ((__u32)bpf_ntohs(udph->dest));
    __u32 enc_ports = 0; /* computed after chacha_block(ks47) below */

    __u32 nonce = wg_nonce32(wg_head);

    __u32 seq = counters->seq;
    if (seq == 0)
        seq = 1;
    counters->seq = seq + 1;

    __u16 tunnel_port = select_port(seq, cfg);
    if (tunnel_port == 0)
        return TC_ACT_OK;

#if defined(GUT_MODE_GOST) || defined(GUT_MODE_B64)
    __u32 quic_hdr_len = GUT_GOST_HEADER_SIZE;
#else /* GUT_MODE_QUIC */
    __u32 quic_hdr_len;
    if (wg_type == 1 || wg_type == 3)
    {
        /* WG Init / Cookie Reply → QUIC Initial long header (ClientHello + AEAD) */
        quic_hdr_len = GUT_QUIC_LONG_HEADER_SIZE;
    }
    else
    {
        quic_hdr_len = GUT_QUIC_SHORT_HEADER_SIZE;
    }
#endif

    __u32 *ks69 = (__u32 *)(scratch + 64);
    chacha_block(ks69, cfg->chacha_init, 69, nonce);
    __u8 *pad_block = (__u8 *)ks69;

    /* Ballast: random padding for all packets to break fixed-size fingerprints.
     * Wire encoding: last GOST header byte = 0x40 | (raw & 0x3F)
     *   bit6 (0x40) = "has ballast" flag
     *   bits[0:5]   = raw ∈ [0..63], actual ballast = raw+1 → [1..64]
     * GOST mode: 16-byte alignment for all packets (pad 0..15).
     * Other modes: small packets (< 220) get larger padding, large packets get [1..15].
     * Verifier note: after bpf_skb_change_tail spills pad_len to stack the
     * tnum loses umin; explicit re-check restores [1,64] before the store. */
    __u32 pad_len = 0;
#if defined(GUT_MODE_GOST)
    /* GOST: 16-byte alignment for small packets (< 256 bytes) only */
    {
        __u32 base_udp = 8 + quic_hdr_len + wg_len;
        if (wg_len < 256)
        {
            __u32 remainder = base_udp & 0x0F;
            if (remainder != 0)
                pad_len = 16 - remainder;
        }
    }
#else
    if (wg_len < BALLAST_THRESHOLD)
    {
#if defined(GUT_MODE_B64)
        __u32 raw = pad_block[63] & 0x1F; /* [0..31] uniform */
        pad_len = raw + 1;                /* [1..32] */
#else
        __u32 raw = pad_block[63] & 0x3F; /* [0..63] uniform */
        pad_len = raw + 1;                /* [1..64] */
#endif
    }
#if defined(GUT_MODE_B64)
    else
    {
        /* Large packets (B64 only): small random padding for traffic shaping.
         * QUIC: real QUIC has uniform MTU-sized data packets — no padding. */
        __u32 raw = pad_block[63] & 0x0F;
        if (raw > 14)
            raw = 14;
        pad_len = raw + 1; /* [1..15] */
    }
#endif
#endif
    if (pad_len > 0)
    {
        if (bpf_skb_change_tail(skb, skb->len + pad_len, 0) < 0)
            return TC_ACT_OK;
        /* Re-establish [1,64] for verifier after bpf_skb_change_tail stack spill.
         * Compiler optimizes out a plain check; asm volatile forces the bound. */
        asm volatile("%[v] &= 127\n\t"
                     "if %[v] < 1 goto +0"
                     : [v] "+r"(pad_len)
                     :
                     :);
        if (pad_len < 1 || pad_len > 64)
            return TC_ACT_OK;
        if (bpf_skb_store_bytes(skb, skb->len - pad_len, pad_block, pad_len, 0) < 0)
            return TC_ACT_OK;
    }

    __u32 *ks47 = (__u32 *)(scratch + 128);
    chacha_block(ks47, cfg->chacha_init, 47, nonce);
    __u8 *ks47_b = (__u8 *)ks47;

    /* enc_ports: XOR inner WG ports with ks47[11] (domain-separated from XOR keys and PPN).*/
    enc_ports = plain_ports ^ ks47[11];

    // Extract index before masking for stable connection IDs
    __u32 wg_idx = 0;
    if (wg_type == 2)
        __builtin_memcpy(&wg_idx, wg_head + 8, 4);
    else
        __builtin_memcpy(&wg_idx, wg_head + 4, 4);

    /* ── Multi-client dynamic peer: session bridging & routing ─────
     * TC egress sees raw (unmasked) WG on the veth.
     *   Type 1 (init): sender_index [4..8] only.  In dynamic_peer server mode
     *     the server should not initiate rekeys — drop; client will re-initiate.
     *   Type 2 (resp): sender=S_idx [4..8], receiver=C_idx [8..12].
     *     Build bridge: session_map[S_idx] = C_idx so XDP ingress can map
     *     future Type 4 packets (keyed by S_idx on ingress) back to C_idx.
     *   Type 4 (data): receiver=C_idx [4..8] — direct lookup in client_map.
     *
     * Note: wg_idx (used for DCID) reads bytes[8..12] for non-Type-1, which is
     * correct for DCID matching but NOT for routing.  Type 4 receiver_index lives
     * at bytes[4..8], so we extract a separate c_idx for the client_map lookup.
     */
    __u32 c_idx = wg_idx; /* correct for Type 2: bytes[8..12] = receiver_index = C_idx */
    if (cfg->dynamic_peer)
    {
        if (wg_type == 1)
            return TC_ACT_OK; /* drop server-initiated rekey; client will retry */

        if (wg_type == 4 || wg_type == 3)
        {
            /* Type 3/4: receiver_index at bytes[4..8] = C_idx */
            __builtin_memcpy(&c_idx, wg_head + 4, 4);
        }

        if (wg_type == 2)
        {
            __u32 s_idx = 0;
            __builtin_memcpy(&s_idx, wg_head + 4, 4); /* sender_index = S_idx */
            /* c_idx = wg_idx = wg_head[8..12] = receiver_index = C_idx for Type 2 */
            bpf_map_update_elem(&session_map, &s_idx, &c_idx, BPF_ANY);
        }
    }

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

#if defined(GUT_MODE_B64)
    /* ── Base64 / RTP mode: build GOST inner and encapsulate ── */
    __u32 b64_total = 0;
    __u32 room = 0;
    __u32 b64_len = 0;

#if defined(GUT_MODE_SIP)
    if (!sip_is_rtp)
    {
#endif /* GUT_MODE_SIP */
        /* ── Signaling path: GOST inner in scratch → base64-encode ── */
        {
            __u8 *inner = scratch + B64_INNER_OFF;
            __u32 wg_total = wg_len + pad_len;
            if (wg_total < WG_MIN_PACKET || wg_total > GUT_B64_MAX_INNER - quic_hdr_len)
                return TC_ACT_OK;

            /* GOST inner header: PPN(4) + enc_ports(4) + 0x00 + pad_byte */
            __builtin_memcpy(inner, &ppn, 4);
            __builtin_memcpy(inner + 4, &enc_ports, 4);
            inner[8] = 0x00;
            inner[9] = (pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;

            /* Load already-XOR'd WG+ballast from packet into scratch.
             * Packet has fully masked payload (first-16 + mac2 XOR done above).
             * Use asm volatile to re-bound wg_total for verifier. */
            {
                __u32 load_len;
                asm volatile("%[out] = %[in]\n\t"
                             "%[out] &= 1023\n\t"
                             "if %[out] < 1 goto +0"
                             : [out] "=r"(load_len)
                             : [in] "r"(wg_total)
                             :);
                if (load_len < 1 || load_len > 886)
                    return TC_ACT_OK;
                if (bpf_skb_load_bytes(skb, wg_off, inner + quic_hdr_len, load_len) < 0)
                    return TC_ACT_OK;
            }

            __u32 inner_len = quic_hdr_len + wg_total;
            b64_len = b64_encode(scratch, B64_INNER_OFF, inner_len, B64_ENC_OFF);
            if (b64_len == 0 || b64_len > GUT_B64_MAX_OUT)
                return TC_ACT_OK;

#if defined(GUT_MODE_SYSLOG)
            __u32 slen = cfg->sni_domain_len;
            if (slen > 32)
                slen = 32;
            __u32 b64_hdr_max = GUT_SYSLOG_HDR_BASE + slen;
#else /* GUT_MODE_SIP */
        sip_hdr_len = write_sip_header(scratch + 256, cfg, wg_type, wg_len);
        sip_hdr_len &= 0x1FF;
        if (sip_hdr_len < 40 || sip_hdr_len > GUT_SIP_HDR_MAX)
            return TC_ACT_OK;
        __u32 b64_hdr_max = sip_hdr_len;
#endif
            b64_total = b64_hdr_max + b64_len;
            /* Force bounded room: verifier loses wg_total range across ChaCha spills. */
            {
                __u32 raw_room = b64_total - wg_total;
                asm volatile("%[out] = %[in]\n\t"
                             "%[out] &= 2047\n\t"
                             "if %[out] < 1 goto +0"
                             : [out] "=r"(room)
                             : [in] "r"(raw_room)
                             :);
            }
#if defined(GUT_MODE_SIP)
            if (room < 1 || room > GUT_SIP_HDR_MAX + GUT_B64_MAX_OUT)
#else
        if (room < 1 || room > GUT_SYSLOG_HDR_MAX + GUT_B64_MAX_OUT)
#endif
                return TC_ACT_OK;
        }
#if defined(GUT_MODE_SIP)
    }
    else
    {
        /* ── RTP data path: raw GOST, no base64 ── */
        room = GUT_RTP_HEADER_SIZE + GUT_GOST_HEADER_SIZE;
        b64_total = GUT_RTP_HEADER_SIZE + GUT_GOST_HEADER_SIZE + wg_len + pad_len;
        /* Override port: RTP data → ports[1+] */
        if (cfg->num_ports > 1)
        {
            __u32 rtp_idx = 1 + (seq % (cfg->num_ports - 1));
            if (rtp_idx >= MAX_PORTS)
                rtp_idx = 1;
            tunnel_port = cfg->ports[rtp_idx];
        }
    }
    /* Signaling: always use ports[0] */
    if (!sip_is_rtp)
        tunnel_port = cfg->ports[0];
#endif /* GUT_MODE_SIP */

#else
    __u32 room = quic_hdr_len;
#endif

    if (bpf_skb_adjust_room(skb, room, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    __u32 shift_len = (ipver == 4) ? 20 + 8 : 40 + 8;
    if (shift_len > 60)
        return TC_ACT_OK;

#if defined(GUT_MODE_B64)
    /* Use bpf_skb_load/store_bytes for the header shift.  Direct packet pointer
     * access would fail because register pressure from b64_encode causes the
     * pkt pointer to be spilled, losing verifier range tracking (r=0). */
    {
        __u32 bounded_shift;
        asm volatile("%[out] = %[in]\n\t"
                     "%[out] &= 63\n\t"
                     "if %[out] < 1 goto +0"
                     : [out] "=r"(bounded_shift)
                     : [in] "r"(shift_len)
                     :);
        if (bounded_shift < 1 || bounded_shift > 60)
            return TC_ACT_OK;
        /* Use scratch+192 (free in b64 mode) to avoid clobbering the
         * SIP header already pre-built at scratch+256. */
        if (bpf_skb_load_bytes(skb, 14 + room, scratch + 192, bounded_shift) < 0)
            return TC_ACT_OK;
        if (bpf_skb_store_bytes(skb, 14, scratch + 192, bounded_shift, 0) < 0)
            return TC_ACT_OK;
    }
#else
    if ((__u8 *)data + 14 + room + shift_len > (__u8 *)data_end)
        return TC_ACT_OK;

#pragma unroll
    for (int i = 0; i < 60; i++)
    {
        if (i >= shift_len)
            break;
        scratch[256 + i] = ((__u8 *)data)[14 + room + i];
    }
#pragma unroll
    for (int i = 0; i < 60; i++)
    {
        if (i >= shift_len)
            break;
        ((__u8 *)data)[14 + i] = scratch[256 + i];
    }
#endif

    __u32 new_quic_off = 14 + shift_len;

#if defined(GUT_MODE_SYSLOG)
    /* Write syslog ASCII header into scratch (avoids packet-pointer spill
     * issues after b64_encode), then bpf_skb_store_bytes both parts. */
    __u32 syslog_hdr_len = write_syslog_ascii(scratch + 256, cfg);

    /* Enforce bounds for verifier */
    syslog_hdr_len &= 127;
    if (syslog_hdr_len < GUT_SYSLOG_HDR_BASE || syslog_hdr_len > GUT_SYSLOG_HDR_MAX)
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, new_quic_off, scratch + 256,
                            syslog_hdr_len, 0) < 0)
        return TC_ACT_OK;
    {
        __u32 slen;
        asm volatile("%[out] = %[in]\n\t"
                     "%[out] &= 4095\n\t"
                     "if %[out] < 4 goto +0"
                     : [out] "=r"(slen)
                     : [in] "r"(b64_len)
                     :);
        if (slen >= 4 && slen <= GUT_B64_MAX_OUT)
        {
            if (bpf_skb_store_bytes(skb, new_quic_off + syslog_hdr_len,
                                    scratch + B64_ENC_OFF, slen, 0) < 0)
                return TC_ACT_OK;
        }
    }
#elif defined(GUT_MODE_SIP)
    if (!sip_is_rtp)
    {
        /* ── Signaling: store pre-built SIP header + b64 payload ── */
        {
            __u32 hlen;
            asm volatile("%[out] = %[in]\n\t"
                         "%[out] &= 511\n\t"
                         "if %[out] < 40 goto +0"
                         : [out] "=r"(hlen)
                         : [in] "r"(sip_hdr_len)
                         :);
            if (hlen < 40 || hlen > GUT_SIP_HDR_MAX)
                return TC_ACT_OK;
            sip_hdr_len = hlen;
        }
        if (bpf_skb_store_bytes(skb, new_quic_off, scratch + 256,
                                sip_hdr_len, 0) < 0)
            return TC_ACT_OK;
        {
            __u32 slen;
            asm volatile("%[out] = %[in]\n\t"
                         "%[out] &= 4095\n\t"
                         "if %[out] < 4 goto +0"
                         : [out] "=r"(slen)
                         : [in] "r"(b64_len)
                         :);
            if (slen >= 4 && slen <= GUT_B64_MAX_OUT)
            {
                if (bpf_skb_store_bytes(skb, new_quic_off + sip_hdr_len,
                                        scratch + B64_ENC_OFF, slen, 0) < 0)
                    return TC_ACT_OK;
            }
        }
    }
    else
    {
        /* ── RTP data: write 22-byte header (RTP 12 + GOST 10) ── */
        __u8 rtp_gost[22];
        /* RTP header: V=2, PT=96, seq, ts=seq*160, SSRC=dcid
         * Timestamp: G.711 PCMU/PCMA sampled at 8kHz. 20ms = 160 samples.
         * We increment timestamp by 160 per packet to mimic a real media stream. */
        rtp_gost[0] = 0x80; /* V=2, P=0, X=0, CC=0 */
        rtp_gost[1] = 0x60; /* M=0, PT=96 */
        rtp_gost[2] = (seq >> 8) & 0xFF;
        rtp_gost[3] = seq & 0xFF;
        __u32 ts = seq * 160;
        rtp_gost[4] = (ts >> 24) & 0xFF;
        rtp_gost[5] = (ts >> 16) & 0xFF;
        rtp_gost[6] = (ts >> 8) & 0xFF;
        rtp_gost[7] = ts & 0xFF;
        __u32 dcid = ks47[9]; /* ks47[9]: unused word, keyed by nonce+shared key */
        __builtin_memcpy(rtp_gost + 8, &dcid, 4);
        /* GOST header: PPN(4) + enc_ports(4) + 0x00 + pad_byte */
        __builtin_memcpy(rtp_gost + 12, &ppn, 4);
        __builtin_memcpy(rtp_gost + 16, &enc_ports, 4);
        rtp_gost[20] = 0x00;
        rtp_gost[21] = (pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;

        /* Write updated WG headers (XOR'd) and mac2 to RTP payload */
        /* RTP payload starts at new_quic_off + 22.
         * GOST header at new_quic_off.
         * WG data starts at new_quic_off + 22. */
        if (bpf_skb_store_bytes(skb, new_quic_off, rtp_gost, 22, 0) < 0)
            return TC_ACT_OK;
        /* WG payload (including first-16 XOR and mac2 XOR) is already
         * in-place at new_quic_off+22 after adjust_room + header shift.
         * No additional masking needed — unified GOST prep above. */
    }
#elif defined(GUT_MODE_GOST)
    __u8 *quic = (__u8 *)data + new_quic_off;
    write_gost_header(quic, data_end, ppn, enc_ports, pad_len);
#else  /* GUT_MODE_QUIC */
    __u8 *quic = (__u8 *)data + new_quic_off;
    if (quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE)
    {
        __u32 dcid = ks47[9]; /* per-packet keyed value, no need for Feistel PRP */
        write_quic_short_header(quic, data_end, dcid, ppn, enc_ports, pad_len);
    }
    else
    {
        write_quic_long_header(quic, data_end, wg_type, wg_idx, ppn, enc_ports, pad_len, cfg, pad_block, scratch);
    }
#endif /* GUT_MODE */

#if defined(GUT_MODE_B64)
    /* Re-fetch packet pointers: b64 path (b64_encode + store_bytes) causes
     * packet pointers to be spilled with lost type/range tracking. */
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
#endif

    if (ipver == 4)
    {
        iph = (void *)((__u8 *)data + 14);
        udph = (void *)((__u8 *)data + 14 + 20);

#if defined(GUT_MODE_B64)
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
#endif

#if defined(GUT_MODE_B64)
        __u32 new_udp_len = b64_total + sizeof(struct udphdr);
#else
        __u32 new_udp_len = wg_len + quic_hdr_len + pad_len + sizeof(struct udphdr);
#endif
        __u32 new_ip_len = new_udp_len + 20;

        iph->tot_len = bpf_htons(new_ip_len);
        udph->len = bpf_htons(new_udp_len);

        udph->source = bpf_htons(tunnel_port);
        udph->dest = bpf_htons(tunnel_port);

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

#if defined(GUT_MODE_B64)
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
#endif

#if defined(GUT_MODE_B64)
        __u32 new_udp_len = b64_total + sizeof(struct udphdr);
#else
        __u32 new_udp_len = wg_len + quic_hdr_len + pad_len + sizeof(struct udphdr);
#endif

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
