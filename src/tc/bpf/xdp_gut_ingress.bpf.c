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

#if defined(GUT_MODE_SIP)
/* ── SIP marker scan via bpf_loop ── scan scratch[SIP_SCAN_OFF..] for "a=fmtp:0 " */
struct sip_scan_ctx
{
    __u8 *scratch;
    __u32 max_len;
    __u32 result;
    __u64 date_numeric;
    __u32 auth_token;
};

static __attribute__((unused)) long sip_date_extract_cb(__u32 idx, void *_ctx)
{
    struct sip_scan_ctx *ctx = (struct sip_scan_ctx *)_ctx;
    if (idx + 7 > ctx->max_len)
        return 1;
    __u32 base = SIP_SCAN_OFF + idx;
    __u8 *s = ctx->scratch;

    // Quick find "Date: "
    if (s[base & (SCRATCH_SIZE - 1)] == 'D' && s[(base + 1) & (SCRATCH_SIZE - 1)] == 'a' &&
        s[(base + 2) & (SCRATCH_SIZE - 1)] == 't' && s[(base + 3) & (SCRATCH_SIZE - 1)] == 'e' &&
        s[(base + 4) & (SCRATCH_SIZE - 1)] == ':' && s[(base + 5) & (SCRATCH_SIZE - 1)] == ' ')
    {
        // Extract digits until CRLF
        for (int i = 6; i < 48; i++)
        {
            if (idx + i >= ctx->max_len)
                break;
            __u16 b_off = (base + i) & (SCRATCH_SIZE - 1);
            __u8 b = s[b_off];
            if (b == '\r' || b == '\n' || b == ' ')
                break;
            if (b >= '0' && b <= '9')
            {
                ctx->date_numeric = ctx->date_numeric * 10 + (b - '0');
            }
        }
        return 1; // found Date, stop
    }
    return 0;
}

static __attribute__((unused)) long sip_marker_scan_cb(__u32 idx, void *_ctx)
{
    struct sip_scan_ctx *ctx = (struct sip_scan_ctx *)_ctx;
    if (ctx->result != 0)
        return 1; /* already found — stop */
    if (idx + 9 > ctx->max_len)
        return 1; /* past end — stop */
    __u32 base = SIP_SCAN_OFF + idx;
    __u8 *s = ctx->scratch;
    if (s[base & (SCRATCH_SIZE - 1)] == 'a' &&
        s[(base + 1) & (SCRATCH_SIZE - 1)] == '=' &&
        s[(base + 2) & (SCRATCH_SIZE - 1)] == 'f' &&
        s[(base + 3) & (SCRATCH_SIZE - 1)] == 'm' &&
        s[(base + 4) & (SCRATCH_SIZE - 1)] == 't' &&
        s[(base + 5) & (SCRATCH_SIZE - 1)] == 'p' &&
        s[(base + 6) & (SCRATCH_SIZE - 1)] == ':' &&
        s[(base + 7) & (SCRATCH_SIZE - 1)] == '0' &&
        s[(base + 8) & (SCRATCH_SIZE - 1)] == ' ')
    {
        ctx->result = idx + 9;
        return 1; /* found — stop */
    }
    return 0; /* continue */
}

static __attribute__((unused)) long sip_auth_scan_cb(__u32 idx, void *_ctx)
{
    struct sip_scan_ctx *ctx = (struct sip_scan_ctx *)_ctx;
    if (ctx->auth_token != 0)
        return 1; /* already found */
    if (idx >= ctx->max_len)
        return 1;
    __u32 base = (SIP_SCAN_OFF + idx) & (SCRATCH_SIZE - 1);
    __u8 *s = ctx->scratch;
    if (s[base] == 'z' && s[(base + 7) & (SCRATCH_SIZE - 1)] == '-')
    {
        __u32 tok = 0;
        for (int j = 0; j < 8; j++)
        {
            __u8 b = s[(base + 8 + j) & (SCRATCH_SIZE - 1)];
            if (b >= '0' && b <= '9')
                tok = (tok << 4) | (b - '0');
            else if (b >= 'a' && b <= 'f')
                tok = (tok << 4) | (b - 'a' + 10);
            else if (b >= 'A' && b <= 'F')
                tok = (tok << 4) | (b - 'A' + 10);
        }
        ctx->auth_token = tok;
        return 1;
    }
    return 0;
}
#endif /* GUT_MODE_SIP */

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

#if defined(GUT_MODE_B64)
/* Not needed as separate subprog — b64_decode is called inline to avoid
 * mark_precise explosion from noinline map-value invalidation. */
#endif /* GUT_MODE_B64 */

static __always_inline int gut_xdp_core(struct xdp_md *ctx, struct gut_config *cfg)
{
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    __u32 zero = 0;
    struct gut_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (!stats)
        return -1;

    __u8 *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch)
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

    /* Auto-detect gost vs plain QUIC per client.
     * Try plain QUIC first (check first byte for 0x40/0xC0/0xF0).
     * If that fails, apply gost unmask and check again. */
    if (wg + 12 > (__u8 *)data_end)
        return -1;

#if defined(GUT_MODE_GOST)
    __u32 quic_hdr_len = GUT_GOST_HEADER_SIZE;
#elif defined(GUT_MODE_SYSLOG)
    /* Syslog base64 → GOST conversion: load, decode (noinline), store, trim.
     * Scan for " - - -  " marker to find where b64 data starts — the service
     * name length varies per peer, so we cannot use a fixed header size. */
    if (wg[0] != 0x3C) /* '<' */
        return -1;
    {
        /* Scan for " - - -  " (8 bytes) starting from position 28 (after timestamp).
         * Service name is at most 32 bytes, so marker is in [28..60). */
        __u32 syslog_hdr_len = 0;
        if (wg + 68 > (__u8 *)data_end)
            return -1;

        _Pragma("unroll") for (__u32 i = 28; i < 60; i++)
        {
            if (wg[i] == ' ' && wg[i + 1] == '-' && wg[i + 2] == ' ' &&
                wg[i + 3] == '-' && wg[i + 4] == ' ' && wg[i + 5] == '-' &&
                wg[i + 6] == ' ' && wg[i + 7] == ' ')
            {
                syslog_hdr_len = i + 8;
                break;
            }
        }
        if (syslog_hdr_len < GUT_SYSLOG_HDR_BASE || syslog_hdr_len > GUT_SYSLOG_HDR_MAX)
            return -1;

        __u32 b64_data_len = wg_len - syslog_hdr_len;
        b64_data_len &= 0xFFF; /* unsigned bound for verifier */
        if (b64_data_len < 16 || b64_data_len > GUT_B64_MAX_OUT)
            return -1;
        if (bpf_xdp_load_bytes(ctx, wg_off + syslog_hdr_len,
                               scratch + B64_ENC_OFF, b64_data_len) < 0)
            return -1;

        /* Decode base64 inline */
        __u32 b64_bounded = b64_data_len & 0xFFF;
        if (b64_bounded < 16 || b64_bounded > GUT_B64_MAX_OUT || (b64_bounded & 3))
            return -1;
        __u32 decoded_len = b64_decode(scratch, B64_ENC_OFF, b64_bounded, B64_INNER_OFF);
        if (decoded_len < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET ||
            decoded_len > GUT_B64_MAX_INNER)
            return -1;

        /* Strip ballast from decoded GOST inner so we only write net data
         * to the packet and need a single bpf_xdp_adjust_tail. */
        __u32 pad_off = (B64_INNER_OFF + 9) & (SCRATCH_SIZE - 1);
        __u8 pad_byte_s = scratch[pad_off];
        __u32 ballast_s = (pad_byte_s & 0x40) ? ((__u32)(pad_byte_s & 0x3F) + 1) : 0;
        if (ballast_s >= decoded_len - GUT_GOST_HEADER_SIZE)
            return -1;
        decoded_len -= ballast_s;

        decoded_len &= 0x3FF;
        if (decoded_len < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET || decoded_len > 1023)
            return -1;
        scratch[pad_off] = 0x00; /* clear ballast flag for shared GOST code */

        /* Force compiler to resolve bounds strictly before call */
        __u32 slen = decoded_len & 0x3FF;
        if (slen == 0)
            return -1;

        /* Write decoded GOST inner (without ballast) back to packet */
        if (bpf_xdp_store_bytes(ctx, wg_off,
                                scratch + B64_INNER_OFF, slen) < 0)
            return -1;

        /* Trim excess tail bytes (base64 expansion + ballast in one op) */
        __s32 syslog_trim = (__s32)wg_len - (__s32)decoded_len;
        if (syslog_trim > 0)
        {
            if (bpf_xdp_adjust_tail(ctx, -syslog_trim) < 0)
                return -1;
        }

        /* Re-derive all pointers after packet modifications */
        data = (void *)(__u64)ctx->data;
        data_end = (void *)(__u64)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return -1;
        udph = (void *)((__u8 *)data + udp_off);
        if ((void *)(udph + 1) > data_end)
            return -1;
        wg = (__u8 *)data + wg_off;
        wg_len = decoded_len;
        if (wg + GUT_GOST_HEADER_SIZE + WG_MIN_PACKET > (__u8 *)data_end)
            return -1;
        if (wg + wg_len > (__u8 *)data_end)
            return -1;
        udp_len = 8 + (__u16)decoded_len;
    }
    /* Packet is now in GOST format — fall through to GOST processing */
    __u32 quic_hdr_len = GUT_GOST_HEADER_SIZE;
#elif defined(GUT_MODE_SIP)
    /* ── SIP mode: detect RTP (data) vs SIP signaling (b64) ── */
    if (wg_len < 22) /* min: RTP(12) + GOST(10) */
        return -1;

    if ((wg[0] & 0xC0) == 0x80 && (wg[1] & 0x7F) == 0x60)
    {
        /* ── RTP data path: strip 12-byte RTP header → GOST ── */
        __u32 gost_data_len = wg_len - GUT_RTP_HEADER_SIZE;
        gost_data_len &= 0xFFF;
        if (gost_data_len < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET ||
            gost_data_len > 1500)
            return -1;

        /* Re-bound for verifier: spill across branches loses umin tracking */
        asm volatile("%[v] &= 2047\n\t"
                     "if %[v] < 42 goto +0"
                     : [v] "+r"(gost_data_len)
                     :
                     :);
        if (gost_data_len < 42 || gost_data_len > 1500)
            return -1;

        /* Strip RTP header directly from packet.
         * The RTP header is 12 bytes at wg_off.
         * Shift Ethernet+IP+UDP(8) headers forward to cover the hole. */
        __u32 shift_len_head = udp_off + 8;
        if (shift_len_head > 62)
            return -1;

        /* 1. Load original headers into scratch */

        for (int i = 0; i < 62; i++)
        {
            if (i >= shift_len_head)
                break;
            scratch[256 + i] = ((__u8 *)data)[i];
        }

        /* 2. Remove the 12-byte RTP header from the start of the packet data */
        if (bpf_xdp_adjust_head(ctx, (int)GUT_RTP_HEADER_SIZE) < 0)
            return -1;

        /* 3. Restore headers at the new start position */
        data = (void *)(__u64)ctx->data;
        data_end = (void *)(__u64)ctx->data_end;
        if ((__u8 *)data + shift_len_head > (__u8 *)data_end)
            return -1;

        for (int i = 0; i < 62; i++)
        {
            if (i >= shift_len_head)
                break;
            ((__u8 *)data)[i] = scratch[256 + i];
        }

        /* Re-derive all pointers for subsequent processing */
        eth = data;
        udph = (void *)((__u8 *)data + udp_off);
        wg = (__u8 *)data + wg_off;
        wg_len = gost_data_len;
        if (wg + GUT_GOST_HEADER_SIZE + WG_MIN_PACKET > (__u8 *)data_end)
            return -1;
        udp_len = 8 + (__u16)gost_data_len;
    }
    else if (wg[0] == 'M' || wg[0] == 'R' || wg[0] == 'O' ||
             wg[0] == 'S' || wg[0] == 'I' || wg[0] == 'B' ||
             wg[0] == 'A' || wg[0] == 'V' || wg[0] == 'N' || wg[0] == 'P' ||
             (wg[0] == 'G' && wg[1] == 'E' && wg[2] == 'T'))
    {
        /* ── SIP signaling: scan for "a=fmtp:0 " marker, b64 decode → GOST ── */
        __u32 scan_len = wg_len;
        if (scan_len > 1024)
            scan_len = 1024;
        if (scan_len < 64)
            return -1;

        /* Load first up to 1024 bytes for marker scanning */
        if (bpf_xdp_load_bytes(ctx, wg_off,
                               scratch + SIP_SCAN_OFF, scan_len) < 0)
            return -1;

        struct sip_scan_ctx sctx = {};
        sctx.scratch = scratch;
        sctx.max_len = scan_len;
        sctx.result = 0;
        sctx.date_numeric = 0;
        sctx.auth_token = 0;

        /* 1. Extract Date: digits for anti-probing salt */
        bpf_loop(512, sip_date_extract_cb, &sctx, 0);

        /* 2. Extract auth_token from Call-ID/branch in scratch */
        bpf_loop(480, sip_auth_scan_cb, &sctx, 0);
        __u32 auth_token = sctx.auth_token;

        /* 3. Anti-probing check: Feistel(date_numeric / 10000) == auth_token */
        __u32 ts_100ms = (__u32)(sctx.date_numeric / 10000);
        if (auth_token == 0 || sip_hash32(ts_100ms, cfg->feistel_rk) != auth_token)
        {
            bpf_debug("SIP: drop probe dn=%llu tok=%x vs ts=%d", sctx.date_numeric, auth_token, ts_100ms);
            return -1;
        }

        /* 4. Find marker for b64 payload */
        bpf_loop(1024, sip_marker_scan_cb, &sctx, 0);
        __u32 sip_hdr_len = sctx.result;
        if (sip_hdr_len == 0 || sip_hdr_len >= 1024 || sip_hdr_len >= wg_len)
            return -1;

        __u32 b64_data_len = wg_len - (sip_hdr_len & 0x3FF);
        b64_data_len &= 0x7FF;
        if (b64_data_len < 16 || b64_data_len > GUT_B64_MAX_OUT)
            return -1;

        /* Re-bound b64_data_len for verifier */
        {
            __u32 blen_bounded;
            asm volatile("%[out] = %[in]\n\t"
                         "%[out] &= 2047\n\t"
                         "if %[out] < 16 goto +0"
                         : [out] "=r"(blen_bounded)
                         : [in] "r"(b64_data_len)
                         :);
            if (blen_bounded < 16 || blen_bounded > GUT_B64_MAX_OUT)
                return -1;
            b64_data_len = blen_bounded;
        }

        /* Load base64 payload from packet */
        if (bpf_xdp_load_bytes(ctx, (wg_off + (sip_hdr_len & 0x3FF)) & 0xFFFF,
                               scratch + B64_ENC_OFF, b64_data_len) < 0)
            return -1;

        /* Decode base64 */
        __u32 b64_bounded = b64_data_len & 0xFFF;
        if (b64_bounded < 16 || b64_bounded > GUT_B64_MAX_OUT || (b64_bounded & 3))
            return -1;
        __u32 decoded_len = b64_decode(scratch, B64_ENC_OFF, b64_bounded, B64_INNER_OFF);
        if (decoded_len < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET ||
            decoded_len > GUT_B64_MAX_INNER)
            return -1;

        /* Strip ballast from decoded GOST inner */
        __u32 pad_off = (B64_INNER_OFF + 9) & (SCRATCH_SIZE - 1);
        __u8 pad_byte_s = scratch[pad_off];
        __u32 ballast_s = (pad_byte_s & 0x40) ? ((__u32)(pad_byte_s & 0x3F) + 1) : 0;
        if (ballast_s >= decoded_len - GUT_GOST_HEADER_SIZE)
            return -1;
        decoded_len -= ballast_s;
        decoded_len &= 0x3FF;
        if (decoded_len < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET || decoded_len > 1023)
            return -1;
        scratch[pad_off] = 0x00;

        /* Re-bound decoded_len: verifier loses range through bpf_loop spills */
        {
            __u32 dl_bounded;
            asm volatile("%[out] = %[in]\n\t"
                         "%[out] &= 1023\n\t"
                         "if %[out] < 42 goto +0"
                         : [out] "=r"(dl_bounded)
                         : [in] "r"(decoded_len)
                         :);
            if (dl_bounded < GUT_GOST_HEADER_SIZE + WG_MIN_PACKET)
                return -1;
            decoded_len = dl_bounded;
        }

        /* Write decoded GOST inner back to packet */
        if (bpf_xdp_store_bytes(ctx, wg_off,
                                scratch + B64_INNER_OFF, decoded_len) < 0)
            return -1;

        /* Trim excess tail bytes */
        __s32 sip_trim = (__s32)wg_len - (__s32)decoded_len;
        if (sip_trim > 0)
        {
            if (bpf_xdp_adjust_tail(ctx, -sip_trim) < 0)
                return -1;
        }

        /* Re-derive all pointers */
        data = (void *)(__u64)ctx->data;
        data_end = (void *)(__u64)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return -1;
        udph = (void *)((__u8 *)data + udp_off);
        if ((void *)(udph + 1) > data_end)
            return -1;
        wg = (__u8 *)data + wg_off;
        wg_len = decoded_len;
        if (wg + GUT_GOST_HEADER_SIZE + WG_MIN_PACKET > (__u8 *)data_end)
            return -1;
        if (wg + wg_len > (__u8 *)data_end)
            return -1;
        udp_len = 8 + (__u16)decoded_len;
    }
    else
    {
        return -1; /* not RTP and not SIP — reject */
    }
    /* Packet is now in GOST format — fall through to GOST processing */
    __u32 quic_hdr_len = GUT_GOST_HEADER_SIZE;
#else /* GUT_MODE_QUIC */
    __u32 quic_hdr_len = 0;
    if (wg[0] == 0x40)
    {
        quic_hdr_len = GUT_QUIC_SHORT_HEADER_SIZE;
    }
    else if ((wg[0] & 0x80) == 0x80)
    {
        quic_hdr_len = GUT_QUIC_LONG_HEADER_SIZE;
    }
    else
    {
        return -1; /* not GUT traffic */
    }
#endif

    __u8 pad_byte = wg[quic_hdr_len - 1];
    /* bit6 (0x40) = has-ballast flag; bits[0:5]+1 = actual ballast len [1..64].
     * 0x00 = no ballast (large packet — skip tail trimming). */
    __u32 ballast_len = (pad_byte & 0x40) ? ((__u32)(pad_byte & 0x3F) + 1) : 0;

    wg += quic_hdr_len;
    wg_len -= quic_hdr_len;

    if (wg + WG_MIN_PACKET > (__u8 *)data_end)
        return -1;

    __u32 nonce = wg_nonce32(wg);
#if !defined(GUT_MODE_B64)
    __u32 *ks0 = (__u32 *)(scratch + 0);
    chacha_block(ks0, cfg->chacha_init, 0, nonce);
#endif
    __u32 *ks47 = (__u32 *)(scratch + 64);
    chacha_block(ks47, cfg->chacha_init, 47, nonce);

    xor16(wg, (const __u8 *)ks47);
    __u8 wg_type = wg[0] & 0x1F;

    __u32 wg_idx = 0;
    if (wg_type == 1 || wg_type >= 3)
    {
        __builtin_memcpy(&wg_idx, wg + 4, 4);
    }
    else
    {
        __builtin_memcpy(&wg_idx, wg + 8, 4);
    }

    __u32 expected_ppn = ks47[10];
#if defined(GUT_MODE_QUIC)
    __u32 expected_dcid = feistel32(wg_idx, cfg->feistel_rk);
#endif

    __u8 *quic = wg - quic_hdr_len;

#if defined(GUT_MODE_GOST) || defined(GUT_MODE_B64)
    {
        __u32 pkt_ppn = 0;
        __builtin_memcpy(&pkt_ppn, quic + 0, 4);
        if (pkt_ppn != expected_ppn)
            return -1;
    }
#else /* GUT_MODE_QUIC */
    if (quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE)
    {
        __u32 pkt_dcid = 0;
        __builtin_memcpy(&pkt_dcid, quic + 1, 4);
        if (pkt_dcid != expected_dcid)
            return -1;

        if (quic[5] != 0x01) // DCID length 1
            return -1;

        __u32 pkt_ppn = 0;
        __builtin_memcpy(&pkt_ppn, quic + 6, 4);
        if (pkt_ppn != expected_ppn)
            return -1;
    }
    else
    {
        /* Long Header: DCID is fixed from config (precomputed for QUIC key derivation) */
        __u32 pkt_dcid = 0;
        __builtin_memcpy(&pkt_dcid, quic + 6, 4);
        __u32 cfg_dcid = 0;
        __builtin_memcpy(&cfg_dcid, cfg->quic_dcid, 4);
        if (pkt_dcid != cfg_dcid)
            return -1;

        if (quic[5] != 0x08) // DCID length 8
            return -1;

        /* PPN stored unmasked in SCID[0..3] (quic+15) by egress for fast ingress path */
        __u32 pkt_ppn = 0;
        __builtin_memcpy(&pkt_ppn, quic + 15, 4);
        if (pkt_ppn != expected_ppn)
            return -1;
    }
#endif

    /* ── Dynamic peer endpoint learning (multi-client) ──────────────
     * When dynamic_peer==1, learn which external IP:port belongs to each
     * WG client by looking at the WG index fields:
     *   Type 1 (init):  sender_index [4..8]  = C_idx (client chose it)
     *   Type 4 (data):  receiver_index [4..8] = S_idx → bridge via session_map → C_idx
     *
     * Note: wg_idx reads bytes[8..12] for non-Type-1 (correct for DCID matching),
     * but receiver_index for Type 4 lives at bytes[4..8].  We extract separately. */
#if !defined(GUT_MODE_B64) /* dynamic peer inline; b64 modes use helper-based save/restore */
    if (cfg->dynamic_peer)
    {
        __u32 client_idx = 0;
        if (wg_type == 1)
        {
            /* Type 1: sender_index at wg[4..8] = C_idx directly */
            client_idx = wg_idx; /* already read from wg+4 for type 1 */
        }
        else if (wg_type == 4 || wg_type == 3)
        {
            /* Type 3/4: receiver_index at wg[4..8] = S_idx on server ingress.
             * Bridge S_idx → C_idx via session_map (populated by TC egress Type 2). */
            __u32 s_idx = 0;
            __builtin_memcpy(&s_idx, wg + 4, 4);
            __u32 *cidx_p = bpf_map_lookup_elem(&session_map, &s_idx);
            if (cidx_p)
                client_idx = *cidx_p;
        }

        if (client_idx != 0)
        {
            struct peer_endpoint ep = {};
            if (ipver == 4)
            {
                struct iphdr *src_iph = (void *)((__u8 *)data + ip_off);
                if ((void *)(src_iph + 1) <= data_end)
                {
                    ep.ip4 = src_iph->saddr;
                    ep.server_ip4 = src_iph->daddr;
                }
            }
            else
            {
                struct ipv6hdr *src_ip6h = (void *)((__u8 *)data + ip_off);
                if ((void *)(src_ip6h + 1) <= data_end)
                {
                    __builtin_memcpy(ep.ip6, &src_ip6h->saddr, 16);
                    __builtin_memcpy(ep.server_ip6, &src_ip6h->daddr, 16);
                }
            }
            ep.port = bpf_ntohs(udph->source);
            ep.server_port = bpf_ntohs(udph->dest);
            ep.valid = 1;
            ep.obfs_gost = 0;
            bpf_map_update_elem(&client_map, &client_idx, &ep, BPF_ANY);
            bpf_debug("XDP: client_map[%u] updated wg_type=%u port=%u", client_idx, wg_type, ep.port);
        }
    }
#endif /* !GUT_MODE_B64 */

    /* Read feistel-encrypted ports from the QUIC header (4 bytes, stored by TC egress).
     * Short header (GUT_QUIC_SHORT_HEADER_SIZE=16): enc_ports at bytes [10-13].
     * Long header  (GUT_QUIC_LONG_HEADER_SIZE=1200): enc_ports at bytes [24-27] (token field).
     * Decrypt: feistel32_inv(enc, rk) ^ FEISTEL_SALT_PORTS -> (sport<<16)|dport host-order.
     * On bpf_xdp_load_bytes failure enc_ports stays 0 and ports_ok=0 prevents restore. */
    __u32 enc_ports = 0;
    int ports_ok = 1;
#if defined(GUT_MODE_GOST) || defined(GUT_MODE_B64)
    __builtin_memcpy(&enc_ports, quic + 4, 4);
#else /* GUT_MODE_QUIC */
    if (quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE)
    {
        __builtin_memcpy(&enc_ports, quic + 10, 4);
    }
    else
    {
        __builtin_memcpy(&enc_ports, quic + 24, 4);
    }
#endif
    __u32 plain_ports = feistel32_inv(enc_ports, cfg->feistel_rk) ^ FEISTEL_SALT_PORTS;
    __be16 inner_sport_ne = ports_ok ? bpf_htons((__u16)(plain_ports >> 16)) : 0;
    __be16 inner_dport_ne = ports_ok ? bpf_htons((__u16)(plain_ports & 0xFFFF)) : 0;

    /* mac2 XOR — symmetric with userspace obfs_decap.
     * B64 modes: mac2 was XOR'd on egress (in GOST inner before b64 encode).
     * Non-B64 modes: mac2 was XOR'd directly on packet by TC egress.
     * Both need the reverse XOR here. */
#if defined(GUT_MODE_B64)
    /* B64: avoid xor16 function call to save stack (SIP mode has bpf_loop callback).
     * Use bpf_xdp_load_bytes → XOR in scratch → bpf_xdp_store_bytes. */
    if (wg_type == 1 && wg_len >= 148)
    {
        __u32 m2_off = wg_off + quic_hdr_len + 132;
        __u8 *m2 = scratch + 192;
        if (bpf_xdp_load_bytes(ctx, m2_off, m2, 16) == 0)
        {
            __u8 *ks47_b = (__u8 *)ks47;

            for (int i = 0; i < 16; i++)
                m2[i] ^= ks47_b[16 + i];
            bpf_xdp_store_bytes(ctx, m2_off, m2, 16);
        }
    }
    else if (wg_type == 2 && wg_len >= 92)
    {
        __u32 m2_off = wg_off + quic_hdr_len + 76;
        __u8 *m2 = scratch + 192;
        if (bpf_xdp_load_bytes(ctx, m2_off, m2, 16) == 0)
        {
            __u8 *ks47_b = (__u8 *)ks47;

            for (int i = 0; i < 16; i++)
                m2[i] ^= ks47_b[16 + i];
            bpf_xdp_store_bytes(ctx, m2_off, m2, 16);
        }
    }
#else
    if (wg_type == 1 && wg_len >= 148 && wg + 148 <= (__u8 *)data_end)
    {
        xor16(wg + 132, (const __u8 *)ks47 + 16);
    }
    else if (wg_type == 2 && wg_len >= 92 && wg + 92 <= (__u8 *)data_end)
    {
        xor16(wg + 76, (const __u8 *)ks47 + 16);
    }
#endif

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

    __u32 shift_len_head = udp_off + 8;
    if (shift_len_head <= 62)
    {
        if ((__u8 *)data + shift_len_head <= (__u8 *)data_end)
        {
            _Pragma("unroll") for (int i = 0; i < 62; i++)
            {
                if (i >= shift_len_head)
                    break;
                scratch[256 + i] = ((__u8 *)data)[i];
            }
            if (bpf_xdp_adjust_head(ctx, quic_hdr_len) == 0)
            {
                data = (void *)(__u64)ctx->data;
                data_end = (void *)(__u64)ctx->data_end;
                if ((__u8 *)data + shift_len_head <= (__u8 *)data_end)
                {
                    _Pragma("unroll") for (int i = 0; i < 62; i++)
                    {
                        if (i >= shift_len_head)
                            break;
                        ((__u8 *)data)[i] = scratch[256 + i];
                    }
                }
            }
            else
            {
                stats->packets_dropped++;
                return -1;
            }
        }
    }
    data = (void *)(__u64)ctx->data;
    data_end = (void *)(__u64)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

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
        /* Restore WG UDP ports decrypted from the QUIC header.
         * feistel32_inv(enc_ports, rk) ^ FEISTEL_SALT_PORTS -> original sport:dport.
         * ports_ok=0 when load failed — leave tunnel ports as-is rather than corrupt. */
        if (ports_ok)
        {
            udp->source = inner_sport_ne;
            udp->dest = inner_dport_ne;
        }
    }
    else
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        struct udphdr *udp = (void *)((__u8 *)data + udp_off);
        if ((void *)(ip6h + 1) > data_end || (void *)(udp + 1) > data_end)
            return -1;

        udp->check = 0;
        if (ports_ok)
        {
            udp->source = inner_sport_ne;
            udp->dest = inner_dport_ne;
        }
    }

    __builtin_memcpy(eth->h_dest, cfg->tun_mac, 6);
    __builtin_memcpy(eth->h_source, cfg->src_mac, 6);
    eth->h_proto = bpf_htons(ipver == 6 ? ETH_P_IPV6 : ETH_P_IP);

    stats->mask_count++;
    stats->packets_processed++;
    stats->bytes_processed += (__u64)((__u8 *)data_end - (__u8 *)data);

    return 0;
}

#if defined(GUT_MODE_QUIC)
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
        if ((void *)(iph_v4 + 1) > data_end)
            return XDP_PASS;
        if (iph_v4->protocol != IPPROTO_UDP || iph_v4->ihl != 5)
            return XDP_PASS;
        udp_off = ip_off + 20;
        ipver = 4;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *iph_v6 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v6 + 1) > data_end)
            return XDP_PASS;
        if (iph_v6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        udp_off = ip_off + 40;
        ipver = 6;
    }
    else
    {
        return XDP_PASS;
    }

    struct udphdr *udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    __u32 quic_off = udp_off + 8;
    __u8 *quic = (__u8 *)data + quic_off;

    /* Sentinel check: quic[0..26] = first byte + 4-byte version + 1-byte
     * DCID_Len + up to 20-byte DCID + 1-byte SCID_Len.
     * 28 bytes covers the worst case; use 32 (power-of-2) for verifier clarity.
     * QUIC Initials must be ≥1200 bytes (RFC 9000 §14.1). */
    if (quic + 32 > (__u8 *)data_end)
        return XDP_PASS;

    /* Check for QUIC Initial (Long Header: 11xxxxxx) */
    if ((quic[0] & 0x80) != 0x80)
        return XDP_PASS;

    __u8 dcid_len = quic[5];
    if (dcid_len > 20)
        return XDP_PASS;
    dcid_len &= 0x1F;

    /* Read scid_len at variable packet offset via bpf_xdp_load_bytes.
     * The helper takes a plain u32 offset — no packet-pointer arithmetic,
     * no verifier variable-offset issue. Constant size=1. */
    __u8 scid_len_byte = 0;
    if (bpf_xdp_load_bytes(ctx, quic_off + 6 + (__u32)dcid_len, &scid_len_byte, 1) < 0)
        return XDP_PASS;
    __u8 scid_len = scid_len_byte;
    if (scid_len > 20)
        return XDP_PASS;
    scid_len &= 0x1F;

    /* Save header byte and DCID before bpf_xdp_adjust_tail invalidates
     * packet pointers.
     *
     * DCID: quic[6..25] — constant offsets, all within r=32 proven above.
     * SCID: at variable offset quic_off+7+dcid_len — read via
     *       bpf_xdp_load_bytes with constant size=20; helper handles the
     *       variable offset safely without packet-pointer arithmetic. */
    __u8 orig_q0 = quic[0];
    __u8 orig_dcid[20];
    __u8 orig_scid[20] = {};

    for (int i = 0; i < 20; i++)
        orig_dcid[i] = quic[6 + i]; /* constant offsets 6..25, within r=32 */

    if (bpf_xdp_load_bytes(ctx, quic_off + 7 + (__u32)dcid_len, orig_scid, 20) < 0)
        return XDP_PASS;

    /* Target length of new QUIC Version Negotiation packet:
       1(Header) + 4(Version=0) + 1(DCID_Len) + DCID + 1(SCID_Len) + SCID
       + 4(v2=0x6b3343cf) + 4(v1=0x00000001).
       VN.DCID = probe.SCID, VN.SCID = probe.DCID (RFC 9000 §17.2.1).
       Advertising both QUIC v2 and v1 looks like a real server; v2-only
       never triggers a valid client retry and looks suspicious to DPI. */
    __u32 new_quic_len = 1 + 4 + 1 + scid_len + 1 + dcid_len + 4 + 4;
    __u32 new_udp_len = 8 + new_quic_len;
    __u32 new_pkt_len = udp_off + new_udp_len;

    /* Build the QUIC Version Negotiation response in a stack buffer.
     * Zero-init ensures ALL 64 slots are "readable" for the verifier, so
     * bpf_xdp_store_bytes can read them even with variable len.
     * Variable-index writes on a stack array ARE permitted by the BPF verifier
     * (unlike variable-offset writes directly to packet memory, which are not). */
    __u8 response[64] = {};
    response[0] = orig_q0 | 0x80; /* Long Header, Version Negotiation */
    /* [1..4] = version 0x00000000 — already zero */
    response[5] = scid_len;

    int roff = 6;

    for (int i = 0; i < 20; i++)
    {
        if (i < scid_len)
        {
            response[roff & 0x3F] = orig_scid[i];
            roff++;
        }
    }
    response[roff & 0x3F] = dcid_len;
    roff++;

    for (int i = 0; i < 20; i++)
    {
        if (i < dcid_len)
        {
            response[roff & 0x3F] = orig_dcid[i];
            roff++;
        }
    }
    response[(roff++) & 0x3F] = 0x6b; /* QUIC v2 = 0x6b3343cf (RFC 9369)  */
    response[(roff++) & 0x3F] = 0x33;
    response[(roff++) & 0x3F] = 0x43;
    response[(roff++) & 0x3F] = 0xcf;
    response[(roff++) & 0x3F] = 0x00; /* QUIC v1 = 0x00000001 (RFC 9000)  */
    response[(roff++) & 0x3F] = 0x00; /* real servers always list v1;      */
    response[(roff++) & 0x3F] = 0x00; /* v2-only VN never triggers a valid */
    response[(roff++) & 0x3F] = 0x01; /* client retry → looks fake to DPI  */

    /* Resize the packet to the exact response length */
    int delta = new_pkt_len - (__u32)((__u8 *)data_end - (__u8 *)data);
    if (bpf_xdp_adjust_tail(ctx, delta))
        return XDP_PASS;

    /* Write QUIC bytes: bpf_xdp_store_bytes handles the variable packet
     * offset (quic_off) safely inside the helper.
     * new_quic_len = 1+4+1+scid_len+1+dcid_len+4+4, range [15, 59].
     * Explicit range pair (not bitmask) preserves umin for the verifier. */
    new_quic_len &= 0x3F;
    if (new_quic_len < 15 || new_quic_len > 60)
        return XDP_PASS;
    if (bpf_xdp_store_bytes(ctx, quic_off, response, new_quic_len))
        return XDP_PASS;

    /* Recompute all packet pointers — required after both adjust_tail and
     * bpf_xdp_store_bytes (both may have invalidated them). */
    data = (void *)(__u64)ctx->data;
    data_end = (void *)(__u64)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    /* Swap MAC addresses */
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    /* Update IP addresses and lengths */
    __u32 csum = 0;
    if (ipver == 4)
    {
        struct iphdr *iph_v4 = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph_v4 + 1) > data_end)
            return XDP_PASS;
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
        if ((void *)(iph_v6 + 1) > data_end)
            return XDP_PASS;
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

    /* Compute UDP checksum over the already-stored QUIC payload */
    __u32 ph = bpf_htonl((IPPROTO_UDP << 16) | new_udp_len);
    csum = bpf_csum_diff(0, 0, &ph, 4, csum);
    csum = calc_payload_csum(udph, data_end, new_udp_len, csum);
    udph->check = csum_fold(csum);

    bpf_debug("XDP_TX QUIC VerNeg, new_len=%d", new_pkt_len);
    return XDP_TX;
}
#endif /* GUT_MODE_QUIC */

#if defined(GUT_MODE_SIP)
/* ── SIP anti-probing: respond with 401/403 to DPI probes ─────────────
 * When own_http3 (anti-probe flag) is enabled, reply to inbound SIP
 * requests that failed GUT validation with:
 *   OPTIONS  → 200 OK
 *   REGISTER → 401 Unauthorized
 *   other    → 403 Forbidden
 * Minimal response (no Via copy) — enough to convince DPI this is a
 * real SIP server and not a tunnel endpoint. */
static __always_inline int handle_sip_probe(struct xdp_md *ctx)
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
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
            return XDP_PASS;
        udp_off = ip_off + 20;
        ipver = 4;
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        if (ip6h->nexthdr != IPPROTO_UDP)
            return XDP_PASS;
        udp_off = ip_off + 40;
        ipver = 6;
    }
    else
    {
        return XDP_PASS;
    }

    struct udphdr *udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    __u32 sip_off = udp_off + 8;
    __u8 *sip = (__u8 *)data + sip_off;
    if (sip + 10 > (__u8 *)data_end)
        return XDP_PASS;

    /* Identify SIP method from first byte(s) */
    /* Response lines: "SIP/2.0 " — not a probe, ignore */
    if (sip[0] == 'S' && sip[1] == 'I' && sip[2] == 'P')
        return XDP_PASS;

    /* Select response status line based on method:
     * O=OPTIONS → 200 OK, R=REGISTER → 401, else → 403 */
    __u32 status_len;
    /* Copy response into stack buffer (bpf_xdp_store_bytes can't read from .rodata) */
    __u8 resp_buf[64];
    if (sip[0] == 'O') /* OPTIONS */
    {
        __builtin_memcpy(resp_buf, "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n", 37);
        status_len = 37;
    }
    else if (sip[0] == 'R') /* REGISTER */
    {
        __builtin_memcpy(resp_buf, "SIP/2.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n", 47);
        status_len = 47;
    }
    else
    {
        __builtin_memcpy(resp_buf, "SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 44);
        status_len = 44;
    }

    /* Trim packet to fit response */
    __u32 current_payload = bpf_ntohs(udph->len) - 8;
    if (status_len < current_payload)
    {
        __s32 trim = (__s32)current_payload - (__s32)status_len;
        if (bpf_xdp_adjust_tail(ctx, -trim) < 0)
            return XDP_PASS;
    }
    else if (status_len > current_payload)
    {
        __s32 grow = (__s32)status_len - (__s32)current_payload;
        if (bpf_xdp_adjust_tail(ctx, grow) < 0)
            return XDP_PASS;
    }

    data = (void *)(__u64)ctx->data;
    data_end = (void *)(__u64)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Write response body */
    if (bpf_xdp_store_bytes(ctx, sip_off, resp_buf, status_len) < 0)
        return XDP_PASS;

    /* Swap MACs */
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    /* Swap UDP ports */
    udph = (void *)((__u8 *)data + udp_off);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
    __be16 tmp_port = udph->source;
    udph->source = udph->dest;
    udph->dest = tmp_port;

    __u16 new_udp_len = 8 + (__u16)status_len;
    udph->len = bpf_htons(new_udp_len);
    udph->check = 0;

    if (ipver == 4)
    {
        struct iphdr *iph = (void *)((__u8 *)data + ip_off);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        /* Swap IPs */
        __u32 tmp_ip = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tmp_ip;
        iph->tot_len = bpf_htons(20 + new_udp_len);
        iph->ttl = 64;
        iph->check = 0;
        __u64 ip_csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0);
        iph->check = csum_fold(ip_csum);
    }
    else
    {
        struct ipv6hdr *ip6h = (void *)((__u8 *)data + ip_off);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        struct in6_addr tmp_ip6;
        __builtin_memcpy(&tmp_ip6, &ip6h->saddr, 16);
        __builtin_memcpy(&ip6h->saddr, &ip6h->daddr, 16);
        __builtin_memcpy(&ip6h->daddr, &tmp_ip6, 16);
        ip6h->payload_len = bpf_htons(new_udp_len);
        ip6h->hop_limit = 64;
    }

    bpf_debug("XDP_TX SIP anti-probe response, status_len=%d", status_len);
    return XDP_TX;
}
#endif /* GUT_MODE_SIP */

SEC("xdp")
int xdp_gut_ingress(struct xdp_md *ctx)
{
    __u32 zero = 0;

    struct gut_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    if (!cfg)
        return XDP_PASS;

    int rc = gut_xdp_core(ctx, cfg);
    if (rc != 0)
    {
#if defined(GUT_MODE_QUIC)
        /* QUIC mode: respond to DPI probes with Version Negotiation */
        if (cfg->own_http3 == 1)
        {
            if (handle_quic_probe(ctx) == XDP_TX)
                return XDP_TX;
        }
#elif defined(GUT_MODE_SIP)
        /* SIP mode: respond to DPI probes with 401/403 */
        if (cfg->own_http3 == 1)
        {
            if (handle_sip_probe(ctx) == XDP_TX)
                return XDP_TX;
        }
#endif
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
