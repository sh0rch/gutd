/* GUT v1 Protocol TC/XDP eBPF Common Definitions
 *
 * Current branch uses payload-only WG mode in datapath:
 * - no extra nonce/pkt_id/cookie wire header on outer UDP payload
 * - optional ballast is appended to UDP payload
 */

#ifndef __GUT_COMMON_H__
#define __GUT_COMMON_H__

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PORTS 6
/* Short header layout (14 bytes):
 * [0]=0x40 [1-4]=DCID [5-8]=PPN [9-10]=inner_sport_be [11-12]=inner_dport_be [13]=pad_len
 * Long header layout (100 bytes):
 * [0]=0xC0 [1-4]=version [5]=dcid_len [6-13]=dcid [14]=scid_len [15-22]=scid
 * [23]=token_len [24-25]=length [26-29]=PPN [30-31]=inner_sport_be [32-33]=inner_dport_be
 * [34-98]=PRNG gost [99]=pad_len
 * TC egress stores the original WG UDP src/dst ports so XDP can restore them
 * after decapsulation, preserving the conntrack/WG port numbers end-to-end. */
#define GUT_QUIC_SHORT_HEADER_SIZE 16
#define GUT_QUIC_LONG_HEADER_SIZE 1200
#define GUT_KEY_SIZE 32
#define MAX_PACKET_SIZE 1500
#define SCRATCH_SIZE 4096                    /* scratch buffer: power-of-2.  Must be > MAX_PACKET_SIZE + 1 \
                                              * so BPF_BOUND_LEN ([1,2048]) with scratch+1 stays within    \
                                              * map value bounds (off=1 + 2048 ≤ 4096).                  \
                                              * mask_data_fast uses (i &= 0x7FF) → max 2047+7 < 4096.       */
#define MAX_INNER_TECH_LIMIT MAX_PACKET_SIZE /* technical verifier/scratch cap, runtime MTU comes from config_map */

/* Masking: always ChaCha (rounds configured at compile time) */

/* Packet flags */
#define FLAG_SINGLE 0

/* Payload-only mode: no extra protocol bytes above UDP payload */
#define GUT_WIRE_HDR_SIZE 0
#define GUT_MIN_OVERHEAD 0

/* Variable-length ballast: ChaCha-derived 0..63 bytes appended inside masked body
 * inner length from IP header; remainder is ballast (ignored). */
#define BALLAST_MAX 63
#define GUT_PMTU_RESERVE 20
#define GUT_OUTER_OVERHEAD_V4 (8 + 20 + GUT_PMTU_RESERVE)
#define GUT_OUTER_OVERHEAD_V6 (8 + 40 + GUT_PMTU_RESERVE)
#define GUT_DEFAULT_INNER_MTU 1492

/* Flag alias */
#define GUT_FLAG_SINGLE FLAG_SINGLE

/* ip_summed values (from linux/skbuff.h; not included in BPF builds) */
#define CHECKSUM_NONE 0        /* checksum already in packet, or not needed */
#define CHECKSUM_UNNECESSARY 1 /* HW validated, no need to check */
#define CHECKSUM_COMPLETE 2    /* HW-computed full csum in skb->csum */
#define CHECKSUM_PARTIAL 3     /* pseudo-header only in field; data portion missing */

/* Offload capability flags (set by loader) */
#define GUT_FLAG_NEED_L4_CSUM (1U << 0) /* finalize inner L4 csum when ip_summed==CHECKSUM_PARTIAL */

/* GUT protocol configuration (shared between Rust loader and eBPF) */
struct gut_config
{
    __u8 key[GUT_KEY_SIZE]; /* Masking key (256 bits) */
    __u16 ports[MAX_PORTS]; /* Port striping array */
    __u32 num_ports;        /* Number of active ports */
    __u16 outer_mtu;        /* Max outer UDP payload size */
    __u16 inner_mtu_v4;     /* Precomputed inner IPv4 MTU */
    __u16 inner_mtu_v6;     /* Precomputed inner IPv6 MTU */
    __u32 peer_ip;          /* Peer IP address (network byte order) */
    __u32 bind_ip;          /* Local bind IP (network byte order) */
    __u32 egress_ifindex;   /* Physical NIC ifindex for bpf_redirect (egress→NIC) */
    __u32 tun_ifindex;      /* TUN ifindex for bpf_redirect (ingress→TUN) */
    __u8 src_mac[6];        /* Source MAC (local NIC) */
    __u8 dst_mac[6];        /* Dest MAC (gateway/peer) */
    __u8 tun_mac[6];        /* TUN/TAP MAC for PACKET_HOST on redirect */
    __u16 offload_flags;    /* GUT_FLAG_NEED_* bitmask from loader */

    /* --- Precomputed by loader (avoid per-packet key expansion) --- */
    __u32 chacha_init[12];       /* ChaCha state[0..11]: constants(4) + key_words(8) */
    __u8 chacha_rounds;          /* ChaCha round count (2,4,6,...,20). Default: 4 */
    __u32 partial_ip_csum;       /* Precomputed partial IP header checksum (fixed fields) */
    __u8 default_xdp_action;     /* XDP action for non-GUT packets: 0=XDP_PASS, 1=XDP_DROP */
    __u8 keepalive_drop_percent; /* Keepalive drop probability in % (0..100) */
    __u32 feistel_rk[4];         /* Feistel32 round keys (derived from key via ChaCha) */
    __u8 peer_ip6[16];           /* Peer IPv6 address (network byte order, zero if v4) */
    __u8 bind_ip6[16];           /* Local bind IPv6 (network byte order, zero if v4) */
    __u32 tun_local_ip4;         /* Local veth (gut0) IP — XDP ingress rewrites dst to this */
    __u32 tun_peer_ip4;          /* Remote veth peer IP — XDP ingress rewrites src to this */
    __u8 tun_local_ip6[16];      /* Local veth IPv6 (zero if v4 only) */
    __u8 tun_peer_ip6[16];       /* Remote veth peer IPv6 (zero if v4 only) */
    __u8 own_http3;              /* Respond to DPI probes via XDP_TX (1=yes) */
    __u8 dynamic_peer;           /* 1 = peer_ip unknown, learn from validated inbound packets */
    __u8 obfs_gost;             /* 1 = gost mode: XOR quic[0..6] with quic[6..12] to hide QUIC signatures */
} __attribute__((packed));

/* Dynamic peer endpoint — learned from validated inbound packets.
 * Updated by XDP ingress after DCID/PPN crypto-validation passes.
 * Read by TC egress to set outer IP dst + UDP dst port.
 * In multi-client mode, keyed by WG receiver_index (C_idx). */
struct peer_endpoint
{
    __u32 ip4;           /* Last-seen IPv4 source (client) */
    __u8 ip6[16];        /* Last-seen IPv6 source (client) */
    __u16 port;          /* Last-seen UDP source port (client) */
    __u16 _pad_port;     /* alignment */
    __u32 server_ip4;    /* Last-seen IPv4 dest (server) */
    __u8 server_ip6[16]; /* Last-seen IPv6 dest (server) */
    __u16 server_port;   /* Last-seen UDP dest port (server) */
    __u8 valid;          /* 1 = endpoint learned, 0 = not yet */
    __u8 obfs_gost;     /* 1 = this client uses gost mode, 0 = plain quic (auto-detected) */
};

/* Per-CPU statistics */
struct gut_stats
{
    __u64 packets_processed;
    __u64 packets_dropped;
    __u64 bytes_processed;
    __u64 _reserved_stat;
    __u64 mask_count;
    __u64 packets_fragmented;
    __u64 inner_tcp_seen;
};

/* Monotonic sequence counter for packets */
struct gut_counters
{
    __u32 seq;
};

/* BPF Maps */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct gut_config);
} config_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct gut_stats);
} stats_map SEC(".maps");

/* Atomic counters map */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct gut_counters);
} counters_map SEC(".maps");

/* Scratch buffer map (per-CPU to avoid stack overflow).
 * SCRATCH_SIZE > MAX_PACKET_SIZE to give the BPF verifier headroom
 * for offset arithmetic after inline-asm bounds masks. */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[SCRATCH_SIZE]);
} scratch_map SEC(".maps");

/* Multi-client dynamic peer maps — used when gut_config.dynamic_peer == 1.
 *
 * client_map: WG client_index (C_idx) → peer_endpoint.
 *   Written by XDP ingress after crypto-validation (Type 1: sender_index,
 *   Type 4: bridged via session_map).
 *   Read by TC egress to determine destination (Type 2/4: receiver_index = C_idx).
 *
 * session_map: WG server_index (S_idx) → C_idx.
 *   Written by TC egress on Type 2 (response) where sender=S_idx, receiver=C_idx.
 *   Read by XDP ingress on Type 4 where receiver=S_idx, to bridge back to C_idx.
 *
 * LRU automatically evicts stale entries on WG rekey (~120s). */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct peer_endpoint);
} client_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} session_map SEC(".maps");

/* Compile-time ChaCha round count.  Override at build via -DCHACHA_ROUNDS=N.
 * Must match between sender and receiver BPF programs.
 * Default: 4 (ChaCha4 — 2 double-rounds).  Valid: 2,4,6,...,20. */
#ifndef CHACHA_ROUNDS
#define CHACHA_ROUNDS 4
#endif

/* ── ChaCha keystream (compile-time rounds, 64 bytes/block) ──────────
 *
 * Replaces splitmix64 for masking.  ChaCha is self-synchronising
 * (mask == unmask) and generates 64 bytes per block, so both egress
 * (in-place) and XDP ingress (in-place) consume identical keystream.
 *
 * State layout (16 × u32):
 *   [0..3]   = "expand 32-byte k" constants  ─┐ precomputed in
 *   [4..11]  = key words (8×u32 LE)           ─┘ chacha_init[12]
 *   [12]     = block counter (starts 0, ++)
 *   [13]     = nonce LE u32
 *   [14..15] = 0
 *
 * Must match src/proto/mask_balanced.rs (FastChaCha20 with 2 double-rounds).
 */

/* ChaCha quarter-round on named variables (kept for reference / external use). */
#define CHACHA_QR(a, b, c, d)      \
    do                             \
    {                              \
        a += b;                    \
        d ^= a;                    \
        d = (d << 16) | (d >> 16); \
        c += d;                    \
        b ^= c;                    \
        b = (b << 12) | (b >> 20); \
        a += b;                    \
        d ^= a;                    \
        d = (d << 8) | (d >> 24);  \
        c += d;                    \
        b ^= c;                    \
        b = (b << 7) | (b >> 25);  \
    } while (0)

/* ChaCha quarter-round on a __u32 state array at compile-time-constant indices.
 * All index arguments must be integer literals so the BPF verifier sees fixed offsets. */
#define CHACHA_QR_IDX(st, ai, bi, ci, di)         \
    do                                            \
    {                                             \
        st[ai] += st[bi];                         \
        st[di] ^= st[ai];                         \
        st[di] = (st[di] << 16) | (st[di] >> 16); \
        st[ci] += st[di];                         \
        st[bi] ^= st[ci];                         \
        st[bi] = (st[bi] << 12) | (st[bi] >> 20); \
        st[ai] += st[bi];                         \
        st[di] ^= st[ai];                         \
        st[di] = (st[di] << 8) | (st[di] >> 24);  \
        st[ci] += st[di];                         \
        st[bi] ^= st[ci];                         \
        st[bi] = (st[bi] << 7) | (st[bi] >> 25);  \
    } while (0)

/* One ChaCha double-round (column + diagonal) operating in-place on st[16].
 * Uses CHACHA_QR_IDX so all indices are compile-time constants — no stack needed. */
#define CHACHA_DOUBLE_ROUND_IDX(st)  \
    CHACHA_QR_IDX(st, 0, 4, 8, 12);  \
    CHACHA_QR_IDX(st, 1, 5, 9, 13);  \
    CHACHA_QR_IDX(st, 2, 6, 10, 14); \
    CHACHA_QR_IDX(st, 3, 7, 11, 15); \
    CHACHA_QR_IDX(st, 0, 5, 10, 15); \
    CHACHA_QR_IDX(st, 1, 6, 11, 12); \
    CHACHA_QR_IDX(st, 2, 7, 8, 13);  \
    CHACHA_QR_IDX(st, 3, 4, 9, 14)

/* Generate 64 bytes of ChaCha keystream into ks[16].
 * chacha_init[12] = loader-precomputed constants+key.
 * counter = block index (0, 1, 2, ...).
 * nonce   = per-packet nonce (u32 LE).
 * Rounds = compile-time CHACHA_ROUNDS.  NO LOOPS — #if-chain only.
 *
 * Working state is kept entirely in ks[] (the caller-provided buffer, which
 * lives in the scratch per-CPU map) so that chacha_block itself has zero
 * u32 local variables on the BPF 512-byte stack.  The initial state is
 * re-read from the chacha_init pointer for the final addition. */
static __attribute__((noinline)) void chacha_block(__u32 ks[16],
                                                   const __u32 chacha_init[12],
                                                   __u32 counter, __u32 nonce)
{
    /* Load initial state into ks[] — no s0..s15 locals, no stack pressure. */
    ks[0] = chacha_init[0];
    ks[1] = chacha_init[1];
    ks[2] = chacha_init[2];
    ks[3] = chacha_init[3];
    ks[4] = chacha_init[4];
    ks[5] = chacha_init[5];
    ks[6] = chacha_init[6];
    ks[7] = chacha_init[7];
    ks[8] = chacha_init[8];
    ks[9] = chacha_init[9];
    ks[10] = chacha_init[10];
    ks[11] = chacha_init[11];
    ks[12] = counter;
    ks[13] = nonce;
    ks[14] = 0;
    ks[15] = 0;

    /* Double-round 1 — ChaCha2 (always, minimum) */
    CHACHA_DOUBLE_ROUND_IDX(ks);

    /* Double-round 2 — ChaCha4 */
#if (CHACHA_ROUNDS >= 4)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 3 — ChaCha6 */
#if (CHACHA_ROUNDS >= 6)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 4 — ChaCha8 */
#if (CHACHA_ROUNDS >= 8)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 5 — ChaCha10 */
#if (CHACHA_ROUNDS >= 10)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 6 — ChaCha12 */
#if (CHACHA_ROUNDS >= 12)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 7 — ChaCha14 */
#if (CHACHA_ROUNDS >= 14)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 8 — ChaCha16 */
#if (CHACHA_ROUNDS >= 16)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 9 — ChaCha18 */
#if (CHACHA_ROUNDS >= 18)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Double-round 10 — ChaCha20 */
#if (CHACHA_ROUNDS >= 20)
    CHACHA_DOUBLE_ROUND_IDX(ks);
#endif

    /* Add initial state back (re-read chacha_init instead of keeping copies). */
    ks[0] += chacha_init[0];
    ks[1] += chacha_init[1];
    ks[2] += chacha_init[2];
    ks[3] += chacha_init[3];
    ks[4] += chacha_init[4];
    ks[5] += chacha_init[5];
    ks[6] += chacha_init[6];
    ks[7] += chacha_init[7];
    ks[8] += chacha_init[8];
    ks[9] += chacha_init[9];
    ks[10] += chacha_init[10];
    ks[11] += chacha_init[11];
    ks[12] += counter;
    ks[13] += nonce;
    /* ks[14] += 0 and ks[15] += 0 are no-ops; values stay correct. */
}

/* XOR up to 64 bytes of data[] (at offset `off`) with keystream ks[16].
 * `n` is the number of bytes to XOR (0..64).
 * Full 64-byte blocks use u32 XOR (16 ops), tail uses byte XOR. */
static __always_inline void xor_ks(__u8 *data, __u32 off, __u32 n,
                                   const __u32 ks[16])
{
    __u32 o = off & 0x7FF;
    if (n == 64 && o + 64 <= SCRATCH_SIZE)
    {
        __u32 *p = (__u32 *)(data + o);
#pragma unroll
        for (__u32 j = 0; j < 16; j++)
            p[j] ^= ks[j];
    }
    else
    {
        const __u8 *kbytes = (const __u8 *)ks;
#pragma unroll
        for (__u32 j = 0; j < 64; j++)
        {
            if (j < n)
            {
                __u32 oj = (off + j) & 0x7FF;
                data[oj] ^= kbytes[j];
            }
        }
    }
}

/* ── Context and callback for bpf_loop-based ChaCha masking ──── */
struct chacha_ctx
{
    __u8 *data;
    __u32 len;
    __u32 i;     /* byte offset processed so far */
    __u32 block; /* ChaCha block counter */
    __u32 nonce;
    const __u32 *chacha_init;
};

static long chacha_loop_cb(__u32 idx, void *_ctx)
{
    struct chacha_ctx *ctx = (struct chacha_ctx *)_ctx;
    __u32 i = ctx->i;
    if (i >= ctx->len)
        return 1;

    __u32 ks[16];
    chacha_block(ks, ctx->chacha_init, ctx->block, ctx->nonce);
    ctx->block++;

    __u32 remain = ctx->len - i;
    __u32 n = remain < 64 ? remain : 64;

    asm volatile("" : "+r"(i));
    i &= 0x7FF;
    if (i > SCRATCH_SIZE - 64)
        return 1;

    xor_ks(ctx->data, i, n, ks);
    ctx->i += 64; /* always advance by block size for counter sync */
    return 0;
}

/* Mask/unmask data using ChaCha keystream via bpf_loop.
 * Processes 64 bytes per iteration.  Self-inverse (mask == unmask).
 * MUST match src/proto/mask_balanced.rs exactly. */
static __always_inline void mask_data_chacha(__u8 *data, __u32 len,
                                             const __u32 chacha_init[12],
                                             __u32 nonce)
{
    if (len > MAX_PACKET_SIZE)
        len = MAX_PACKET_SIZE;

    struct chacha_ctx ctx = {
        .data = data,
        .len = len,
        .i = 0,
        .block = 0,
        .nonce = nonce,
        .chacha_init = chacha_init,
    };

    bpf_loop(MAX_PACKET_SIZE / 64 + 1, chacha_loop_cb, &ctx, 0);
}

/* ── ChaCha-derived ballast & nonce chain ─────────────────────────
 * All randomness derived from the same ChaCha keystream used for masking,
 * just at high block counters that never overlap with data blocks
 * (MAX_PACKET_SIZE=1500 → max 24 data blocks).
 *
 * Block 99 (counter=99, same nonce):
 *   bytes  0..62 = ballast data (up to 63 bytes)
 *   byte  63 bits[0:5] = ballast_len (0..63)
 *
 * Block 111 (counter=111, same nonce):
 *   words[0] = next_nonce (u32 LE), guaranteed non-zero
 *   words[1] = next_pkt_id (u32 LE), guaranteed non-zero
 *   Always computed — eliminates all separate PRNGs from datapath.
 *
 * Loader seeds initial (nonce, pkt_id) into counters_map.
 * Receiver never predicts nonce — reads it from wire header.
 */
#define CHACHA_BLOCK_BALLAST 99
#define CHACHA_BLOCK_NEXT_IDS 111

/* Generate ballast data + length from ChaCha block 99.
 * Writes up to 63 bytes into ballast_out, returns ballast_len.
 * max_body = maximum body bytes available for inner + ballast. */
static __always_inline __u32 chacha_ballast(
    __u8 *ballast_out, __u32 inner_len, __u32 max_body,
    const __u32 chacha_init[12], __u32 nonce)
{
        return 0;

    __u32 ks[16];
    chacha_block(ks, chacha_init, CHACHA_BLOCK_BALLAST, nonce);

    const __u8 *kb = (const __u8 *)ks;
    __u32 bl = kb[63] & 0x3F; /* 0..63 */
    __u32 body_used = inner_len;
    if (body_used + bl > max_body)
        bl = max_body - body_used;

    /* Copy ballast bytes (unrolled, max 63) */
#pragma unroll
    for (__u32 j = 0; j < 63; j++)
    {
        if (j < bl)
            ballast_out[j] = kb[j];
    }
    return bl;
}

/* Derive next nonce and pkt_id from ChaCha block 111 (same nonce).
 * Returns (next_nonce, next_pkt_id) via out-params. Both guaranteed non-zero. */
static __always_inline void chacha_next_ids(
    const __u32 chacha_init[12], __u32 nonce,
    __u32 *out_nonce, __u32 *out_pkt_id)
{
    __u32 ks[16];
    chacha_block(ks, chacha_init, CHACHA_BLOCK_NEXT_IDS, nonce);
    *out_nonce = ks[0] ? ks[0] : 1;
    *out_pkt_id = ks[1] ? ks[1] : 1;
}

/* Helper: check if port is in ports[] array */
static __always_inline int is_gut_port(__u16 port, const struct gut_config *cfg)
{
#pragma unroll
    for (__u32 i = 0; i < MAX_PORTS; i++)
    {
        if (i >= cfg->num_ports)
            break;
        if (cfg->ports[i] == port)
            return 1;
    }
    return 0;
}

/* Select destination port using port striping */
static __always_inline __u16 select_port(__u32 pkt_id, const struct gut_config *cfg)
{
    if (cfg->num_ports == 0)
        return 0;
    __u32 idx = pkt_id % cfg->num_ports;
    if (idx >= MAX_PORTS)
        return 0;
    return cfg->ports[idx];
}

/* ── Feistel32: 4-round balanced Feistel network (u32 → u32 PRP) ─────
 *
 * Bijection on [0, 2^32): every input maps to a unique output.
 * Used to generate pseudorandom wire nonce and pkt_id from a monotonic
 * sequence counter — unpredictable without key knowledge, yet unique.
 *
 * Salt constants for domain separation: different salts produce
 * independent permutations from the same round keys. */
#define FEISTEL_SALT_PKT_ID 0x9E3779B9u  /* golden ratio × 2^32 */
#define FEISTEL_SALT_BALLAST 0x517CC1B7u /* sqrt(3) × 2^32 */
#define FEISTEL_SALT_PORTS 0xB7E15163u   /* 2π × 2^31 — domain for port encryption */

static __always_inline __u32 feistel32(__u32 x, const __u32 rk[4])
{
    __u16 lo = (__u16)(x & 0xFFFF);
    __u16 hi = (__u16)(x >> 16);

#pragma unroll
    for (int i = 0; i < 4; i++)
    {
        __u32 f = ((__u32)lo * 0x9E37 + rk[i]) ^ ((__u32)lo << 3) ^ ((__u32)lo >> 5);
        __u16 new_lo = hi ^ (__u16)(f & 0xFFFF);
        hi = lo;
        lo = new_lo;
    }

    return ((__u32)hi << 16) | (__u32)lo;
}

/* ── feistel32_inv: exact inverse of feistel32 ────────────────────────
 *
 * Forward round: {lo, hi} → {hi ^ F(lo), lo}
 * Inverse round: given {lo', hi'} = {hi^F(lo_old), lo_old}
 *   lo_old = hi'   →   hi_old = lo' ^ F(hi')
 * Decrypt: run rounds in reverse order with same round-function. */
static __always_inline __u32 feistel32_inv(__u32 x, const __u32 rk[4])
{
    __u16 lo = (__u16)(x & 0xFFFF);
    __u16 hi = (__u16)(x >> 16);

#pragma unroll
    for (int i = 3; i >= 0; i--)
    {
        __u16 lo_old = hi;
        __u32 f = ((__u32)hi * 0x9E37 + rk[i]) ^ ((__u32)hi << 3) ^ ((__u32)hi >> 5);
        __u16 hi_old = lo ^ (__u16)(f & 0xFFFF);
        lo = lo_old;
        hi = hi_old;
    }

    return ((__u32)hi << 16) | (__u32)lo;
}

/* Compiler barriers for BPF verifier (technique from libbpf_wgobfs) */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif

/* Force verifier to see bounds check */
#define FORCE_BOUNDS_CHECK(val, max) \
    do                               \
    {                                \
        if ((val) > (max))           \
            (val) = (max);           \
        barrier_var(val);            \
    } while (0)

/* Verifier-safe wrappers in libbpf_wgobfs style */
static __always_inline int gut_skb_load_bounded(struct __sk_buff *skb, __u32 off, void *dst, __u32 len, __u32 max)
{
    len &= 0xffff;
    if (len == 0 || len > max)
        return -1;
    barrier_var(len);
    return bpf_skb_load_bytes(skb, off, dst, len);
}

static __always_inline int gut_skb_store_bounded(struct __sk_buff *skb, __u32 off, const void *src, __u32 len, __u64 flags, __u32 max)
{
    len &= 0xffff;
    if (len == 0 || len > max)
        return -1;
    barrier_var(len);
    return bpf_skb_store_bytes(skb, off, src, len, flags);
}

/* Fold a 64-bit checksum accumulator into a 16-bit one's-complement result.
 * Shared by TC egress (bpf_csum_diff) and XDP ingress (bpf_csum_diff). */
static __always_inline __u16 csum_fold(__u64 csum)
{
#pragma unroll
    for (int i = 0; i < 4; i++)
        if (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)(~csum);
}

static __always_inline void fix_ipv4_header_checksum(__u8 *scratch, __u32 inner_len)
{
    const __u32 B = 0;

    if (inner_len < 20)
        return;
    if (inner_len > MAX_INNER_TECH_LIMIT)
        return;

    __u8 version = scratch[B] >> 4;
    if (version != 4)
        return;

    __u32 ihl = ((__u32)(scratch[B] & 0x0F)) * 4;
    if (ihl < 20 || ihl > 60)
        return;
    if (ihl > inner_len)
        return;

    __u32 check_off = B + 10;
    scratch[check_off] = 0;
    scratch[check_off + 1] = 0;

    __u32 sum = 0;
#pragma unroll
    for (int i = 0; i < 30; i++)
    {
        __u32 off = (__u32)i * 2;
        if (off + 1 >= ihl)
            break;
        __u32 p = B + off;
        sum += ((__u32)scratch[p] << 8) | (__u32)scratch[p + 1];
    }

#pragma unroll
    for (int i = 0; i < 4; i++)
        if (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

    __u16 hc = ~((__u16)sum);
    scratch[check_off] = (__u8)(hc >> 8);
    scratch[check_off + 1] = (__u8)(hc & 0xFF);
}

/* ── Finalize inner L4 (TCP/UDP) checksum ─────────────────────────────
 *
 * At TC egress on TAP, ip_summed=CHECKSUM_PARTIAL: the L4 checksum field
 * contains ~pseudo_header_sum, and the kernel expects HW or a later stage
 * to complete it.  Since we copy raw bytes into scratch and XOR-mask them,
 * we must finalize the L4 checksum BEFORE masking.  On ingress, unmask
 * restores the finalized bytes losslessly, so no L4 fixup is needed there.
 *
 * Strategy: zero the L4 checksum field, recompute from scratch over
 * pseudo-header + L4 segment.  Uses bpf_loop for verifier compliance.
 */

struct l4_csum_ctx
{
    __u8 *scratch;
    __u32 l4_start;
    __u32 l4_len;
    __u32 i;
    __u32 sum;
};

/* Sum 8 bytes (four 16-bit BE words) per bpf_loop iteration. */
static long __l4_csum_word_cb(__u32 idx, void *ctx_ptr)
{
    struct l4_csum_ctx *ctx = (struct l4_csum_ctx *)ctx_ptr;
    (void)idx;

    __u32 i = ctx->i;
    if (i + 7 >= ctx->l4_len)
        return 1;

    __u32 off = ctx->l4_start + i;
    asm volatile("" : "+r"(off));
    off &= 0x7FF;
    if (off > SCRATCH_SIZE - 8)
        return 1;

    ctx->sum += ((__u32)ctx->scratch[off + 0] << 8) | (__u32)ctx->scratch[off + 1];
    ctx->sum += ((__u32)ctx->scratch[off + 2] << 8) | (__u32)ctx->scratch[off + 3];
    ctx->sum += ((__u32)ctx->scratch[off + 4] << 8) | (__u32)ctx->scratch[off + 5];
    ctx->sum += ((__u32)ctx->scratch[off + 6] << 8) | (__u32)ctx->scratch[off + 7];
    ctx->i = i + 8;
    return 0;
}

static __always_inline void fix_l4_checksum(__u8 *scratch, __u32 inner_len)
{
    const __u32 B = 0;

    if (inner_len < 28)
        return;
    if (inner_len > MAX_INNER_TECH_LIMIT)
        return;

    __u8 version = scratch[B] >> 4;
    if (version != 4)
        return;

    __u32 ihl = ((__u32)(scratch[B] & 0x0F)) * 4;
    if (ihl != 20)
        return; /* no IP options supported */

    __u8 proto = scratch[B + 9];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
        return;

    __u32 ip_tot_len = ((__u32)scratch[B + 2] << 8) | (__u32)scratch[B + 3];
    if (ip_tot_len > inner_len)
        ip_tot_len = inner_len;
    if (ip_tot_len < 28)
        return;

    __u32 l4_len = ip_tot_len - 20;
    if (l4_len < 8)
        return;
    if (l4_len > MAX_INNER_TECH_LIMIT)
        l4_len = MAX_INNER_TECH_LIMIT;

    const __u32 l4_start = B + 20;

    /* Zero checksum field: TCP=16, UDP=6, ICMP=2 */
    __u32 csum_off;
    if (proto == IPPROTO_TCP)
        csum_off = 16;
    else if (proto == IPPROTO_ICMP)
        csum_off = 2;
    else
        csum_off = 6; /* UDP */
    if (csum_off + 2 > l4_len)
        return;
    __u32 zpos = l4_start + csum_off;
    if (zpos + 2 > SCRATCH_SIZE)
        return;
    scratch[zpos] = 0;
    scratch[zpos + 1] = 0;

    /* Pseudo-header (TCP/UDP only; ICMP has no pseudo-header) */
    __u32 sum = 0;
    if (proto != IPPROTO_ICMP)
    {
        sum += ((__u32)scratch[B + 12] << 8) | (__u32)scratch[B + 13]; /* src ip */
        sum += ((__u32)scratch[B + 14] << 8) | (__u32)scratch[B + 15];
        sum += ((__u32)scratch[B + 16] << 8) | (__u32)scratch[B + 17]; /* dst ip */
        sum += ((__u32)scratch[B + 18] << 8) | (__u32)scratch[B + 19];
        sum += (__u32)proto;
        sum += (__u32)l4_len;
    }

    /* Sum L4 segment via bpf_loop (8 bytes = 4 words per iteration) */
    struct l4_csum_ctx ctx = {
        .scratch = scratch,
        .l4_start = l4_start,
        .l4_len = l4_len,
        .i = 0,
        .sum = sum,
    };
    bpf_loop(MAX_INNER_TECH_LIMIT / 8 + 1, __l4_csum_word_cb, &ctx, 0);
    sum = ctx.sum;

    /* Remaining 0..7 tail bytes (sum 16-bit words manually) */
    __u32 ti = ctx.i;
#pragma unroll
    for (int t = 0; t < 3; t++)
    {
        if (ti + 1 < l4_len)
        {
            __u32 toff = l4_start + ti;
            asm volatile("" : "+r"(toff));
            toff &= 0x7FF;
            __u32 toff1 = (toff + 1) & 0x7FF;
            sum += ((__u32)scratch[toff] << 8) | (__u32)scratch[toff1];
            ti += 2;
        }
    }

    /* Odd trailing byte */
    if (l4_len & 1)
    {
        __u32 tail = l4_start + l4_len - 1;
        asm volatile("" : "+r"(tail));
        tail &= 0x7FF;
        sum += (__u32)scratch[tail] << 8;
    }

/* Fold */
#pragma unroll
    for (int i = 0; i < 4; i++)
        if (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

    __u16 fc = ~((__u16)sum);
    if (fc == 0 && proto == IPPROTO_UDP)
        fc = 0xFFFF;

    scratch[zpos] = (__u8)(fc >> 8);
    scratch[zpos + 1] = (__u8)(fc & 0xFF);
}

/* ── Finalize inner IPv6 L4 (TCP/UDP/ICMPv6) checksum ────────────────
 *
 * Same strategy as fix_l4_checksum but for IPv6 inner packets.
 * IPv6 pseudo-header: saddr(16) + daddr(16) + length(4) + next_hdr(4).
 * Note: no extension header parsing — assumes next_hdr is L4 directly.
 * ICMPv6 also uses the IPv6 pseudo-header (unlike ICMPv4).
 */
static __always_inline void fix_l4_checksum_v6(__u8 *scratch, __u32 inner_len)
{
    const __u32 B = 0;

    if (inner_len < 48)
        return;
    if (inner_len > MAX_INNER_TECH_LIMIT)
        return;

    __u8 version = scratch[B] >> 4;
    if (version != 6)
        return;

    __u8 proto = scratch[B + 6]; /* next header */
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != 58 /* ICMPv6 */)
        return;

    __u32 payload_len = ((__u32)scratch[B + 4] << 8) | (__u32)scratch[B + 5];
    if (payload_len + 40 > inner_len)
        payload_len = inner_len - 40;
    if (payload_len < 8)
        return;

    __u32 l4_len = payload_len;
    if (l4_len > MAX_INNER_TECH_LIMIT)
        l4_len = MAX_INNER_TECH_LIMIT;

    const __u32 l4_start = B + 40;

    /* Zero checksum field: TCP=16, UDP=6, ICMPv6=2 */
    __u32 csum_off;
    if (proto == IPPROTO_TCP)
        csum_off = 16;
    else if (proto == 58) /* ICMPv6 */
        csum_off = 2;
    else
        csum_off = 6; /* UDP */
    if (csum_off + 2 > l4_len)
        return;
    __u32 zpos = l4_start + csum_off;
    if (zpos + 2 > SCRATCH_SIZE)
        return;
    scratch[zpos] = 0;
    scratch[zpos + 1] = 0;

    /* IPv6 pseudo-header: saddr(16) + daddr(16) + upper-layer-len(4) + next-hdr(4) */
    __u32 sum = 0;
    /* Source address: 8 words at B+8 */
#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        __u32 off = B + 8 + (__u32)i * 2;
        sum += ((__u32)scratch[off] << 8) | (__u32)scratch[off + 1];
    }
    /* Destination address: 8 words at B+24 */
#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        __u32 off = B + 24 + (__u32)i * 2;
        sum += ((__u32)scratch[off] << 8) | (__u32)scratch[off + 1];
    }
    /* Upper-layer length in pseudo-header (as u32 → two 16-bit words; fits u16) */
    sum += (__u32)l4_len;
    /* Next header (proto) */
    sum += (__u32)proto;

    /* Sum L4 segment via bpf_loop (8 bytes = 4 words per iteration) */
    struct l4_csum_ctx ctx = {
        .scratch = scratch,
        .l4_start = l4_start,
        .l4_len = l4_len,
        .i = 0,
        .sum = sum,
    };
    bpf_loop(MAX_INNER_TECH_LIMIT / 8 + 1, __l4_csum_word_cb, &ctx, 0);
    sum = ctx.sum;

    /* Remaining 0..7 tail bytes */
    __u32 ti = ctx.i;
#pragma unroll
    for (int t = 0; t < 3; t++)
    {
        if (ti + 1 < l4_len)
        {
            __u32 toff = l4_start + ti;
            asm volatile("" : "+r"(toff));
            toff &= 0x7FF;
            __u32 toff1 = (toff + 1) & 0x7FF;
            sum += ((__u32)scratch[toff] << 8) | (__u32)scratch[toff1];
            ti += 2;
        }
    }

    /* Odd trailing byte */
    if (l4_len & 1)
    {
        __u32 tail = l4_start + l4_len - 1;
        asm volatile("" : "+r"(tail));
        tail &= 0x7FF;
        sum += (__u32)scratch[tail] << 8;
    }

/* Fold */
#pragma unroll
    for (int i = 0; i < 4; i++)
        if (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

    __u16 fc = ~((__u16)sum);
    /* IPv6 UDP/ICMPv6: 0x0000 checksum is invalid → use 0xFFFF */
    if (fc == 0)
        fc = 0xFFFF;

    scratch[zpos] = (__u8)(fc >> 8);
    scratch[zpos + 1] = (__u8)(fc & 0xFF);
}

static __always_inline __u32 calc_payload_csum(void *data, void *data_end, __u32 len, __u64 seed)
{
    __u64 csum = seed;

#pragma unroll
    for (int i = 0; i < 24; i++)
    { // 24 * 64 = 1536
        if (len >= 64)
        {
            if ((__u8 *)data + 64 > (__u8 *)data_end)
                break;
            csum = bpf_csum_diff(NULL, 0, data, 64, csum);
            data = (__u8 *)data + 64;
            len -= 64;
        }
    }

#pragma unroll
    for (int i = 0; i < 15; i++)
    { // 15 * 4 = 60
        if (len >= 4)
        {
            if ((__u8 *)data + 4 > (__u8 *)data_end)
                break;
            csum = bpf_csum_diff(NULL, 0, data, 4, csum);
            data = (__u8 *)data + 4;
            len -= 4;
        }
    }

    if (len > 0 && len <= 3)
    {
        __u32 tail = 0;
        __u8 *tail_bytes = (__u8 *)data;
        if (len == 1)
        {
            if (tail_bytes + 1 > (__u8 *)data_end)
                return csum;
            tail = tail_bytes[0];
        }
        else if (len == 2)
        {
            if (tail_bytes + 2 > (__u8 *)data_end)
                return csum;
            tail = (tail_bytes[1] << 8) | tail_bytes[0];
        }
        else if (len == 3)
        {
            if (tail_bytes + 3 > (__u8 *)data_end)
                return csum;
            tail = (tail_bytes[2] << 16) | (tail_bytes[1] << 8) | tail_bytes[0];
        }

        csum += tail;
        if (csum < tail)
            csum++;
    }

    return csum;
}

#ifdef BPF_DEBUG
#define bpf_debug(fmt, ...) bpf_printk("GUT: " fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...) \
    do                      \
    {                       \
    } while (0)
#endif

static __always_inline __u8 is_quic_server(const struct gut_config *cfg)
{
    if (cfg->tun_local_ip4 != 0)
    {
        return ((const __u8 *)&cfg->tun_local_ip4)[3] & 1;
    }
    else
    {
        return cfg->tun_local_ip6[15] & 1;
    }
}

#endif /* __GUT_COMMON_H__ */
