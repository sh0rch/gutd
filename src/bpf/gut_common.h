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

/* bpf_ktime_get_tai_ns: TAI nanoseconds since epoch (helper 161, kernel 6.1+).
 * TAI ≈ UTC + 37s — close enough for syslog DPI evasion timestamps.
 * Available for sched_cls (TC), unlike bpf_ktime_get_real_ns (#381). */

/* ── Compile-time obfuscation mode ─────────────────────────────────────
 * Exactly one GUT_MODE_* must be defined via -D flag in build.rs.
 * Default: GUT_MODE_QUIC (backward-compatible QUIC encapsulation).   */
#if !defined(GUT_MODE_QUIC) && !defined(GUT_MODE_GUT) && \
    !defined(GUT_MODE_SYSLOG) && !defined(GUT_MODE_SIP)
#define GUT_MODE_QUIC
#endif

#define MAX_PORTS 6
/* Short header layout (16 bytes):
 * [0]=0x40 [1-4]=DCID [5]=dcid_len(0x01) [6-9]=PPN [10-13]=enc_ports [14]=reserved [15]=pad_len
 * Long header layout (1200 bytes):
 * [0]=0xC3 [1-4]=version(QUICv1) [5]=dcid_len(0x08) [6-13]=DCID [14]=scid_len(0x08) [15-22]=SCID
 * [23]=token_len(0x04) [24-27]=enc_ports [28-29]=length [30-33]=PPN
 * [34-43]=fake CRYPTO frame [44..1198]=PRNG fill [1199]=pad_len
 * TC egress stores the original WG UDP src/dst ports so XDP can restore them
 * after decapsulation, preserving the conntrack/WG port numbers end-to-end. */
#define GUT_QUIC_SHORT_HEADER_SIZE 16
#define GUT_QUIC_LONG_HEADER_SIZE 1200
#define GUT_HEADER_SIZE 10
#define GUT_SYSLOG_HDR_BASE 36 /* "<165>1 YYYY-MM-DDTHH:MM:SSZ " + " - - -  " = 28 + 8 */
#define GUT_SYSLOG_HDR_MAX 68  /* 36 + max sni_domain_len(32) */
#define GUT_SIP_HDR_BASE 182   /* Fixed bytes in write_sip_header() (excl. 2 × sni_domain) */
#define GUT_SIP_HDR_MAX 256    /* Max SIP header: GUT_SIP_HDR_BASE + 2*32 + margin */
#define GUT_RTP_HEADER_SIZE 12 /* RTP header: V(1)+PT(1)+seq(2)+ts(4)+SSRC(4) */
#define GUT_B64_MAX_INNER 896  /* max inner before b64: GUT_HDR(10) + wg(800) + pad(64) */
#define GUT_B64_MAX_OUT 1200   /* ceil(896/3)*4 = 1200 */
#define GUT_B64_WG_MTU_MAX 886 /* max wg_total (wg_len+pad_len) for syslog b64 path; \
                                * = GUT_B64_MAX_INNER(896) - GUT_HDR(10);            \
                                * WG_MTU=800 → wg_len=832 ≤ 886, output ~ 1196 bytes ≤ 1500 */
#define SIP_SCAN_OFF 2560      /* scratch offset for SIP marker scan on ingress */

/* Combined base64 mode flag for shared syslog/SIP code paths */
#if defined(GUT_MODE_SYSLOG) || defined(GUT_MODE_SIP)
#define GUT_MODE_B64 1
#endif
#define GUT_KEY_SIZE 32
#define MAX_PACKET_SIZE 9000
#define SCRATCH_SIZE 16384                   /* scratch buffer: power-of-2.  Must be > MAX_PACKET_SIZE + 1 \
                                              * so BPF_BOUND_LEN ([1,2048]) with scratch+1 stays within    \
                                              * map value bounds (off=1 + 2048 ≤ 4096).                  \
                                              * mask_data_fast uses (i &= 0x3FFF) → max 16383.              */
#define MAX_INNER_TECH_LIMIT MAX_PACKET_SIZE /* technical verifier/scratch cap, runtime MTU comes from config_map */

/* Masking: always ChaCha (rounds configured at compile time) */

/* Packet flags */
#define FLAG_SINGLE 0

/* Payload-only mode: no extra protocol bytes above UDP payload */
#define GUT_WIRE_HDR_SIZE 0
#define GUT_MIN_OVERHEAD 0

/* Variable-length ballast: ChaCha-derived 0..63 bytes appended inside masked body
 * for packets with inner_len < BALLAST_THRESHOLD.  Receiver determines
 * inner length from IP header; remainder is ballast (ignored). */
#define BALLAST_THRESHOLD 220
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
    __u8 peer_ip6[16];           /* Peer IPv6 address (network byte order, zero if v4) */
    __u8 bind_ip6[16];           /* Local bind IPv6 (network byte order, zero if v4) */
    __u32 tun_local_ip4;         /* Local veth (gut0) IP — XDP ingress rewrites dst to this */
    __u32 tun_peer_ip4;          /* Remote veth peer IP — XDP ingress rewrites src to this */
    __u8 tun_local_ip6[16];      /* Local veth IPv6 (zero if v4 only) */
    __u8 tun_peer_ip6[16];       /* Remote veth peer IPv6 (zero if v4 only) */
    __u8 own_http3;              /* Respond to DPI probes via XDP_TX (1=yes) */
    __u8 dynamic_peer;           /* 1 = peer_ip unknown, learn from validated inbound packets */
    __u8 obfs_gut;               /* 1 = noise mode: XOR quic[0..6] with quic[6..12] to hide QUIC signatures */

    /* ── QUIC crypto: precomputed by loader for BPF AEAD on Long Headers ── */
    __u8 sni_domain[32];   /* SNI domain for ClientHello (null-terminated) */
    __u8 sni_domain_len;   /* Actual length of sni_domain */
    __u8 _pad_quic[3];     /* Alignment padding for u32 arrays below */
    __u8 quic_dcid[8];     /* Fixed 8-byte DCID for Long Headers */
    __u32 quic_key_rk[44]; /* AES-128 expanded round keys for AEAD (q_key) */
    __u32 quic_hp_rk[44];  /* AES-128 expanded round keys for HP (q_hp) */
    __u8 quic_iv[12];      /* AEAD IV — XOR with PPN(BE) for GCM nonce */
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
    __u8 obfs_gut;       /* 1 = this client uses noise mode, 0 = plain quic (auto-detected) */
};

/* Per-CPU statistics */
struct gut_stats
{
    __u64 packets_processed; /* combined egress+ingress (legacy, kept for ABI) */
    __u64 packets_dropped;
    __u64 bytes_processed;
    __u64 packets_oversized;
    __u64 mask_count;
    __u64 packets_fragmented;
    __u64 inner_tcp_seen;
    __u64 packets_egress;  /* TC egress: WG→outer (obfuscated) packets sent */
    __u64 packets_ingress; /* XDP ingress: outer→WG (de-obfuscated) packets received */
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
 * re-read from the chacha_init pointer for the final addition.
 *
 * __always_inline is required on kernel 6.17+ where the BPF verifier
 * rejects noinline helpers that receive map-value pointers as arguments
 * (ks[] points into scratch_map).  Since chacha_block has zero stack
 * locals of its own the inlining cost is just code size, not stack. */
static __always_inline void chacha_block(__u32 ks[16],
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
    __u32 o = off & 0x3FFF;
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
                __u32 oj = (off + j) & 0x3FFF;
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
    i &= 0x3FFF;
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
 *   Only computed for small packets (inner_len < BALLAST_THRESHOLD).
 *
 * Block 211 (counter=211, same nonce):
 *   words[0] = next_nonce (u32 LE), guaranteed non-zero
 *   words[1] = next_pkt_id (u32 LE), guaranteed non-zero
 *   Always computed — eliminates all separate PRNGs from datapath.
 *
 * Loader seeds initial (nonce, pkt_id) into counters_map.
 * Receiver never predicts nonce — reads it from wire header.
 */
#define CHACHA_BLOCK_BALLAST 199
#define CHACHA_BLOCK_NEXT_IDS 211

/* Generate ballast data + length from ChaCha block 99.
 * Writes up to 63 bytes into ballast_out, returns ballast_len.
 * max_body = maximum body bytes available for inner + ballast. */
static __always_inline __u32 chacha_ballast(
    __u8 *ballast_out, __u32 inner_len, __u32 max_body,
    const __u32 chacha_init[12], __u32 nonce)
{
    if (inner_len >= BALLAST_THRESHOLD)
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
    /* The loader caps num_ports to MAX_PORTS, so idx < MAX_PORTS always.
     * Defensive guard: if somehow violated, return 0 so the caller
     * (TC egress) drops the packet rather than silently misrouting. */
    if (idx >= MAX_PORTS)
        return 0;
    return cfg->ports[idx];
}

static __always_inline __u32 sip_hash32(__u32 x, const __u32 rk[4])
{
    __u32 h = x;
    h = h * 0xcc9e2d51 + rk[0];
    h = (h << 15) | (h >> 17);
    h = h * 0x1b873593 + rk[1];
    h = (h << 13) | (h >> 19);
    h = h * 0xe6546b64 + rk[2];
    h = (h << 10) | (h >> 22);
    h = h * 0x85ebca6b + rk[3];
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
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

/* ── AES-128 (FIPS 197) for QUIC AEAD + Header Protection ──────────── */
#if defined(GUT_MODE_QUIC)

static const __u8 AES_SBOX[256] = {
    0x63,
    0x7c,
    0x77,
    0x7b,
    0xf2,
    0x6b,
    0x6f,
    0xc5,
    0x30,
    0x01,
    0x67,
    0x2b,
    0xfe,
    0xd7,
    0xab,
    0x76,
    0xca,
    0x82,
    0xc9,
    0x7d,
    0xfa,
    0x59,
    0x47,
    0xf0,
    0xad,
    0xd4,
    0xa2,
    0xaf,
    0x9c,
    0xa4,
    0x72,
    0xc0,
    0xb7,
    0xfd,
    0x93,
    0x26,
    0x36,
    0x3f,
    0xf7,
    0xcc,
    0x34,
    0xa5,
    0xe5,
    0xf1,
    0x71,
    0xd8,
    0x31,
    0x15,
    0x04,
    0xc7,
    0x23,
    0xc3,
    0x18,
    0x96,
    0x05,
    0x9a,
    0x07,
    0x12,
    0x80,
    0xe2,
    0xeb,
    0x27,
    0xb2,
    0x75,
    0x09,
    0x83,
    0x2c,
    0x1a,
    0x1b,
    0x6e,
    0x5a,
    0xa0,
    0x52,
    0x3b,
    0xd6,
    0xb3,
    0x29,
    0xe3,
    0x2f,
    0x84,
    0x53,
    0xd1,
    0x00,
    0xed,
    0x20,
    0xfc,
    0xb1,
    0x5b,
    0x6a,
    0xcb,
    0xbe,
    0x39,
    0x4a,
    0x4c,
    0x58,
    0xcf,
    0xd0,
    0xef,
    0xaa,
    0xfb,
    0x43,
    0x4d,
    0x33,
    0x85,
    0x45,
    0xf9,
    0x02,
    0x7f,
    0x50,
    0x3c,
    0x9f,
    0xa8,
    0x51,
    0xa3,
    0x40,
    0x8f,
    0x92,
    0x9d,
    0x38,
    0xf5,
    0xbc,
    0xb6,
    0xda,
    0x21,
    0x10,
    0xff,
    0xf3,
    0xd2,
    0xcd,
    0x0c,
    0x13,
    0xec,
    0x5f,
    0x97,
    0x44,
    0x17,
    0xc4,
    0xa7,
    0x7e,
    0x3d,
    0x64,
    0x5d,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4f,
    0xdc,
    0x22,
    0x2a,
    0x90,
    0x88,
    0x46,
    0xee,
    0xb8,
    0x14,
    0xde,
    0x5e,
    0x0b,
    0xdb,
    0xe0,
    0x32,
    0x3a,
    0x0a,
    0x49,
    0x06,
    0x24,
    0x5c,
    0xc2,
    0xd3,
    0xac,
    0x62,
    0x91,
    0x95,
    0xe4,
    0x79,
    0xe7,
    0xc8,
    0x37,
    0x6d,
    0x8d,
    0xd5,
    0x4e,
    0xa9,
    0x6c,
    0x56,
    0xf4,
    0xea,
    0x65,
    0x7a,
    0xae,
    0x08,
    0xba,
    0x78,
    0x25,
    0x2e,
    0x1c,
    0xa6,
    0xb4,
    0xc6,
    0xe8,
    0xdd,
    0x74,
    0x1f,
    0x4b,
    0xbd,
    0x8b,
    0x8a,
    0x70,
    0x3e,
    0xb5,
    0x66,
    0x48,
    0x03,
    0xf6,
    0x0e,
    0x61,
    0x35,
    0x57,
    0xb9,
    0x86,
    0xc1,
    0x1d,
    0x9e,
    0xe1,
    0xf8,
    0x98,
    0x11,
    0x69,
    0xd9,
    0x8e,
    0x94,
    0x9b,
    0x1e,
    0x87,
    0xe9,
    0xce,
    0x55,
    0x28,
    0xdf,
    0x8c,
    0xa1,
    0x89,
    0x0d,
    0xbf,
    0xe6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2d,
    0x0f,
    0xb0,
    0x54,
    0xbb,
    0x16,
};

#define SB(b) AES_SBOX[(b) & 0xFF]

/* AES-128 encrypt a single 16-byte block using precomputed round keys.
 * noinline: BPF subprogram — keeps stack in its own frame (~200B), called from
 * gut_egress at call depth 1.  AES-CTR keystreams are precomputed BEFORE calling
 * the GHASH function, so AES and GHASH never nest (max 2 call depth). */
static __attribute__((noinline)) void aes128_encrypt_block(const __u32 *rk, const __u8 *in, __u8 *out)
{
    /* Load state as 4 column-major u32, AddRoundKey(0) */
    __u32 s0 = ((__u32)in[0] << 24 | (__u32)in[1] << 16 | (__u32)in[2] << 8 | in[3]) ^ rk[0];
    __u32 s1 = ((__u32)in[4] << 24 | (__u32)in[5] << 16 | (__u32)in[6] << 8 | in[7]) ^ rk[1];
    __u32 s2 = ((__u32)in[8] << 24 | (__u32)in[9] << 16 | (__u32)in[10] << 8 | in[11]) ^ rk[2];
    __u32 s3 = ((__u32)in[12] << 24 | (__u32)in[13] << 16 | (__u32)in[14] << 8 | in[15]) ^ rk[3];

    /* Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey */
#define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
#define AES_ROUND(r)                                                                  \
    do                                                                                \
    {                                                                                 \
        __u8 b0 = SB(s0 >> 24), b1 = SB(s1 >> 16), b2 = SB(s2 >> 8), b3 = SB(s3);     \
        __u8 b4 = SB(s1 >> 24), b5 = SB(s2 >> 16), b6 = SB(s3 >> 8), b7 = SB(s0);     \
        __u8 b8 = SB(s2 >> 24), b9 = SB(s3 >> 16), b10 = SB(s0 >> 8), b11 = SB(s1);   \
        __u8 b12 = SB(s3 >> 24), b13 = SB(s0 >> 16), b14 = SB(s1 >> 8), b15 = SB(s2); \
        __u8 h0, h1, h2, h3;                                                          \
        /* MixColumns col 0 */                                                        \
        h0 = XTIME(b0);                                                               \
        h1 = XTIME(b1);                                                               \
        h2 = XTIME(b2);                                                               \
        h3 = XTIME(b3);                                                               \
        s0 = ((__u32)(h0 ^ (h1 ^ b1) ^ b2 ^ b3) << 24) |                              \
             ((__u32)(b0 ^ h1 ^ (h2 ^ b2) ^ b3) << 16) |                              \
             ((__u32)(b0 ^ b1 ^ h2 ^ (h3 ^ b3)) << 8) |                               \
             ((__u32)((h0 ^ b0) ^ b1 ^ b2 ^ h3));                                     \
        s0 ^= rk[(r) * 4 + 0];                                                        \
        /* MixColumns col 1 */                                                        \
        h0 = XTIME(b4);                                                               \
        h1 = XTIME(b5);                                                               \
        h2 = XTIME(b6);                                                               \
        h3 = XTIME(b7);                                                               \
        s1 = ((__u32)(h0 ^ (h1 ^ b5) ^ b6 ^ b7) << 24) |                              \
             ((__u32)(b4 ^ h1 ^ (h2 ^ b6) ^ b7) << 16) |                              \
             ((__u32)(b4 ^ b5 ^ h2 ^ (h3 ^ b7)) << 8) |                               \
             ((__u32)((h0 ^ b4) ^ b5 ^ b6 ^ h3));                                     \
        s1 ^= rk[(r) * 4 + 1];                                                        \
        /* MixColumns col 2 */                                                        \
        h0 = XTIME(b8);                                                               \
        h1 = XTIME(b9);                                                               \
        h2 = XTIME(b10);                                                              \
        h3 = XTIME(b11);                                                              \
        s2 = ((__u32)(h0 ^ (h1 ^ b9) ^ b10 ^ b11) << 24) |                            \
             ((__u32)(b8 ^ h1 ^ (h2 ^ b10) ^ b11) << 16) |                            \
             ((__u32)(b8 ^ b9 ^ h2 ^ (h3 ^ b11)) << 8) |                              \
             ((__u32)((h0 ^ b8) ^ b9 ^ b10 ^ h3));                                    \
        s2 ^= rk[(r) * 4 + 2];                                                        \
        /* MixColumns col 3 */                                                        \
        h0 = XTIME(b12);                                                              \
        h1 = XTIME(b13);                                                              \
        h2 = XTIME(b14);                                                              \
        h3 = XTIME(b15);                                                              \
        s3 = ((__u32)(h0 ^ (h1 ^ b13) ^ b14 ^ b15) << 24) |                           \
             ((__u32)(b12 ^ h1 ^ (h2 ^ b14) ^ b15) << 16) |                           \
             ((__u32)(b12 ^ b13 ^ h2 ^ (h3 ^ b15)) << 8) |                            \
             ((__u32)((h0 ^ b12) ^ b13 ^ b14 ^ h3));                                  \
        s3 ^= rk[(r) * 4 + 3];                                                        \
    } while (0)

    AES_ROUND(1);
    AES_ROUND(2);
    AES_ROUND(3);
    AES_ROUND(4);
    AES_ROUND(5);
    AES_ROUND(6);
    AES_ROUND(7);
    AES_ROUND(8);
    AES_ROUND(9);

#undef AES_ROUND

    /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    out[0] = SB(s0 >> 24) ^ (rk[40] >> 24);
    out[1] = SB(s1 >> 16) ^ (rk[40] >> 16);
    out[2] = SB(s2 >> 8) ^ (rk[40] >> 8);
    out[3] = SB(s3) ^ rk[40];
    out[4] = SB(s1 >> 24) ^ (rk[41] >> 24);
    out[5] = SB(s2 >> 16) ^ (rk[41] >> 16);
    out[6] = SB(s3 >> 8) ^ (rk[41] >> 8);
    out[7] = SB(s0) ^ rk[41];
    out[8] = SB(s2 >> 24) ^ (rk[42] >> 24);
    out[9] = SB(s3 >> 16) ^ (rk[42] >> 16);
    out[10] = SB(s0 >> 8) ^ (rk[42] >> 8);
    out[11] = SB(s1) ^ rk[42];
    out[12] = SB(s3 >> 24) ^ (rk[43] >> 24);
    out[13] = SB(s0 >> 16) ^ (rk[43] >> 16);
    out[14] = SB(s1 >> 8) ^ (rk[43] >> 8);
    out[15] = SB(s2) ^ rk[43];

#undef XTIME
#undef SB
}

/* ── GF(2^128) multiply via bpf_loop ──────────────────────────────────
 * Using bpf_loop(32, callback, ctx, 0) the verifier checks the callback body
 * ONCE regardless of iteration count, eliminating the state explosion that
 * killed the verifier budget with schoolbook-unroll or bounded-loop approaches.
 * Available since kernel 5.17; target is 6.1+. */

struct gf_ctx
{
    __u32 z0, z1, z2, z3;
    __u32 v0, v1, v2, v3;
    __u32 xw; /* current 32-bit word of x being processed */
};

static long gf_step_cb(__u32 bit, void *_ctx)
{
    struct gf_ctx *c = (struct gf_ctx *)_ctx;
    __u32 b = bit & 31; /* ensure [0,31] for shift safety */
    __u32 mask = -((__u32)((c->xw >> (31 - b)) & 1));
    c->z0 ^= c->v0 & mask;
    c->z1 ^= c->v1 & mask;
    c->z2 ^= c->v2 & mask;
    c->z3 ^= c->v3 & mask;
    __u32 carry = -(c->v3 & 1);
    c->v3 = (c->v3 >> 1) | (c->v2 << 31);
    c->v2 = (c->v2 >> 1) | (c->v1 << 31);
    c->v1 = (c->v1 >> 1) | (c->v0 << 31);
    c->v0 = (c->v0 >> 1) ^ (0xE1000000U & carry);
    return 0;
}

/* GF(2^128) multiply: z = x * h, reduction polynomial x^128+x^7+x^2+x+1.
 * All 128-bit values in big-endian byte order (GCM convention).
 * 32-bit safe. Uses bpf_loop for verifier-friendly iteration. */
static __always_inline void gf128_mul(const __u8 *x, const __u8 *h, __u8 *z)
{
    struct gf_ctx ctx;
    __u32 x0, x1, x2, x3;

    __builtin_memcpy(&x0, x, 4);
    x0 = __builtin_bswap32(x0);
    __builtin_memcpy(&x1, x + 4, 4);
    x1 = __builtin_bswap32(x1);
    __builtin_memcpy(&x2, x + 8, 4);
    x2 = __builtin_bswap32(x2);
    __builtin_memcpy(&x3, x + 12, 4);
    x3 = __builtin_bswap32(x3);

    __builtin_memcpy(&ctx.v0, h, 4);
    ctx.v0 = __builtin_bswap32(ctx.v0);
    __builtin_memcpy(&ctx.v1, h + 4, 4);
    ctx.v1 = __builtin_bswap32(ctx.v1);
    __builtin_memcpy(&ctx.v2, h + 8, 4);
    ctx.v2 = __builtin_bswap32(ctx.v2);
    __builtin_memcpy(&ctx.v3, h + 12, 4);
    ctx.v3 = __builtin_bswap32(ctx.v3);

    ctx.z0 = ctx.z1 = ctx.z2 = ctx.z3 = 0;

    /* Memory barriers after each bpf_loop: the callback modifies ctx
     * through a pointer, but Clang -O2 may keep z/v fields in callee-saved
     * registers across the helper call and use stale values.  The barrier
     * forces a reload from the stack where the callback actually wrote. */
    ctx.xw = x0;
    bpf_loop(32, gf_step_cb, &ctx, 0);
    asm volatile("" : "+m"(ctx));
    ctx.xw = x1;
    bpf_loop(32, gf_step_cb, &ctx, 0);
    asm volatile("" : "+m"(ctx));
    ctx.xw = x2;
    bpf_loop(32, gf_step_cb, &ctx, 0);
    asm volatile("" : "+m"(ctx));
    ctx.xw = x3;
    bpf_loop(32, gf_step_cb, &ctx, 0);
    asm volatile("" : "+m"(ctx));

    ctx.z0 = __builtin_bswap32(ctx.z0);
    ctx.z1 = __builtin_bswap32(ctx.z1);
    ctx.z2 = __builtin_bswap32(ctx.z2);
    ctx.z3 = __builtin_bswap32(ctx.z3);
    __builtin_memcpy(z, &ctx.z0, 4);
    __builtin_memcpy(z + 4, &ctx.z1, 4);
    __builtin_memcpy(z + 8, &ctx.z2, 4);
    __builtin_memcpy(z + 12, &ctx.z3, 4);
}

/* GHASH: update accumulator x with block b using hash subkey H.
 * x = gf128_mul(x XOR b, H). */
static __always_inline void ghash_update(const __u8 *H, __u8 *x, const __u8 *block, __u8 *tmp)
{
    for (int j = 0; j < 16; j++)
        x[j] ^= block[j];
    gf128_mul(x, H, tmp);
    __builtin_memcpy(x, tmp, 16);
}

/* GCM-GHASH + tag computation over pre-encrypted ciphertext.
 * AES-CTR XOR and AES(H)/AES(J0) are precomputed by the caller so this
 * function contains NO AES calls — only XOR + GHASH (via bpf_loop).
 * noinline: separate stack frame (~80B), called from gut_egress at depth 1.
 * bpf_loop callback adds depth +1 → max depth 2.
 *
 * scratch_ghash layout (≥80 bytes):
 *   [0..15]=ghash_x, [16..31]=tmp, [32..47]=blk, [48..63]=tag_out, [64..99]=gf_ctx
 *
 * @H:           precomputed hash subkey AES(K, 0^128), 16 bytes
 * @aad:         AAD buffer, exactly 34 bytes
 * @ct:          ciphertext buffer, exactly 128 bytes (already XOR'd with CTR keystreams)
 * @j0_ks:       precomputed AES(K, J0) for tag finalization, 16 bytes
 * @scratch_ghash: working area (≥100 bytes, in per-cpu scratch map) */
static __attribute__((noinline)) void gcm_ghash_tag_128(
    const __u8 *H,
    const __u8 *aad,
    const __u8 *ct,
    const __u8 *j0_ks,
    __u8 *scratch_ghash)
{
    __u8 *ghash_x = scratch_ghash;
    __u8 *tmp = scratch_ghash + 16;
    __u8 *blk = scratch_ghash + 32;

    __builtin_memset(ghash_x, 0, 16);

    /* GHASH over AAD: 34 bytes = 3 blocks (last padded with zeros) */
    __builtin_memcpy(blk, aad, 16);
    ghash_update(H, ghash_x, blk, tmp);
    __builtin_memcpy(blk, aad + 16, 16);
    ghash_update(H, ghash_x, blk, tmp);
    __builtin_memset(blk, 0, 16);
    blk[0] = aad[32];
    blk[1] = aad[33];
    ghash_update(H, ghash_x, blk, tmp);

    /* GHASH over 8 ciphertext blocks */
    for (__u32 i = 0; i < 8; i++)
        ghash_update(H, ghash_x, ct + i * 16, tmp);

    /* Length block: AAD=272 bits, CT=1024 bits */
    __builtin_memset(blk, 0, 16);
    blk[6] = 0x01;
    blk[7] = 0x10;
    blk[14] = 0x04;
    blk[15] = 0x00;
    ghash_update(H, ghash_x, blk, tmp);

    /* Tag = AES(K, J0) XOR GHASH — AES(K,J0) is precomputed in j0_ks */
    __u8 *tag_out = scratch_ghash + 48;
    for (int j = 0; j < 16; j++)
        tag_out[j] = j0_ks[j] ^ ghash_x[j];
}

#endif /* GUT_MODE_QUIC */

#endif /* __GUT_COMMON_H__ */

static __always_inline void write_gut_header(__u8 *quic, void *data_end, __u32 ppn, __u32 enc_ports, __u32 pad_len)
{
    if ((__u8 *)quic + GUT_HEADER_SIZE > (__u8 *)data_end)
        return;
    __builtin_memcpy((__u8 *)quic + 0, &ppn, 4);
    __builtin_memcpy((__u8 *)quic + 4, &enc_ports, 4);
    quic[8] = 0x00;
    quic[9] = (pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;
}

/* ── Base64 encode/decode for Syslog / SIP BPF modes ──────────────────
 * Scratch buffer layout for base64 operations:
 *   scratch[384..384+GUT_B64_MAX_INNER]  = inner buffer (encode input / decode output)
 *   scratch[1280..1280+GUT_B64_MAX_OUT]  = base64 buffer (encode output / decode input)
 * These offsets are chosen to avoid collision with ChaCha keystreams (0..255)
 * and header shift temp (256..319).  */
#define B64_INNER_OFF 384
#define B64_ENC_OFF 1280

/* Base64 decode LUT in .rodata — accessed by callback with variable index.
 * No init needed; libbpf loads .rodata automatically. */
static const __u8 b64_dec_lut[256] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    62,
    0,
    0,
    0,
    63,
    52,
    53,
    54,
    55,
    56,
    57,
    58,
    59,
    60,
    61,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    0,
    0,
    0,
    0,
    0,
    0,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

/* Base64 encode LUT: 6-bit value [0..63] → ASCII char.
 * Placed in .rodata — verifier-friendly, no runtime init. */
static const __u8 b64_enc_lut[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

/* Lookup with forced mask — prevents the compiler from eliding the & 63
 * which the verifier needs to bound the map_value pointer arithmetic. */
static __always_inline __u8 b64e(__u32 val)
{
    __u32 idx;
    asm volatile("%[out] = %[in]\n\t"
                 "%[out] &= 63"
                 : [out] "=r"(idx)
                 : [in] "r"(val)
                 :);
    return b64_enc_lut[idx];
}

/* Encode scratch[in_off..in_off+in_len] → scratch[out_off..].
 * Returns output length (always multiple of 4).
 * Uses bpf_loop to handle up to GUT_B64_MAX_INNER bytes without hitting
 * verifier instruction limits. Remainder 1–2 bytes handled after the loop. */
struct b64_enc_ctx
{
    __u8 *scratch;
    __u32 in_off;
    __u32 out_off;
};

static long b64_encode_step(__u32 idx, void *_ctx)
{
    struct b64_enc_ctx *ctx = (struct b64_enc_ctx *)_ctx;
    __u32 pos = idx * 3;
    __u32 opos = idx * 4;

    __u32 i0 = (ctx->in_off + pos) & (SCRATCH_SIZE - 1);
    __u32 i1 = (ctx->in_off + pos + 1) & (SCRATCH_SIZE - 1);
    __u32 i2 = (ctx->in_off + pos + 2) & (SCRATCH_SIZE - 1);

    __u8 a = ctx->scratch[i0];
    __u8 b = ctx->scratch[i1];
    __u8 d = ctx->scratch[i2];

    __u32 o0 = (ctx->out_off + opos) & (SCRATCH_SIZE - 1);
    __u32 o1 = (ctx->out_off + opos + 1) & (SCRATCH_SIZE - 1);
    __u32 o2 = (ctx->out_off + opos + 2) & (SCRATCH_SIZE - 1);
    __u32 o3 = (ctx->out_off + opos + 3) & (SCRATCH_SIZE - 1);

    ctx->scratch[o0] = b64e(a >> 2);
    ctx->scratch[o1] = b64e(((a & 0x03) << 4) | (b >> 4));
    ctx->scratch[o2] = b64e(((b & 0x0F) << 2) | (d >> 6));
    ctx->scratch[o3] = b64e(d & 0x3F);

    return 0;
}

static __always_inline __u32 b64_encode(__u8 *scratch, __u32 in_off, __u32 in_len, __u32 out_off)
{
    __u32 full_groups = in_len / 3;
    if (full_groups > 300)
        full_groups = 300;

    struct b64_enc_ctx ctx = {
        .scratch = scratch,
        .in_off = in_off,
        .out_off = out_off,
    };

    bpf_loop(full_groups, b64_encode_step, &ctx, 0);

    __u32 ip = full_groups * 3;
    __u32 op = full_groups * 4;

    /* Re-bound ip/op for verifier: multiplication result spilled to stack
     * loses scalar range tracking.  Force asm masks the compiler cannot elide. */
    asm volatile("%[v] &= 0xFFF" : [v] "+r"(ip) : :);
    asm volatile("%[v] &= 0xFFF" : [v] "+r"(op) : :);

    /* Handle trailing 1 or 2 bytes outside the loop */
    __u32 rem = in_len - ip;
    if (rem >= 1)
    {
        __u32 i0 = (in_off + ip) & (SCRATCH_SIZE - 1);
        __u8 a = scratch[i0];
        __u32 o0 = (out_off + op) & (SCRATCH_SIZE - 1);
        __u32 o1 = (out_off + op + 1) & (SCRATCH_SIZE - 1);
        __u32 o2 = (out_off + op + 2) & (SCRATCH_SIZE - 1);
        __u32 o3 = (out_off + op + 3) & (SCRATCH_SIZE - 1);

        if (rem >= 2)
        {
            __u32 i1 = (in_off + ip + 1) & (SCRATCH_SIZE - 1);
            __u8 b = scratch[i1];
            scratch[o0] = b64e(a >> 2);
            scratch[o1] = b64e(((a & 0x03) << 4) | (b >> 4));
            scratch[o2] = b64e((b & 0x0F) << 2);
            scratch[o3] = '=';
        }
        else
        {
            scratch[o0] = b64e(a >> 2);
            scratch[o1] = b64e((a & 0x03) << 4);
            scratch[o2] = '=';
            scratch[o3] = '=';
        }
        op += 4;
    }
    return op;
}

static __always_inline __u8 b64_decode_char(__u8 c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return 0; /* '=' or invalid → treated as 0 */
}

/* ── bpf_loop callback for base64 decode ──────────────────────────────
 * Fully stateless: all offsets computed from idx (no mutable ctx fields).
 * No conditional break: bpf_loop controls iteration count.
 * This minimises verifier state: single straight-line path, converges
 * in one abstract iteration. */
struct b64_dec_ctx
{
    __u8 *scratch;
    __u32 in_off;
    __u32 out_off;
};

static long b64_decode_step(__u32 idx, void *_ctx)
{
    struct b64_dec_ctx *ctx = (struct b64_dec_ctx *)_ctx;
    __u32 pos = idx * 4;
    __u32 opos = idx * 3;

    __u32 i0 = (ctx->in_off + pos) & (SCRATCH_SIZE - 1);
    __u32 i1 = (ctx->in_off + pos + 1) & (SCRATCH_SIZE - 1);
    __u32 i2 = (ctx->in_off + pos + 2) & (SCRATCH_SIZE - 1);
    __u32 i3 = (ctx->in_off + pos + 3) & (SCRATCH_SIZE - 1);

    __u8 v0 = b64_dec_lut[ctx->scratch[i0]];
    __u8 v1 = b64_dec_lut[ctx->scratch[i1]];
    __u8 v2 = b64_dec_lut[ctx->scratch[i2]];
    __u8 v3 = b64_dec_lut[ctx->scratch[i3]];

    __u32 o0 = (ctx->out_off + opos) & (SCRATCH_SIZE - 1);
    __u32 o1 = (ctx->out_off + opos + 1) & (SCRATCH_SIZE - 1);
    __u32 o2 = (ctx->out_off + opos + 2) & (SCRATCH_SIZE - 1);
    ctx->scratch[o0] = (v0 << 2) | (v1 >> 4);
    ctx->scratch[o1] = (v1 << 4) | (v2 >> 2);
    ctx->scratch[o2] = (v2 << 6) | v3;

    return 0;
}

/* Decode scratch[in_off..in_off+in_len] → scratch[out_off..].
 * Uses bpf_loop with stateless callback — idx-based offsets, no mutable ctx.
 * Returns decoded length (adjusted for '=' padding). */
static __always_inline __u32 b64_decode(__u8 *scratch, __u32 in_off, __u32 in_len, __u32 out_off)
{
    struct b64_dec_ctx ctx = {
        .scratch = scratch,
        .in_off = in_off,
        .out_off = out_off,
    };

    __u32 ngroups = in_len / 4;
    bpf_loop(ngroups, b64_decode_step, &ctx, 0);

    /* Output length = ngroups * 3, minus '=' padding chars. */
    __u32 opos = ngroups * 3;
    if (in_len >= 4)
    {
        __u8 p3 = scratch[(in_off + in_len - 1) & (SCRATCH_SIZE - 1)];
        __u8 p2 = scratch[(in_off + in_len - 2) & (SCRATCH_SIZE - 1)];
        if (p3 == '=')
            opos--;
        if (p2 == '=')
            opos--;
    }
    return opos;
}

/* Write dynamic-length ASCII syslog header with current timestamp.
 * Format: "<165>1 YYYY-MM-DDTHH:MM:SSZ <name(32 space-padded)> - - -  "
 * Always writes exactly GUT_SYSLOG_HDR_MAX (68) bytes.
 * Uses bpf_ktime_get_tai_ns() for near-wall-clock time (TAI ≈ UTC+37s). */
static __always_inline __u32 write_syslog_ascii(__u8 *buf, struct gut_config *cfg)
{

    /* Static prefix/suffix — only the 19-byte timestamp is dynamic */
    buf[0] = '<';
    buf[1] = '1';
    buf[2] = '6';
    buf[3] = '5';
    buf[4] = '>';
    buf[5] = '1';
    buf[6] = ' ';

    __u64 ns = bpf_ktime_get_tai_ns();
    /* TAI is ahead of UTC by 37 leap seconds (since 2017-01-01).
     * Subtract the offset so the formatted timestamp is UTC. */
    __u64 secs = ns / 1000000000ULL - 37;
    __u32 tod = (__u32)(secs % 86400);
    __u32 hour = tod / 3600;
    __u32 min = (tod % 3600) / 60;
    __u32 sec = tod % 60;

    /* Civil date from days since 1970-01-01 (Howard Hinnant algorithm) */
    __u32 z = (__u32)(secs / 86400) + 719468;
    __u32 era = z / 146097;
    __u32 doe = z - era * 146097;
    __u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    __u32 y = yoe + era * 400;
    __u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    __u32 mp = (5 * doy + 2) / 153;
    __u32 d = doy - (153 * mp + 2) / 5 + 1;
    __u32 m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2)
        y++;

    /* "YYYY-MM-DDTHH:MM:SS" at buf[7..25] */
    buf[7] = '0' + (y / 1000) % 10;
    buf[8] = '0' + (y / 100) % 10;
    buf[9] = '0' + (y / 10) % 10;
    buf[10] = '0' + y % 10;
    buf[11] = '-';
    buf[12] = '0' + m / 10;
    buf[13] = '0' + m % 10;
    buf[14] = '-';
    buf[15] = '0' + d / 10;
    buf[16] = '0' + d % 10;
    buf[17] = 'T';
    buf[18] = '0' + hour / 10;
    buf[19] = '0' + hour % 10;
    buf[20] = ':';
    buf[21] = '0' + min / 10;
    buf[22] = '0' + min % 10;
    buf[23] = ':';
    buf[24] = '0' + sec / 10;
    buf[25] = '0' + sec % 10;

    /* "Z <service_name(32 space-padded)> - - -  " — always 42 bytes, fixed for verifier */
    buf[26] = 'Z';
    buf[27] = ' ';

    __u32 slen = cfg->sni_domain_len;
    if (slen > 32)
        slen = 32;

    for (int i = 0; i < 32; i++)
    {
        if (i >= slen)
            break;
        buf[28 + i] = cfg->sni_domain[i];
    }

    __u32 j = 28 + slen;
    j &= 63; /* bound for verifier max 28+32 = 60 */
    buf[j] = ' ';
    buf[j + 1] = '-';
    buf[j + 2] = ' ';
    buf[j + 3] = '-';
    buf[j + 4] = ' ';
    buf[j + 5] = '-';
    buf[j + 6] = ' ';
    buf[j + 7] = ' ';

    return j + 8;
}

/* Write dynamic SIP header for obfuscation.
 * wg_type mapping (matches userspace):
 *   1 → REGISTER, 2 → SIP/2.0 200 OK, 3 → SIP/2.0 401 Unauthorized,
 *   4 (keepalive, len==32) → OPTIONS, else → MESSAGE.
 * Returns total bytes written, ending right after "a=fmtp:0 " marker.
 * Auth token in Via branch = sip_hash32(date_digits / 10000, chacha_init+4). */
/* noinline so BPF verifier sees it as a subprogram verified ONCE independently
 * of its multiple call sites.  The 5-way wg_type switch + 7-way day-of-week
 * + 12-way month inline would multiply verifier path count beyond complexity
 * budget for the full TC egress SIP program.  Caller bounds the return value
 * with &= 0x1FF + range check before any further use. */
static __attribute__((noinline)) __attribute__((unused)) __u32 write_sip_header(__u8 *buf, struct gut_config *cfg,
                                                                                __u8 wg_type, __u32 wg_len)
{
    __u32 off = 0;
    __u32 slen = cfg->sni_domain_len;
    if (slen > 32)
        slen = 32;

    /* ── Timestamp (TAI → UTC) ── */
    __u64 ns = bpf_ktime_get_tai_ns();
    __u64 secs = ns / 1000000000ULL - 37;
    __u32 tod = (__u32)(secs % 86400);
    __u32 hour = tod / 3600;
    __u32 min = (tod % 3600) / 60;
    __u32 sec = tod % 60;
    __u32 us = (__u32)((ns / 1000) % 1000000);

    /* Civil date (Howard Hinnant) */
    __u32 days_since_epoch = (__u32)(secs / 86400);
    __u32 z = days_since_epoch + 719468;
    __u32 era = z / 146097;
    __u32 doe = z - era * 146097;
    __u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    __u32 y = yoe + era * 400;
    __u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    __u32 mp = (5 * doy + 2) / 153;
    __u32 d = doy - (153 * mp + 2) / 5 + 1;
    __u32 m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2)
        y++;

    /* Day of week: 1970-01-01 = Thursday; Mon=0 */
    __u32 dow = (days_since_epoch + 3) % 7;

    /* date_numeric: all digits from "Dow, DD Mon YYYY HH:MM:SS.UUUUUU GMT"
     * left to right — must match ingress sip_date_extract_cb. */
    __u64 date_numeric = (__u64)d * 10000000000000000ULL + (__u64)y * 1000000000000ULL + (__u64)hour * 10000000000ULL + (__u64)min * 100000000ULL + (__u64)sec * 1000000ULL + (__u64)us;
    __u32 ts_100ms = (__u32)(date_numeric / 10000);
    __u32 auth_token = sip_hash32(ts_100ms, cfg->chacha_init + 4);

    /* ── Request/status line (depends on WG type) ── */
    if (wg_type == 1)
    {
        /* REGISTER sip:DOMAIN SIP/2.0\r\n */
        __builtin_memcpy(buf, "REGISTER sip:", 13);
        off = 13;
        for (int i = 0; i < 32; i++)
        {
            if (i >= slen)
                break;
            buf[off + i] = cfg->sni_domain[i];
        }
        off += slen;
        __builtin_memcpy(buf + off, " SIP/2.0\r\n", 10);
        off += 10;
    }
    else if (wg_type == 2)
    {
        /* SIP/2.0 200 OK\r\n */
        __builtin_memcpy(buf, "SIP/2.0 200 OK\r\n", 17);
        off = 17;
    }
    else if (wg_type == 3)
    {
        /* SIP/2.0 401 Unauthorized\r\n */
        __builtin_memcpy(buf, "SIP/2.0 401 Unauthorized\r\n", 26);
        off = 26;
    }
    else if (wg_type == 4 && wg_len == 32)
    {
        /* OPTIONS sip:5060@DOMAIN SIP/2.0\r\n */
        __builtin_memcpy(buf, "OPTIONS sip:5060@", 17);
        off = 17;
        for (int i = 0; i < 32; i++)
        {
            if (i >= slen)
                break;
            buf[off + i] = cfg->sni_domain[i];
        }
        off += slen;
        __builtin_memcpy(buf + off, " SIP/2.0\r\n", 10);
        off += 10;
    }
    else
    {
        /* MESSAGE sip:5060@DOMAIN SIP/2.0\r\n */
        __builtin_memcpy(buf, "MESSAGE sip:5060@", 17);
        off = 17;
        for (int i = 0; i < 32; i++)
        {
            if (i >= slen)
                break;
            buf[off + i] = cfg->sni_domain[i];
        }
        off += slen;
        __builtin_memcpy(buf + off, " SIP/2.0\r\n", 10);
        off += 10;
    }

    /* ── Via: SIP/2.0/UDP DOMAIN;branch=z9hG4bK-XXXXXXXX\r\n ── */
    __builtin_memcpy(buf + off, "Via: SIP/2.0/UDP ", 17);
    off += 17;
    for (int i = 0; i < 32; i++)
    {
        if (i >= slen)
            break;
        buf[off + i] = cfg->sni_domain[i];
    }
    off += slen;
    __builtin_memcpy(buf + off, ";branch=z9hG4bK-", 16);
    off += 16;
    /* Auth token: 8 hex chars */
    {
        __u32 tok = auth_token;
        for (int i = 7; i >= 0; i--)
        {
            __u32 nib = tok & 0xF;
            buf[off + i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
            tok >>= 4;
        }
    }
    off += 8;
    buf[off++] = '\r';
    buf[off++] = '\n';

    /* ── Date: Dow, DD Mon YYYY HH:MM:SS.UUUUUU GMT\r\n ── */
    __builtin_memcpy(buf + off, "Date: ", 6);
    off += 6;

    /* Day-of-week name */
    switch (dow % 7)
    {
    case 0:
        buf[off] = 'M';
        buf[off + 1] = 'o';
        buf[off + 2] = 'n';
        break;
    case 1:
        buf[off] = 'T';
        buf[off + 1] = 'u';
        buf[off + 2] = 'e';
        break;
    case 2:
        buf[off] = 'W';
        buf[off + 1] = 'e';
        buf[off + 2] = 'd';
        break;
    case 3:
        buf[off] = 'T';
        buf[off + 1] = 'h';
        buf[off + 2] = 'u';
        break;
    case 4:
        buf[off] = 'F';
        buf[off + 1] = 'r';
        buf[off + 2] = 'i';
        break;
    case 5:
        buf[off] = 'S';
        buf[off + 1] = 'a';
        buf[off + 2] = 't';
        break;
    default:
        buf[off] = 'S';
        buf[off + 1] = 'u';
        buf[off + 2] = 'n';
        break;
    }
    off += 3;
    buf[off++] = ',';
    buf[off++] = ' ';

    buf[off++] = '0' + d / 10;
    buf[off++] = '0' + d % 10;
    buf[off++] = ' ';

    /* Month name */
    switch ((m - 1) % 12)
    {
    case 0:
        buf[off] = 'J';
        buf[off + 1] = 'a';
        buf[off + 2] = 'n';
        break;
    case 1:
        buf[off] = 'F';
        buf[off + 1] = 'e';
        buf[off + 2] = 'b';
        break;
    case 2:
        buf[off] = 'M';
        buf[off + 1] = 'a';
        buf[off + 2] = 'r';
        break;
    case 3:
        buf[off] = 'A';
        buf[off + 1] = 'p';
        buf[off + 2] = 'r';
        break;
    case 4:
        buf[off] = 'M';
        buf[off + 1] = 'a';
        buf[off + 2] = 'y';
        break;
    case 5:
        buf[off] = 'J';
        buf[off + 1] = 'u';
        buf[off + 2] = 'n';
        break;
    case 6:
        buf[off] = 'J';
        buf[off + 1] = 'u';
        buf[off + 2] = 'l';
        break;
    case 7:
        buf[off] = 'A';
        buf[off + 1] = 'u';
        buf[off + 2] = 'g';
        break;
    case 8:
        buf[off] = 'S';
        buf[off + 1] = 'e';
        buf[off + 2] = 'p';
        break;
    case 9:
        buf[off] = 'O';
        buf[off + 1] = 'c';
        buf[off + 2] = 't';
        break;
    case 10:
        buf[off] = 'N';
        buf[off + 1] = 'o';
        buf[off + 2] = 'v';
        break;
    default:
        buf[off] = 'D';
        buf[off + 1] = 'e';
        buf[off + 2] = 'c';
        break;
    }
    off += 3;
    buf[off++] = ' ';

    buf[off++] = '0' + (y / 1000) % 10;
    buf[off++] = '0' + (y / 100) % 10;
    buf[off++] = '0' + (y / 10) % 10;
    buf[off++] = '0' + y % 10;
    buf[off++] = ' ';

    buf[off++] = '0' + hour / 10;
    buf[off++] = '0' + hour % 10;
    buf[off++] = ':';
    buf[off++] = '0' + min / 10;
    buf[off++] = '0' + min % 10;
    buf[off++] = ':';
    buf[off++] = '0' + sec / 10;
    buf[off++] = '0' + sec % 10;
    buf[off++] = '.';
    buf[off++] = '0' + (us / 100000) % 10;
    buf[off++] = '0' + (us / 10000) % 10;
    buf[off++] = '0' + (us / 1000) % 10;
    buf[off++] = '0' + (us / 100) % 10;
    buf[off++] = '0' + (us / 10) % 10;
    buf[off++] = '0' + us % 10;
    __builtin_memcpy(buf + off, " GMT\r\n", 6);
    off += 6;

    /* ── Content-Type + empty line + SDP + marker ── */
    __builtin_memcpy(buf + off, "Content-Type: application/sdp\r\n\r\n", 33);
    off += 33;
    __builtin_memcpy(buf + off, "v=0\r\nm=audio 0 RTP/AVP 0\r\na=fmtp:0 ", 35);
    off += 35;

    return off;
}

static __always_inline void write_quic_short_header(__u8 *quic, void *data_end, __u32 dcid, __u32 ppn, __u32 enc_ports, __u32 pad_len)
{
    if ((__u8 *)quic + GUT_QUIC_SHORT_HEADER_SIZE > (__u8 *)data_end)
        return;
    quic[0] = 0x40; // Short
    __builtin_memcpy((__u8 *)quic + 1, &dcid, 4);
    quic[5] = 0x01; // DCID Length 1 (RFC compliant)
    __builtin_memcpy((__u8 *)quic + 6, &ppn, 4);
    __builtin_memcpy((__u8 *)quic + 10, &enc_ports, 4);
    quic[14] = 0x00;
    quic[15] = (pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;
}

#if defined(GUT_MODE_QUIC)
static __always_inline void write_quic_long_header(__u8 *quic, void *data_end, __u8 wg_type, __u32 wg_idx, __u32 ppn, __u32 enc_ports, __u32 pad_len, const struct gut_config *cfg, __u8 *pad_block, __u8 *scratch)
{
    if ((__u8 *)quic + GUT_QUIC_LONG_HEADER_SIZE > (__u8 *)data_end)
        return;

    /* Fill entire header with PRNG first */
    __u32 time_gut = sip_hash32((__u32)bpf_ktime_get_ns(), cfg->chacha_init + 4);
    __u8 gb0 = (__u8)(time_gut);
    __u8 gb1 = (__u8)(time_gut >> 8);
    __u8 gb2 = (__u8)(time_gut >> 16);
    __u8 gb3 = (__u8)(time_gut >> 24);
    __u8 gut_bytes[4] = {gb0, gb1, gb2, gb3};

#pragma unroll
    for (int i = 0; i < 64; i++)
        quic[i] = pad_block[(i * 13) & 0x3F] ^ gut_bytes[i & 3];

    /* Unprotected header: RFC 9000 QUIC Initial */
    quic[0] = (wg_type == 3) ? 0xF3 : 0xC3; /* Long Header, 4-byte PN */
    quic[1] = 0x00;
    quic[2] = 0x00;
    quic[3] = 0x00;
    quic[4] = 0x01; /* QUIC v1 */

    /* Fixed DCID from config (precomputed, QUIC keys derived from it) */
    quic[5] = 0x08;
    __builtin_memcpy(quic + 6, cfg->quic_dcid, 8);

    /* SCID: PPN (host-order) in first 4 bytes for ingress fast-path, rest random */
    quic[14] = 0x08;
    __builtin_memcpy(quic + 15, &ppn, 4);
    __u32 scid2 = sip_hash32(wg_idx ^ 0x12345678, cfg->chacha_init + 4);
    __builtin_memcpy(quic + 19, &scid2, 4);

    /* Token: enc_ports (4 bytes, readable without AEAD decryption) */
    quic[23] = 0x04;
    __builtin_memcpy(quic + 24, &enc_ports, 4);

    /* ── Build CRYPTO frame with TLS 1.3 ClientHello + SNI ── */
    /* Use scratch[320..448] for CRYPTO frame plaintext (max 128 bytes) */
    __u8 *cf = scratch + 320;
    __u32 dlen = cfg->sni_domain_len;
    if (dlen > 32)
        dlen = 32;

    /* SNI extension: type(2)+ext_len(2)+list_len(2)+name_type(1)+name_len(2)+name */
    __u32 sni_ext_data = (dlen > 0) ? (dlen + 5) : 0;
    __u32 sni_ext_total = (dlen > 0) ? (sni_ext_data + 4) : 0;
    /* ALPN "h3": type(2)+len(2)+list(2)+proto_len(1)+"h3"(2) = 9 */
    /* supported_versions: type(2)+len(2)+list_len(1)+ver(2) = 7 */
    __u32 ext_len = sni_ext_total + 9 + 7;
    __u32 ch_body = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len; /* 43 + ext_len */
    __u32 hs_len = ch_body + 4;                               /* type(1)+length(3) */
    __u32 cf_data = hs_len;
    __u32 cf_total = 4 + cf_data; /* CRYPTO header(4) + data */
    if (cf_total > 128)
        cf_total = 128;

    __builtin_memset(cf, 0, 128);

    /* CRYPTO frame header */
    cf[0] = 0x06;
    cf[1] = 0x00;
    cf[2] = 0x40 | ((cf_data >> 8) & 0x3F);
    cf[3] = cf_data & 0xFF;
    /* ClientHello */
    cf[4] = 0x01;
    cf[5] = 0;
    cf[6] = (ch_body >> 8) & 0xFF;
    cf[7] = ch_body & 0xFF;
    cf[8] = 0x03;
    cf[9] = 0x03; /* legacy version 0x0303 */
    /* Random 32 bytes from pad_block + time */
    for (int i = 0; i < 32; i++)
        cf[10 + i] = pad_block[i & 0x3F] ^ gut_bytes[(i + 1) & 3];
    cf[42] = 0x00; /* session ID len = 0 */
    cf[43] = 0x00;
    cf[44] = 0x02; /* cipher suites len = 2 */
    cf[45] = 0x13;
    cf[46] = 0x01; /* TLS_AES_128_GCM_SHA256 */
    cf[47] = 0x01;
    cf[48] = 0x00; /* compression: null */
    cf[49] = (ext_len >> 8) & 0xFF;
    cf[50] = ext_len & 0xFF;

    __u32 eoff = 51;
    /* SNI extension (type 0x0000) */
    if (dlen > 0)
    {
        cf[eoff] = 0x00;
        cf[eoff + 1] = 0x00;
        cf[eoff + 2] = (sni_ext_data >> 8);
        cf[eoff + 3] = sni_ext_data & 0xFF;
        __u32 list_len = dlen + 3;
        cf[eoff + 4] = (list_len >> 8);
        cf[eoff + 5] = list_len & 0xFF;
        cf[eoff + 6] = 0x00; /* host_name type */
        cf[eoff + 7] = (dlen >> 8);
        cf[eoff + 8] = dlen & 0xFF;
        for (__u32 i = 0; i < 32 && i < dlen; i++)
            cf[eoff + 9 + i] = cfg->sni_domain[i];
        eoff += sni_ext_total;
    }
    /* ALPN "h3" */
    cf[eoff] = 0x00;
    cf[eoff + 1] = 0x10;
    cf[eoff + 2] = 0x00;
    cf[eoff + 3] = 0x05;
    cf[eoff + 4] = 0x00;
    cf[eoff + 5] = 0x03;
    cf[eoff + 6] = 0x02;
    cf[eoff + 7] = 'h';
    cf[eoff + 8] = '3';
    eoff += 9;
    /* supported_versions 0x0304 */
    cf[eoff] = 0x00;
    cf[eoff + 1] = 0x2b;
    cf[eoff + 2] = 0x00;
    cf[eoff + 3] = 0x03;
    cf[eoff + 4] = 0x02;
    cf[eoff + 5] = 0x03;
    cf[eoff + 6] = 0x04;

    /* ── Length field: PPN(4) + ciphertext(128) + GCM_tag(16) ── */
    /* Always encrypt fixed 128-byte block (cf is zero-padded) so all packet
     * writes use constant offsets — the BPF verifier can prove bounds. */
    __u16 quic_payload_len = 4 + 128 + 16; /* = 148 */
    quic[28] = 0x40 | ((quic_payload_len >> 8) & 0xFF);
    quic[29] = quic_payload_len & 0xFF;

    /* Write PPN in big-endian (will be HP-masked later) */
    __u8 ppn_be[4];
    ppn_be[0] = (ppn >> 24);
    ppn_be[1] = (ppn >> 16);
    ppn_be[2] = (ppn >> 8);
    ppn_be[3] = ppn;
    __builtin_memcpy(quic + 30, ppn_be, 4);

    /* ── AES-128-GCM encrypt CRYPTO frame ── */
    /* AEAD nonce = IV XOR left-padded PPN(BE) (RFC 9001 §5.3) */
    /* All temp buffers in scratch to minimize gut_egress stack frame. */
    __u8 *nonce = scratch + 624;
    __builtin_memcpy(nonce, cfg->quic_iv, 12);
    nonce[8] ^= ppn_be[0];
    nonce[9] ^= ppn_be[1];
    nonce[10] ^= ppn_be[2];
    nonce[11] ^= ppn_be[3];

    /* AAD = unprotected header bytes [0..33] */
    __u8 *aad = scratch + 448;
    __builtin_memcpy(aad, quic, 34);

    /* ── Phase 1: Precompute all AES blocks (noinline calls, depth 1) ── */
    /* H = AES(K, 0^128) */
    __u8 *H = scratch + 512;
    __builtin_memset(H, 0, 16);
    aes128_encrypt_block(cfg->quic_key_rk, H, H);

    /* CTR keystreams: AES(K, ctr_i) for i=2..9, XOR directly into cf */
    __u8 *ks_tmp = scratch + 528;
    __u8 *ctr_block = scratch + 640;
    __builtin_memcpy(ctr_block, nonce, 12);
    ctr_block[12] = 0;
    ctr_block[13] = 0;
    ctr_block[14] = 0;
    for (__u32 i = 0; i < 8; i++)
    {
        ctr_block[15] = (__u8)(i + 2);
        aes128_encrypt_block(cfg->quic_key_rk, ctr_block, ks_tmp);
        __u32 off = i * 16;
        for (int j = 0; j < 16; j++)
            cf[off + j] ^= ks_tmp[j];
    }

    /* J0 keystream: AES(K, nonce || 0x00000001) for tag finalization */
    __u8 *j0_ks = scratch + 544;
    ctr_block[15] = 1;
    aes128_encrypt_block(cfg->quic_key_rk, ctr_block, j0_ks);

    /* ── Phase 2: GHASH + tag (noinline, depth 1 → callback depth 2) ── */
    /* scratch_ghash at scratch+560: [0..15]=ghash_x, [16..31]=tmp, [32..47]=blk, [48..63]=tag_out */
    __u8 *scratch_ghash = scratch + 560;
    gcm_ghash_tag_128(H, aad, cf, j0_ks, scratch_ghash);

    /* Tag is at scratch_ghash+48 (scratch+608) */
    __u8 *tag = scratch_ghash + 48;

    /* Copy ciphertext (128 bytes) + tag (16 bytes) at fixed offsets */
    /* quic[34..162] = ciphertext, quic[162..178] = tag */
    for (__u32 i = 0; i < 128; i++)
        quic[34 + i] = cf[i];
    for (__u32 i = 0; i < 16; i++)
        quic[162 + i] = tag[i];

    /* ── Header Protection (RFC 9001 §5.4) ── */
    /* Sample starts at pn_offset+4 = 34 */
    __u8 *hp_mask = scratch + 656;
    aes128_encrypt_block(cfg->quic_hp_rk, quic + 34, hp_mask);
    /* Mask first byte (Long Header: lower 4 bits) */
    quic[0] ^= (hp_mask[0] & 0x0F);
    /* Mask PPN bytes */
    quic[30] ^= hp_mask[1];
    quic[31] ^= hp_mask[2];
    quic[32] ^= hp_mask[3];
    quic[33] ^= hp_mask[4];

    /* Fill rest of 1200-byte header with PRNG (after AEAD+tag region) */
    for (__u32 i = 178; i < GUT_QUIC_LONG_HEADER_SIZE - 1 && i < 1199; i++)
        quic[i] = pad_block[(i * 7) & 0x3F] ^ gut_bytes[i & 3];

    /* Ballast encoding in last byte (outside AEAD region) */
    quic[GUT_QUIC_LONG_HEADER_SIZE - 1] = (pad_len > 0) ? (0x40 | ((__u8)(pad_len - 1) & 0x3F)) : 0x00;
}
#endif /* GUT_MODE_QUIC — write_quic_long_header */
