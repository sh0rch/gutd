if (dec_len == 0) return -1;
if (dec_len > 1500) return -1;

__u32 len_arg = dec_len;
if (len_arg == 0) return -1;

if (bpf_xdp_store_bytes(ctx, wg_off, scratch, len_arg) != 0) return -1;
