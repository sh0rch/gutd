use std::process::Command;

fn main() {
    // Get version from env, fallback to git tag, fallback to Cargo.toml version
    let version = std::env::var("GUT_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(get_git_version)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=GUT_VERSION={version}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    // TC eBPF compilation (only if tc_ebpf feature enabled and on Linux)
    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
    {
        compile_tc_ebpf();
    }
}

#[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
fn compile_tc_ebpf() {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=src/bpf/");
    println!("cargo:rerun-if-changed=src/bpf/tc_gut_egress.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/xdp_gut_ingress.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/xdp_dispatcher.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/gut_common.h");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Read CHACHA_ROUNDS from environment, default to 4 (ChaCha4)
    let chacha_rounds = env::var("CHACHA_ROUNDS").unwrap_or_else(|_| "4".to_string());
    let chacha_define = format!("-DCHACHA_ROUNDS={chacha_rounds}");
    println!("cargo:warning=BPF CHACHA_ROUNDS={chacha_rounds}");

    // Arch-specific include path for asm/types.h (needed by linux/types.h)
    // On Ubuntu/Debian x86_64 this is /usr/include/x86_64-linux-gnu
    let arch_include = format!(
        "-I/usr/include/{}",
        std::env::consts::ARCH.replace("x86_64", "x86_64-linux-gnu")
    );

    // Compile using libbpf-cargo SkeletonBuilder

    // ── GUT mode skeletons (default, no -D flag needed for C code,
    //    but we pass -DGUT_MODE_GUT to select the GUT code path) ──

    // Generate skeleton for egress GUT mode (outer IPv4)
    let egress_skel = out_dir.join("tc_gut_egress.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_GUT",
            &arch_include,
        ])
        .build_and_generate(&egress_skel)
        .expect("Failed to generate TC egress GUT (v4) skeleton");

    // Generate skeleton for egress GUT mode (outer IPv6)
    let egress_v6_skel = out_dir.join("tc_gut_egress_v6.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_GUT",
            "-DGUT_OUTER_IPV6",
            &arch_include,
        ])
        .build_and_generate(&egress_v6_skel)
        .expect("Failed to generate TC egress GUT (v6) skeleton");

    // Generate skeleton for XDP ingress GUT mode
    let ingress_skel = out_dir.join("xdp_gut_ingress.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/xdp_gut_ingress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_GUT",
            &arch_include,
        ])
        .build_and_generate(&ingress_skel)
        .expect("Failed to generate XDP ingress GUT skeleton");

    // ── QUIC mode skeletons (no -D mode flag = QUIC default in C code) ──

    // Generate skeleton for egress QUIC mode (outer IPv4)
    let egress_quic_skel = out_dir.join("tc_gut_egress_quic.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args(["-I", "src/bpf", &chacha_define, &arch_include])
        .build_and_generate(&egress_quic_skel)
        .expect("Failed to generate TC egress QUIC (v4) skeleton");

    // Generate skeleton for egress QUIC mode (outer IPv6)
    let egress_quic_v6_skel = out_dir.join("tc_gut_egress_quic_v6.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_OUTER_IPV6",
            &arch_include,
        ])
        .build_and_generate(&egress_quic_v6_skel)
        .expect("Failed to generate TC egress QUIC (v6) skeleton");

    // Generate skeleton for XDP ingress QUIC mode
    let ingress_quic_skel = out_dir.join("xdp_gut_ingress_quic.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/xdp_gut_ingress.bpf.c")
        .clang_args(["-I", "src/bpf", &chacha_define, &arch_include])
        .build_and_generate(&ingress_quic_skel)
        .expect("Failed to generate XDP ingress QUIC skeleton");

    // ── Syslog mode skeletons ───────────────────────────────────────

    // Generate skeleton for egress Syslog mode (outer IPv4)
    let egress_syslog_skel = out_dir.join("tc_gut_egress_syslog.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SYSLOG",
            &arch_include,
        ])
        .build_and_generate(&egress_syslog_skel)
        .expect("Failed to generate TC egress Syslog (v4) skeleton");

    // Generate skeleton for egress Syslog mode (outer IPv6)
    let egress_syslog_v6_skel = out_dir.join("tc_gut_egress_syslog_v6.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SYSLOG",
            "-DGUT_OUTER_IPV6",
            &arch_include,
        ])
        .build_and_generate(&egress_syslog_v6_skel)
        .expect("Failed to generate TC egress Syslog (v6) skeleton");

    // Generate skeleton for XDP ingress Syslog mode
    let ingress_syslog_skel = out_dir.join("xdp_gut_ingress_syslog.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/xdp_gut_ingress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SYSLOG",
            &arch_include,
        ])
        .build_and_generate(&ingress_syslog_skel)
        .expect("Failed to generate XDP ingress Syslog skeleton");

    // ── SIP mode skeletons ────────────────────────────────────────

    // Generate skeleton for egress SIP mode (outer IPv4)
    let egress_sip_skel = out_dir.join("tc_gut_egress_sip.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SIP",
            &arch_include,
        ])
        .build_and_generate(&egress_sip_skel)
        .expect("Failed to generate TC egress SIP (v4) skeleton");

    // Generate skeleton for egress SIP mode (outer IPv6)
    let egress_sip_v6_skel = out_dir.join("tc_gut_egress_sip_v6.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SIP",
            "-DGUT_OUTER_IPV6",
            &arch_include,
        ])
        .build_and_generate(&egress_sip_v6_skel)
        .expect("Failed to generate TC egress SIP (v6) skeleton");

    // Generate skeleton for XDP ingress SIP mode
    let ingress_sip_skel = out_dir.join("xdp_gut_ingress_sip.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/xdp_gut_ingress.bpf.c")
        .clang_args([
            "-I",
            "src/bpf",
            &chacha_define,
            "-DGUT_MODE_SIP",
            &arch_include,
        ])
        .build_and_generate(&ingress_sip_skel)
        .expect("Failed to generate XDP ingress SIP skeleton");

    println!("cargo:warning=TC eBPF skeletons generated successfully (GUT + QUIC + Syslog + SIP)");

    // ── XDP Dispatcher (multi-peer port router) ─────────────────────
    let dispatcher_skel = out_dir.join("xdp_dispatcher.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/xdp_dispatcher.bpf.c")
        .clang_args(["-I", "src/bpf", &arch_include])
        .build_and_generate(&dispatcher_skel)
        .expect("Failed to generate XDP dispatcher skeleton");
}

fn get_git_version() -> Option<String> {
    // Try to get the current git tag
    let tag_output = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
        .ok()?;

    if tag_output.status.success() {
        let tag = String::from_utf8(tag_output.stdout).ok()?;
        return Some(tag.trim().to_string());
    }

    // If not on a tag, try to get the latest tag + commit info
    let describe_output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;

    if describe_output.status.success() {
        let version = String::from_utf8(describe_output.stdout).ok()?;
        return Some(version.trim().to_string());
    }

    // Fallback: try to get just the commit hash
    let commit_output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if commit_output.status.success() {
        let commit = String::from_utf8(commit_output.stdout).ok()?;
        return Some(format!("git-{}", commit.trim()));
    }

    None
}
