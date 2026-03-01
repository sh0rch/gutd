use std::process::Command;

fn main() {
    // Get version from git tag, fallback to Cargo.toml version
    let version = get_git_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

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

    println!("cargo:rerun-if-changed=src/tc/bpf/");
    println!("cargo:rerun-if-changed=src/tc/bpf/tc_gut_egress.bpf.c");
    println!("cargo:rerun-if-changed=src/tc/bpf/xdp_gut_ingress.bpf.c");
    println!("cargo:rerun-if-changed=src/tc/bpf/gut_common.h");

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

    // Generate skeleton for egress (outer IPv4)
    let egress_skel = out_dir.join("tc_gut_egress.skel.rs");
    SkeletonBuilder::new()
        .source("src/tc/bpf/tc_gut_egress.bpf.c")
        .clang_args(["-I", "src/tc/bpf", &chacha_define, &arch_include])
        .build_and_generate(&egress_skel)
        .expect("Failed to generate TC egress (v4) skeleton");

    // Generate skeleton for egress (outer IPv6)
    let egress_v6_skel = out_dir.join("tc_gut_egress_v6.skel.rs");
    SkeletonBuilder::new()
        .source("src/tc/bpf/tc_gut_egress.bpf.c")
        .clang_args([
            "-I",
            "src/tc/bpf",
            &chacha_define,
            "-DGUT_OUTER_IPV6",
            &arch_include,
        ])
        .build_and_generate(&egress_v6_skel)
        .expect("Failed to generate TC egress (v6) skeleton");

    // Generate skeleton for XDP ingress (contains both xdp_gut_ingress + gut_tc_redirect)
    let ingress_skel = out_dir.join("xdp_gut_ingress.skel.rs");
    SkeletonBuilder::new()
        .source("src/tc/bpf/xdp_gut_ingress.bpf.c")
        .clang_args(["-I", "src/tc/bpf", &chacha_define, &arch_include])
        .build_and_generate(&ingress_skel)
        .expect("Failed to generate XDP ingress skeleton");

    println!("cargo:warning=TC eBPF skeletons generated successfully");
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
