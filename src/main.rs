use gutd::{config, crypto, reload, Result};

const VERSION: &str = env!("GUT_VERSION");
#[cfg(target_family = "unix")]
const DEFAULT_CONFIG: &str = "/etc/gutd.conf";
#[cfg(target_family = "windows")]
const DEFAULT_CONFIG: &str = "C:\\ProgramData\\gutd\\gutd.conf";
#[cfg(target_family = "unix")]
const DEFAULT_STAT_FILE: &str = "/run/gutd.stat";
#[cfg(target_family = "windows")]
const DEFAULT_STAT_FILE: &str = "C:\\ProgramData\\gutd\\gutd.stat";

#[cfg(target_family = "unix")]
static PRINT_STATS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_family = "unix")]
extern "C" fn handle_sigusr1(_: libc::c_int) {
    use std::sync::atomic::Ordering;
    PRINT_STATS.store(true, Ordering::Relaxed);
}

#[cfg(target_family = "unix")]
extern "C" fn handle_exit(_: libc::c_int) {
    use std::sync::atomic::Ordering;
    reload::EXIT_FLAG.store(true, Ordering::Relaxed);
}

// ──────────────────────────────────────────────────────────────────
//  Lightweight sd_notify (no external crate)
// ──────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn sd_notify(_msg: &str) {
    #[cfg(target_family = "unix")]
    {
        if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
            use std::os::unix::net::UnixDatagram;
            let sock = match UnixDatagram::unbound() {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = sock.send_to(_msg.as_bytes(), &path);
        }
    }
}

// ──────────────────────────────────────────────────────────────────
//  BPF stats reading
// ──────────────────────────────────────────────────────────────────

/// Read and display BPF map statistics for all peers.
#[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
fn print_bpf_stats(managers: &[gutd::tc::TcBpfManager]) {
    eprintln!("=== gutd BPF Statistics ===");
    for manager in managers {
        match manager.get_stats() {
            Ok(stats) => {
                eprintln!("  [{}]", manager.interface());
                eprintln!(
                    "    Egress:  pkts={} drop(cp1)={} bytes(cp4)={} mask(cp5)={} frag(cp2)={} oversz(cp3)={} xdp_decoded_fail={} ",
                    stats.egress.packets_egress,
                    stats.egress.packets_dropped,
                    stats.egress.bytes_processed,
                    stats.egress.mask_count,
                    stats.egress.packets_fragmented,
                    stats.egress.packets_oversized,
                    stats.egress.inner_tcp_seen,
                );
                eprintln!(
                    "    Ingress: pkts={} drop={} bytes={} mask={} frag={} oversized={}",
                    stats.egress.packets_ingress,
                    stats.egress.packets_dropped,
                    stats.egress.bytes_processed,
                    stats.egress.mask_count,
                    stats.egress.packets_fragmented,
                    stats.egress.packets_oversized
                );
            }
            Err(e) => eprintln!("  [{}] Failed to read BPF stats: {e}", manager.interface()),
        }
    }
}

/// Dump counters to file (atomic write via tmp + rename).
#[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
fn dump_counters_file(
    path: &str,
    uptime_secs: f64,
    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))] managers: &[gutd::tc::TcBpfManager],
) {
    use std::fmt::Write as FmtWrite;

    let mut buf = String::with_capacity(512);
    let _ = writeln!(buf, "# gutd counters");
    let _ = writeln!(buf, "version={VERSION}");
    let _ = writeln!(buf, "uptime_secs={uptime_secs:.1}");
    let _ = writeln!(
        buf,
        "drop_policy_safety_overrides_total={}",
        gutd::tc::drop_policy_safety_overrides()
    );

    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
    for manager in managers {
        let peer = manager.interface();
        match manager.get_stats() {
            Ok(stats) => {
                let _ = writeln!(buf, "{peer}_egress_packets={}", stats.egress.packets_egress);
                let _ = writeln!(
                    buf,
                    "{peer}_egress_dropped={}",
                    stats.egress.packets_dropped
                );
                let _ = writeln!(buf, "{peer}_egress_bytes={}", stats.egress.bytes_processed);
                let _ = writeln!(buf, "{peer}_egress_mask_ops={}", stats.egress.mask_count);
                let _ = writeln!(
                    buf,
                    "{peer}_egress_fragmented={}",
                    stats.egress.packets_fragmented
                );
                let _ = writeln!(
                    buf,
                    "{peer}_egress_inner_tcp_seen={}",
                    stats.egress.inner_tcp_seen
                );
                let _ = writeln!(
                    buf,
                    "{peer}_egress_oversized={}",
                    stats.egress.packets_oversized
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_packets={}",
                    stats.egress.packets_ingress
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_dropped={}",
                    stats.egress.packets_dropped
                );
                let _ = writeln!(buf, "{peer}_ingress_bytes={}", stats.egress.bytes_processed);
                let _ = writeln!(buf, "{peer}_ingress_mask_ops={}", stats.egress.mask_count);
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_fragmented={}",
                    stats.egress.packets_fragmented
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_inner_tcp_seen={}",
                    stats.egress.inner_tcp_seen
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_oversized={}",
                    stats.egress.packets_oversized
                );
            }
            Err(e) => {
                let _ = writeln!(buf, "{peer}_bpf_stats_error={e}");
            }
        }
    }

    // Ensure parent directory exists first
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    // Atomic write: tmp → rename
    let tmp = format!("{path}.tmp");
    if let Err(e) = std::fs::write(&tmp, &buf).and_then(|_| std::fs::rename(&tmp, path)) {
        eprintln!("Failed to write {path}: {e}");
    }
}

// ──────────────────────────────────────────────────────────────────
//  CLI
// ──────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Intercept subcommands before normal flag parsing
    if let Some(subcmd) = args.get(1) {
        if !subcmd.starts_with('-') {
            match subcmd.as_str() {
                "install" => gutd::installer::run_install(),
                "uninstall" => gutd::installer::run_uninstall(),
                "genkey" => return cmd_genkey(&args),
                "status" => return cmd_status(&args),
                "version" => {
                    println!("gutd {VERSION}");
                    return Ok(());
                }
                "help" => {
                    print_usage();
                    return Ok(());
                }
                _ => {
                    // Fall through — might be a config file path (legacy)
                }
            }
        }
    }

    // Parse flags
    let mut config_path: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--version" => {
                println!("gutd {VERSION}");
                return Ok(());
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "-c" | "--config" => {
                i += 1;
                config_path = Some(args.get(i).ok_or("--config requires a path")?.clone());
            }
            other => {
                // Legacy: positional config file path
                if !other.starts_with('-') && config_path.is_none() {
                    config_path = Some(other.to_string());
                } else {
                    eprintln!("Unknown option: {other}");
                    eprintln!("Try: gutd --help");
                    std::process::exit(1);
                }
            }
        }
        i += 1;
    }

    let config_path_explicit = config_path.is_some();

    // Env-var mode takes full priority — no file lookup at all.
    if !config_path_explicit && std::env::var("GUTD_PEER_IP").is_ok() {
        eprintln!("GUTD_PEER_IP detected — loading configuration from environment variables");
        let config = config::load_config_from_env()?;
        return run_daemon(config, None);
    }

    // Resolve config path: explicit > /etc/gutd.conf > ./gutd.conf > helpful error.
    let config_path = if let Some(p) = config_path {
        p
    } else if std::path::Path::new(DEFAULT_CONFIG).exists() {
        DEFAULT_CONFIG.to_string()
    } else if std::path::Path::new("gutd.conf").exists() {
        "gutd.conf".to_string()
    } else {
        eprintln!("Error: no configuration found.");
        eprintln!();
        eprintln!("Option 1 — environment variables (no file needed):");
        print_env_hint();
        eprintln!("Option 2 — config file:");
        eprintln!("  gutd --config /path/to/gutd.conf");
        eprintln!("  gutd install    # install system service + example config");
        eprintln!();
        eprintln!("Run 'gutd --help' for full reference.");
        std::process::exit(1);
    };

    let config = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Tip: use environment variables instead of a config file:");
            print_env_hint();
            eprintln!("Run 'gutd --help' for full reference.");
            std::process::exit(1);
        }
    };
    run_daemon(config, Some(config_path))
}

// ──────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────

fn print_env_hint() {
    eprintln!("  export GUTD_PEER_IP=<remote-ip>");
    eprintln!("  export GUTD_BIND_IP=0.0.0.0");
    eprintln!("  export GUTD_ADDRESS=10.0.0.1/30");
    eprintln!("  export GUTD_PORTS=41000,41001,41002,41003");
    eprintln!("  export GUTD_KEY=<64-char-hex>   # or GUTD_PASSPHRASE=<phrase>");
    eprintln!("  gutd");
    eprintln!();
}

// ──────────────────────────────────────────────────────────────────
//  Subcommands
// ──────────────────────────────────────────────────────────────────

/// `gutd genkey` — generate a random key or derive from passphrase
fn cmd_genkey(args: &[String]) -> Result<()> {
    let mut passphrase: Option<&str> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--passphrase" | "-p" => {
                i += 1;
                passphrase = Some(
                    args.get(i)
                        .map(|s| s.as_str())
                        .ok_or("--passphrase requires a value")?,
                );
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(phrase) = passphrase {
        let key = crypto::derive_key(phrase);
        println!("{}", crypto::key_to_hex(&key));
        eprintln!("# Derived from passphrase via HKDF-SHA256");
        eprintln!("# Add to config:  key = {}", crypto::key_to_hex(&key));
        eprintln!("#   or:           passphrase = {phrase}");
    } else {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|e| format!("Failed to generate random key: {e}"))?;
        println!("{}", crypto::key_to_hex(&key));
        eprintln!("# Random 256-bit key");
        eprintln!("# Add to config:  key = {}", crypto::key_to_hex(&key));
    }
    Ok(())
}

/// `gutd status` — show counters from stat file
fn cmd_status(args: &[String]) -> Result<()> {
    let stat_file = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_STAT_FILE);

    match std::fs::read_to_string(stat_file) {
        Ok(content) => {
            println!("=== gutd Status ===");
            println!("(from {stat_file})");
            println!();
            print!("{content}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Cannot read {stat_file}: {e}");
            eprintln!("Is gutd running? (stat_file is written periodically by the daemon)");
            std::process::exit(1);
        }
    }
}

// ──────────────────────────────────────────────────────────────────
//  Daemon main loop
// ──────────────────────────────────────────────────────────────────

fn run_daemon(config: config::Config, reload_source: Option<String>) -> Result<()> {
    sd_notify("READY=1");
    if config.global.userspace_only || std::env::var("GUTD_USERSPACE").is_ok() {
        return gutd::userspace::run(&config);
    }
    eprintln!("gutd {VERSION} starting...");

    match &reload_source {
        Some(path) => eprintln!("Loaded config from {path}"),
        None => eprintln!("Loaded config from environment variables"),
    }

    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
    let stats_interval = config.runtime.stats_interval;
    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
    let stat_file = config.runtime.stat_file.clone();

    // Signal handlers
    reload::setup_signal_handler()?;
    #[cfg(target_family = "unix")]
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;

        sa.sa_sigaction = handle_sigusr1 as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &raw const sa, std::ptr::null_mut());

        sa.sa_sigaction = handle_exit as *const () as usize;
        libc::sigaction(libc::SIGINT, &raw const sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &raw const sa, std::ptr::null_mut());
    }
    #[cfg(target_family = "windows")]
    {
        // On Windows, Ctrl+C sets EXIT_FLAG via the handler registered in reload module
    }
    eprintln!("Signal handlers installed");

    #[cfg(not(target_os = "linux"))]
    return Err("TC eBPF mode is only supported on Linux. Use userspace_only = true.".into());

    #[cfg(all(target_os = "linux", not(feature = "tc_ebpf")))]
    return Err("This build was compiled without eBPF support. Use userspace_only = true.".into());

    #[cfg(all(target_os = "linux", feature = "tc_ebpf"))]
    {
        use gutd::tc::TcBpfManager;
        use gutd::tc::XdpDispatcher;
        use std::sync::atomic::Ordering;

        // Build a single-peer Config wrapper so the existing TcBpfManager::new
        // interface (which reads config.peer()) receives exactly one peer.
        let make_single = |cfg: &config::Config, peer: &config::PeerConfig| config::Config {
            global: cfg.global.clone(),
            runtime: cfg.runtime.clone(),
            peers: vec![peer.clone()],
        };

        // Per-NIC XDP dispatchers: first peer on a NIC creates the dispatcher,
        // subsequent peers reuse it (their programs are registered via tail-call).
        let mut dispatchers: std::collections::HashMap<String, XdpDispatcher> =
            std::collections::HashMap::new();

        let mut managers: Vec<TcBpfManager> = Vec::new();
        for peer in &config.peers {
            let single = make_single(&config, peer);
            let mgr = TcBpfManager::new(&peer.name, &single, &mut dispatchers)?;
            managers.push(mgr);
        }

        eprintln!(
            "TC eBPF mode activated — {} peer(s) — all packet processing in kernel",
            managers.len()
        );

        // Notify systemd: service is ready
        sd_notify("READY=1");
        eprintln!("Ready (sd_notify READY=1)");

        let start = std::time::Instant::now();
        let mut stats_tick: u32 = 0;
        let stats_ticks_target = if stats_interval > 0 {
            stats_interval * 2 // ×500ms
        } else {
            0
        };

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Watchdog ping
            sd_notify("WATCHDOG=1");

            if reload::EXIT_FLAG.load(Ordering::Relaxed) {
                eprintln!("Received exit signal, shutting down...");
                sd_notify("STOPPING=1");
                break;
            }

            if PRINT_STATS.swap(false, Ordering::Relaxed) {
                print_bpf_stats(&managers);
            }

            // Periodic stats dump
            if stats_ticks_target > 0 {
                stats_tick += 1;
                if stats_tick >= stats_ticks_target {
                    stats_tick = 0;
                    dump_counters_file(&stat_file, start.elapsed().as_secs_f64(), &managers);
                }
            }

            if reload::should_reload() {
                reload::clear_reload_flag();
                sd_notify("RELOADING=1");
                let new_config_result = match &reload_source {
                    Some(path) => {
                        eprintln!("SIGHUP received — reloading config from {path}");
                        config::load_config(path)
                    }
                    None => {
                        eprintln!("SIGHUP received — reloading config from environment variables");
                        config::load_config_from_env()
                    }
                };
                match new_config_result {
                    Ok(new_config) => {
                        let mut any_err = false;
                        for mgr in &mut managers {
                            if let Some(peer) =
                                new_config.peers.iter().find(|p| p.name == mgr.interface())
                            {
                                let single = make_single(&new_config, peer);
                                if let Err(e) = mgr.update_config(&single) {
                                    eprintln!(
                                        "Config reload failed for peer '{}': {e}",
                                        mgr.interface()
                                    );
                                    any_err = true;
                                }
                            } else {
                                eprintln!(
                                    "Config reload: peer '{}' not found in new config (skipped)",
                                    mgr.interface()
                                );
                            }
                        }
                        if !any_err {
                            eprintln!("Config reloaded successfully");
                        }
                    }
                    Err(e) => {
                        eprintln!("Config reload failed: {e}");
                    }
                }
                sd_notify("READY=1");
            }
        }

        // Final stats
        if stats_ticks_target > 0 {
            dump_counters_file(&stat_file, start.elapsed().as_secs_f64(), &managers);
        }
        print_bpf_stats(&managers);
        eprintln!("Exiting, BPF programs will be detached");

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────
//  Usage
// ──────────────────────────────────────────────────────────────────

fn print_usage() {
    println!("gutd {VERSION} — Low-overhead IP-over-UDP obfuscation tunnel");
    println!();
    println!("USAGE:");
    println!("    gutd [OPTIONS] [CONFIG_FILE]");
    println!("    gutd <SUBCOMMAND>");
    println!();
    println!("OPTIONS:");
    println!("    -c, --config <FILE>  Path to configuration file [default: {DEFAULT_CONFIG}]");
    println!("    -v, --version        Print version information");
    println!("    -h, --help           Print this help message");
    println!();
    println!("SUBCOMMANDS:");
    #[cfg(target_os = "linux")]
    {
        println!("    install              Install binary, config, and systemd/OpenRC service");
        println!("    uninstall            Remove binary and service (config preserved)");
    }
    #[cfg(target_family = "windows")]
    {
        println!("    install              Install binary, config, and Windows Service");
        println!("    uninstall            Remove binary and service (config preserved)");
    }
    println!("    genkey               Generate random 256-bit key");
    println!("    genkey -p <TEXT>     Derive key from passphrase (HKDF-SHA256)");
    println!(
        "    status [STAT_FILE]   Show counters from stat file [default: {DEFAULT_STAT_FILE}]"
    );
    println!("    version              Print version");
    println!("    help                 Print this help");
    #[cfg(target_family = "unix")]
    {
        println!();
        println!("SIGNALS:");
        println!("    SIGHUP               Reload configuration");
        println!("    SIGUSR1              Print BPF statistics");
        println!("    SIGINT/SIGTERM       Graceful shutdown");
    }
    println!();
    println!("SYSTEMD:");
    println!("    Type=notify with WatchdogSec=30");
    println!("    gutd sends READY=1, WATCHDOG=1, RELOADING=1, STOPPING=1");
    println!();
    println!("CONFIG:");
    println!("    Key can be specified as:");
    println!("      key = <64 hex chars>           Raw 32-byte key");
    println!("      passphrase = <text>            Derived via HKDF-SHA256");
    println!();
    println!("    gutd install creates {DEFAULT_CONFIG} with example config.");
}
