use gutd::{config, crypto, installer, reload, Result};
use std::sync::atomic::{AtomicBool, Ordering};

const VERSION: &str = env!("GUT_VERSION");
const DEFAULT_CONFIG: &str = "/etc/gutd.conf";
const DEFAULT_STAT_FILE: &str = "/run/gutd.stat";

static PRINT_STATS: AtomicBool = AtomicBool::new(false);
static EXIT_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigusr1(_: libc::c_int) {
    PRINT_STATS.store(true, Ordering::Relaxed);
}

extern "C" fn handle_exit(_: libc::c_int) {
    EXIT_FLAG.store(true, Ordering::Relaxed);
}

// ──────────────────────────────────────────────────────────────────
//  Lightweight sd_notify (no external crate)
// ──────────────────────────────────────────────────────────────────

fn sd_notify(msg: &str) {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let sock = match UnixDatagram::unbound() {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = sock.send_to(msg.as_bytes(), &path);
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
                    "    Egress:  pkts={} drop={} bytes={} mask={} cookie_fail={} frag={}",
                    stats.egress.packets_processed,
                    stats.egress.packets_dropped,
                    stats.egress.bytes_processed,
                    stats.egress.mask_count,
                    stats.egress.cookie_validation_failed,
                    stats.egress.packets_fragmented
                );
                eprintln!(
                    "    Ingress: pkts={} drop={} bytes={} mask={} cookie_fail={} frag={}",
                    stats.ingress.packets_processed,
                    stats.ingress.packets_dropped,
                    stats.ingress.bytes_processed,
                    stats.ingress.mask_count,
                    stats.ingress.cookie_validation_failed,
                    stats.ingress.packets_fragmented
                );
            }
            Err(e) => eprintln!("  [{}] Failed to read BPF stats: {e}", manager.interface()),
        }
    }
}

/// Dump counters to file (atomic write via tmp + rename).
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
                let _ = writeln!(
                    buf,
                    "{peer}_egress_packets={}",
                    stats.egress.packets_processed
                );
                let _ = writeln!(
                    buf,
                    "{peer}_egress_dropped={}",
                    stats.egress.packets_dropped
                );
                let _ = writeln!(buf, "{peer}_egress_bytes={}", stats.egress.bytes_processed);
                let _ = writeln!(buf, "{peer}_egress_mask_ops={}", stats.egress.mask_count);
                let _ = writeln!(
                    buf,
                    "{peer}_egress_cookie_validation_failed={}",
                    stats.egress.cookie_validation_failed
                );
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
                    "{peer}_ingress_packets={}",
                    stats.ingress.packets_processed
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_dropped={}",
                    stats.ingress.packets_dropped
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_bytes={}",
                    stats.ingress.bytes_processed
                );
                let _ = writeln!(buf, "{peer}_ingress_mask_ops={}", stats.ingress.mask_count);
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_cookie_validation_failed={}",
                    stats.ingress.cookie_validation_failed
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_fragmented={}",
                    stats.ingress.packets_fragmented
                );
                let _ = writeln!(
                    buf,
                    "{peer}_ingress_inner_tcp_seen={}",
                    stats.ingress.inner_tcp_seen
                );
            }
            Err(e) => {
                let _ = writeln!(buf, "{peer}_bpf_stats_error={e}");
            }
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
                "install" => installer::run_install(),
                "uninstall" => installer::run_uninstall(),
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

    let config_path = config_path.unwrap_or_else(|| {
        if std::path::Path::new(DEFAULT_CONFIG).exists() {
            DEFAULT_CONFIG.to_string()
        } else {
            "gutd.conf".to_string()
        }
    });

    run_daemon(&config_path)
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
        let fd = std::fs::File::open("/dev/urandom")?;
        use std::io::Read;
        let mut reader = std::io::BufReader::new(fd);
        reader.read_exact(&mut key)?;
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

fn run_daemon(config_path: &str) -> Result<()> {
    eprintln!("gutd {VERSION} starting...");

    let config = config::load_config(config_path)?;
    eprintln!("Loaded config from {config_path}");

    let stats_interval = config.runtime.stats_interval;
    let stat_file = config.runtime.stat_file.clone();

    // Signal handlers
    unsafe {
        reload::setup_signal_handler()?;

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;

        sa.sa_sigaction = handle_sigusr1 as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &raw const sa, std::ptr::null_mut());

        sa.sa_sigaction = handle_exit as *const () as usize;
        libc::sigaction(libc::SIGINT, &raw const sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &raw const sa, std::ptr::null_mut());
    }
    eprintln!("Signal handlers installed (SIGHUP=reload, SIGUSR1=stats, SIGINT/SIGTERM=exit)");

    #[cfg(not(target_os = "linux"))]
    {
        return Err("TC eBPF mode is only supported on Linux".into());
    }

    #[cfg(target_os = "linux")]
    {
        use gutd::tc::TcBpfManager;

        // Build a single-peer Config wrapper so the existing TcBpfManager::new
        // interface (which reads config.peer()) receives exactly one peer.
        let make_single = |cfg: &config::Config, peer: &config::PeerConfig| config::Config {
            global: cfg.global.clone(),
            runtime: cfg.runtime.clone(),
            peers: vec![peer.clone()],
        };

        let mut managers: Vec<TcBpfManager> = Vec::new();
        for peer in &config.peers {
            let single = make_single(&config, peer);
            let mgr = TcBpfManager::new(&peer.name, &single)?;
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

            if EXIT_FLAG.load(Ordering::Relaxed) {
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
                eprintln!("SIGHUP received — reloading config from {config_path}");
                match config::load_config(config_path) {
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
        dump_counters_file(&stat_file, start.elapsed().as_secs_f64(), &managers);
        print_bpf_stats(&managers);
        eprintln!("Exiting, BPF programs will be detached");
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────
//  Usage
// ──────────────────────────────────────────────────────────────────

fn print_usage() {
    println!("gutd {VERSION} — Low-overhead IP-over-UDP obfuscation tunnel (BPF)");
    println!();
    println!("USAGE:");
    println!("    gutd [OPTIONS] [CONFIG_FILE]");
    println!("    gutd <SUBCOMMAND>");
    println!();
    println!("OPTIONS:");
    println!("    -c, --config <FILE>  Path to configuration file [default: /etc/gutd.conf]");
    println!("    -v, --version        Print version information");
    println!("    -h, --help           Print this help message");
    println!();
    println!("SUBCOMMANDS:");
    println!("    install              Install binary, config, and systemd/OpenRC service");
    println!("    uninstall            Remove binary and service (config preserved)");
    println!("    genkey               Generate random 256-bit key");
    println!("    genkey -p <TEXT>     Derive key from passphrase (HKDF-SHA256)");
    println!("    status [STAT_FILE]   Show counters from stat file [default: /run/gutd.stat]");
    println!("    version              Print version");
    println!("    help                 Print this help");
    println!();
    println!("SIGNALS:");
    println!("    SIGHUP               Reload configuration");
    println!("    SIGUSR1              Print BPF statistics");
    println!("    SIGINT/SIGTERM       Graceful shutdown");
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
    println!("    gutd install creates /etc/gutd.conf with example config.");
}
