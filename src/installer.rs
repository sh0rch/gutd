//! Install / uninstall subcommands.
//!
//! - **Linux**: copy binary, write example config, create systemd/OpenRC service
//! - **Windows**: copy binary, write example config, register Windows Service (manual start)
//! - `gutd uninstall` — stop service, remove binary and service (config preserved)

use std::fs;
use std::path::Path;
use std::process::Command;

#[cfg(target_family = "unix")]
const BIN_PATH: &str = "/usr/local/bin/gutd";
#[cfg(target_family = "windows")]
const BIN_PATH: &str = "C:\\Program Files\\gutd\\gutd.exe";

#[cfg(target_family = "unix")]
const CONFIG_PATH: &str = "/etc/gutd.conf";
#[cfg(target_family = "windows")]
const CONFIG_PATH: &str = "C:\\ProgramData\\gutd\\gutd.conf";

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "/etc/systemd/system/gutd.service";
#[cfg(target_os = "linux")]
const OPENRC_INIT: &str = "/etc/init.d/gutd";

#[cfg(target_family = "windows")]
const SERVICE_NAME: &str = "gutd";

// ──────────────────────────────────────────────────────────────────
//  Init system detection (Linux only)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitSystem {
    Systemd,
    OpenRC,
    Unknown,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Systemd => write!(f, "systemd"),
            Self::OpenRC => write!(f, "OpenRC"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_init() -> InitSystem {
    if Path::new("/run/systemd/system").exists() {
        return InitSystem::Systemd;
    }
    if Command::new("rc-service").arg("--version").output().is_ok() {
        return InitSystem::OpenRC;
    }
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let comm = comm.trim();
        if comm == "systemd" {
            return InitSystem::Systemd;
        }
        if comm == "init" && Path::new("/sbin/openrc").exists() {
            return InitSystem::OpenRC;
        }
    }
    InitSystem::Unknown
}

// ──────────────────────────────────────────────────────────────────
//  Service templates (Linux)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn systemd_unit() -> String {
    format!(
        r#"[Unit]
Description=GUT IP-over-UDP Obfuscation Tunnel
Documentation=https://github.com/sh0rch/gutd
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={bin} -c {config}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78
WatchdogSec=30

# Hardening
ProtectSystem=strict
ReadWritePaths=/run /sys/fs/bpf /sys/kernel/debug /sys/class/net
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_PERFMON

StandardOutput=journal
StandardError=journal
SyslogIdentifier=gutd

[Install]
WantedBy=multi-user.target
"#,
        bin = BIN_PATH,
        config = CONFIG_PATH,
    )
}

#[cfg(target_os = "linux")]
fn openrc_init_script() -> String {
    format!(
        r#"#!/sbin/openrc-run

description="GUT IP-over-UDP Obfuscation Tunnel"
command="{bin}"
command_args="-c {config}"
command_background=true
pidfile="/run/${{RC_SVCNAME}}.pid"
output_log="/var/log/${{RC_SVCNAME}}.log"
error_log="/var/log/${{RC_SVCNAME}}.log"

depend() {{
    need net
    after firewall
}}

reload() {{
    ebegin "Reloading ${{RC_SVCNAME}}"
    start-stop-daemon --signal HUP --pidfile "$pidfile"
    eend $?
}}
"#,
        bin = BIN_PATH,
        config = CONFIG_PATH,
    )
}

fn example_config() -> String {
    format!(
        r#"# {path} — gutd tunnel configuration
#
# Generate key:    gutd genkey
# From passphrase: gutd genkey --passphrase "my secret"

[global]
# outer_mtu = 1500          # Managed automatically
# stats_interval = 5        # stats dump interval, seconds (0 = off)
# stat_file = {stat_file}
userspace_only = {userspace}

[peer]
name = gut0
# mtu = 1492                # Managed automatically
# nic = eth0                # physical NIC for XDP (auto-detected if omitted)
# responder = true           # QUIC server role; auto from dynamic_peer if not set
# bind_ip = 0.0.0.0         # default: 0.0.0.0 (auto)
peer_ip = 203.0.113.10
ports = 41000
keepalive_drop_percent = 30

# own_http3 = true

# Key — choose ONE:
# passphrase = change-me-to-a-strong-passphrase
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
"#,
        path = CONFIG_PATH,
        stat_file = if cfg!(target_family = "windows") {
            "C:\\ProgramData\\gutd\\gutd.stat"
        } else {
            "/run/gutd.stat"
        },
        userspace = if cfg!(target_family = "windows") {
            "true"
        } else {
            "false"
        },
    )
}

// ──────────────────────────────────────────────────────────────────
//  Install (Linux)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn run_install() -> ! {
    if !is_root() {
        eprintln!("Error: install requires root privileges");
        std::process::exit(1);
    }

    let init = detect_init();
    let mut actions: Vec<String> = Vec::new();

    // 1. Copy binary
    let self_exe = std::env::current_exe().expect("cannot determine own path");
    let dest = Path::new(BIN_PATH);
    if self_exe != dest {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::copy(&self_exe, dest).expect("failed to copy binary");
        set_mode(dest, 0o755);
        actions.push(format!("binary    → {BIN_PATH}"));
    } else {
        actions.push(format!("binary    → {BIN_PATH} (already in place)"));
    }

    // 2. Write example config (don't overwrite existing)
    let config_path = Path::new(CONFIG_PATH);
    if config_path.exists() {
        actions.push(format!("config    → {CONFIG_PATH} (preserved existing)"));
    } else {
        fs::write(config_path, example_config()).expect("failed to write config");
        set_mode(config_path, 0o600);
        actions.push(format!(
            "config    → {CONFIG_PATH} (example, edit before starting)"
        ));
    }

    // 3. Create service
    match init {
        InitSystem::Systemd => {
            fs::write(SYSTEMD_UNIT, systemd_unit()).expect("failed to write systemd unit");
            set_mode(Path::new(SYSTEMD_UNIT), 0o644);
            run_cmd("systemctl", &["daemon-reload"]);
            actions.push(format!("service   → {SYSTEMD_UNIT} (systemd)"));
            actions.push("            systemctl enable gutd".to_string());
            actions.push("            systemctl start gutd".to_string());
        }
        InitSystem::OpenRC => {
            fs::write(OPENRC_INIT, openrc_init_script())
                .expect("failed to write OpenRC init script");
            set_mode(Path::new(OPENRC_INIT), 0o755);
            actions.push(format!("service   → {OPENRC_INIT} (OpenRC)"));
            actions.push("            rc-update add gutd default".to_string());
            actions.push("            rc-service gutd start".to_string());
        }
        InitSystem::Unknown => {
            actions.push("service   → (no systemd/OpenRC detected, skipped)".to_string());
            actions.push(format!(
                "            run manually: {BIN_PATH} -c {CONFIG_PATH}"
            ));
        }
    }

    // Print summary
    let version = env!("GUT_VERSION");
    println!();
    println!("gutd {version} installed successfully");
    println!("─────────────────────────────────────────────");
    println!("init system: {init}");
    println!();
    for a in &actions {
        println!("  {a}");
    }
    println!();
    println!("Next steps:");
    println!("  1. Edit {CONFIG_PATH} — set bind_ip, peer_ip, ports, key/passphrase");
    match init {
        InitSystem::Systemd => {
            println!("  2. systemctl enable --now gutd");
        }
        InitSystem::OpenRC => {
            println!("  2. rc-update add gutd default && rc-service gutd start");
        }
        InitSystem::Unknown => {
            println!("  2. {BIN_PATH} -c {CONFIG_PATH}");
        }
    }
    println!();
    std::process::exit(0);
}

// ──────────────────────────────────────────────────────────────────
//  Uninstall (Linux)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn run_uninstall() -> ! {
    if !is_root() {
        eprintln!("Error: uninstall requires root privileges");
        std::process::exit(1);
    }

    let init = detect_init();
    let mut actions: Vec<String> = Vec::new();

    // 1. Stop and disable service
    match init {
        InitSystem::Systemd => {
            run_cmd_ignore("systemctl", &["stop", "gutd"]);
            run_cmd_ignore("systemctl", &["disable", "gutd"]);
            if remove_file(SYSTEMD_UNIT) {
                run_cmd("systemctl", &["daemon-reload"]);
                actions.push(format!("removed   → {SYSTEMD_UNIT}"));
            }
        }
        InitSystem::OpenRC => {
            run_cmd_ignore("rc-service", &["gutd", "stop"]);
            run_cmd_ignore("rc-update", &["del", "gutd"]);
            if remove_file(OPENRC_INIT) {
                actions.push(format!("removed   → {OPENRC_INIT}"));
            }
        }
        InitSystem::Unknown => {}
    }

    // 2. Remove binary
    if remove_file(BIN_PATH) {
        actions.push(format!("removed   → {BIN_PATH}"));
    }

    // 3. Config is kept intentionally
    if Path::new(CONFIG_PATH).exists() {
        actions.push(format!(
            "preserved → {CONFIG_PATH} (remove manually if desired)"
        ));
    }

    println!();
    println!("gutd uninstalled");
    println!("─────────────────────────────────────────────");
    if actions.is_empty() {
        println!("  (nothing to remove)");
    } else {
        for a in &actions {
            println!("  {a}");
        }
    }
    println!();
    std::process::exit(0);
}

// ──────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────

#[cfg(target_family = "unix")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_family = "windows")]
fn is_root() -> bool {
    // Check for admin rights: try to open the \\.\PhysicalDrive0 (requires admin)
    // Simpler: just try and let sc.exe fail with ACCESS_DENIED if not elevated.
    // We use `net session` as a quick admin check.
    Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_family = "unix")]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).ok();
    }
}

fn remove_file(path: &str) -> bool {
    let p = Path::new(path);
    if !p.exists() {
        return false;
    }
    match fs::remove_file(p) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("Error: failed to remove {path}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_cmd(prog: &str, args: &[&str]) {
    let status = Command::new(prog).args(args).status().unwrap_or_else(|e| {
        eprintln!("Error: failed to run {prog} {args:?}: {e}");
        std::process::exit(1);
    });
    if !status.success() {
        eprintln!(
            "Error: {prog} {args:?} exited with {}",
            status.code().unwrap_or(-1)
        );
        std::process::exit(1);
    }
}

fn run_cmd_ignore(prog: &str, args: &[&str]) {
    Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok();
}

// ──────────────────────────────────────────────────────────────────
//  Install (Windows)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_family = "windows")]
pub fn run_install() -> ! {
    if !is_root() {
        eprintln!("Error: install requires administrator privileges");
        eprintln!("Run this command from an elevated (Administrator) terminal.");
        std::process::exit(1);
    }

    let mut actions: Vec<String> = Vec::new();

    // 1. Copy binary
    let self_exe = std::env::current_exe().expect("cannot determine own path");
    let dest = Path::new(BIN_PATH);
    if self_exe != *dest {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::copy(&self_exe, dest).expect("failed to copy binary");
        actions.push(format!("binary    → {BIN_PATH}"));
    } else {
        actions.push(format!("binary    → {BIN_PATH} (already in place)"));
    }

    // 2. Write example config (don't overwrite existing)
    let config_path = Path::new(CONFIG_PATH);
    if config_path.exists() {
        actions.push(format!("config    → {CONFIG_PATH} (preserved existing)"));
    } else {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(config_path, example_config()).expect("failed to write config");
        actions.push(format!(
            "config    → {CONFIG_PATH} (example, edit before starting)"
        ));
    }

    // 3. Register Windows Service (manual start, stopped)
    //    sc.exe create gutd binPath= "..." start= demand
    let bin_arg = format!("\"{}\" -c \"{}\"", BIN_PATH, CONFIG_PATH);
    let sc_result = Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_arg,
            "start=",
            "demand",
        ])
        .status();

    match sc_result {
        Ok(status) if status.success() => {
            actions.push(format!(
                "service   → {SERVICE_NAME} (Windows Service, manual start)"
            ));
            // Set description
            run_cmd_ignore(
                "sc.exe",
                &[
                    "description",
                    SERVICE_NAME,
                    "GUT IP-over-UDP Obfuscation Tunnel (userspace)",
                ],
            );
        }
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            if code == 1073 {
                // ERROR_SERVICE_EXISTS — update the binPath instead
                let _ = Command::new("sc.exe")
                    .args(["config", SERVICE_NAME, "binPath=", &bin_arg])
                    .status();
                actions.push(format!("service   → {SERVICE_NAME} (updated existing)"));
            } else {
                actions.push(format!("service   → FAILED (sc.exe exit code {code})"));
            }
        }
        Err(e) => {
            actions.push(format!("service   → FAILED ({e})"));
        }
    }

    // Print summary
    let version = env!("GUT_VERSION");
    println!();
    println!("gutd {version} installed successfully");
    println!("─────────────────────────────────────────────");
    for a in &actions {
        println!("  {a}");
    }
    println!();
    println!("Next steps:");
    println!("  1. Edit {CONFIG_PATH}");
    println!("     Set peer_ip, ports, key/passphrase");
    println!("  2. Start the service:");
    println!("     sc.exe start {SERVICE_NAME}");
    println!("     (or: net start {SERVICE_NAME})");
    println!();
    std::process::exit(0);
}

// ──────────────────────────────────────────────────────────────────
//  Uninstall (Windows)
// ──────────────────────────────────────────────────────────────────

#[cfg(target_family = "windows")]
pub fn run_uninstall() -> ! {
    if !is_root() {
        eprintln!("Error: uninstall requires administrator privileges");
        eprintln!("Run this command from an elevated (Administrator) terminal.");
        std::process::exit(1);
    }

    let mut actions: Vec<String> = Vec::new();

    // 1. Stop and delete service
    run_cmd_ignore("sc.exe", &["stop", SERVICE_NAME]);
    let del_result = Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .status();
    match del_result {
        Ok(status) if status.success() => {
            actions.push(format!("removed   → service {SERVICE_NAME}"));
        }
        _ => {
            actions.push(format!(
                "service   → {SERVICE_NAME} (not found or already removed)"
            ));
        }
    }

    // 2. Remove binary
    if remove_file(BIN_PATH) {
        actions.push(format!("removed   → {BIN_PATH}"));
    }

    // 3. Config is kept intentionally
    if Path::new(CONFIG_PATH).exists() {
        actions.push(format!(
            "preserved → {CONFIG_PATH} (remove manually if desired)"
        ));
    }

    println!();
    println!("gutd uninstalled");
    println!("─────────────────────────────────────────────");
    if actions.is_empty() {
        println!("  (nothing to remove)");
    } else {
        for a in &actions {
            println!("  {a}");
        }
    }
    println!();
    std::process::exit(0);
}
