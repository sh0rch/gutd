//! Install / uninstall subcommands.
//!
//! `gutd install`   — copy binary, write example config, create systemd/OpenRC service
//! `gutd uninstall` — stop service, remove binary and unit file (config preserved)

use std::fs;
use std::path::Path;
use std::process::Command;

const BIN_PATH: &str = "/usr/local/bin/gutd";
const CONFIG_PATH: &str = "/etc/gutd.conf";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/gutd.service";
const OPENRC_INIT: &str = "/etc/init.d/gutd";

// ──────────────────────────────────────────────────────────────────
//  Init system detection
// ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitSystem {
    Systemd,
    OpenRC,
    Unknown,
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Systemd => write!(f, "systemd"),
            Self::OpenRC => write!(f, "OpenRC"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

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
//  Service templates
// ──────────────────────────────────────────────────────────────────

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

fn example_config() -> &'static str {
    r#"# /etc/gutd.conf — GUT v1 TC/XDP tunnel configuration
#
# Generate key:    gutd genkey
# From passphrase: gutd genkey --passphrase "my secret"

[global]
outer_mtu = 1500
# stats_interval = 5        # stats dump interval, seconds (0 = off)
# stat_file = /run/gutd.stat

[peer]
name = gut0                 # veth pair name (gut0 ↔ gut0_xdp)
mtu = 1492
# nic = eth0                # physical NIC for XDP (auto-detected if omitted)
address = 10.0.0.1/30       # IP address on veth (CIDR, /30 for p2p)

bind_ip = 0.0.0.0
peer_ip = 203.0.113.10
ports = 41000
keepalive_drop_percent = 75

# Key — choose ONE:
# passphrase = change-me-to-a-strong-passphrase
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
"#
}

// ──────────────────────────────────────────────────────────────────
//  Install
// ──────────────────────────────────────────────────────────────────

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
    let version = env!("CARGO_PKG_VERSION");
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
//  Uninstall
// ──────────────────────────────────────────────────────────────────

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

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

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
