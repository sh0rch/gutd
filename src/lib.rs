pub mod config;
pub mod crypto;
pub mod installer;
pub mod metrics;
pub mod proto;
pub mod reload;
#[cfg(target_os = "linux")]
pub mod tc;
pub mod tun;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
