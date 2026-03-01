//! TC/XDP eBPF fast path for GUT v1 protocol
//!
//! Architecture:
//! - Egress TC on veth: inner IP → masked UDP to peer
//! - Ingress XDP on NIC: masked UDP → devmap redirect → veth → protocol stack
//! - All packet processing happens in kernel (no userspace data path)

pub mod loader;
pub mod maps;

pub use loader::drop_policy_safety_overrides;
pub use loader::TcBpfManager;
pub use maps::GutConfig;
