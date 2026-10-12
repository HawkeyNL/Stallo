//! Stallo: an agent-first VM manager for Ubuntu on QEMU/KVM.
//!
//! `stallod` (the daemon) owns every VM; `stallo` (the CLI) talks to it over
//! a Unix socket.

pub mod config;
pub mod paths;
