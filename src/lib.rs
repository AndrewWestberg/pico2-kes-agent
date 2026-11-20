//! Host-side security and durable publication primitives.

pub mod build_info;

#[cfg(target_os = "linux")]
pub mod backup;
#[cfg(target_os = "linux")]
pub mod cli;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod files;
#[cfg(target_os = "linux")]
pub mod flash;
#[cfg(target_os = "linux")]
pub mod memory;
#[cfg(target_os = "linux")]
pub mod release;
#[cfg(target_os = "linux")]
pub mod updater;
