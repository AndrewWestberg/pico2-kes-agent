//! Host-side security and durable publication primitives.

#[cfg(target_os = "linux")]
pub mod cli;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod files;
#[cfg(target_os = "linux")]
pub mod memory;
