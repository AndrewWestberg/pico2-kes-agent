//! Locked transient secret memory. Callers must keep secret data in these buffers,
//! including during error and disconnect handling; dropping or clearing wipes them.

use rustix::mm::{MapFlags, ProtFlags, mlock, mmap_anonymous, munlock, munmap};
use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
use std::io;
use std::ptr::NonNull;
use zeroize::Zeroize;
/// Disables process dumps before USB can return an operational key. Long-lived
/// key material uses `SecretBuffer`; failure is fatal and has no pageable
/// fallback.
pub fn protect_process() -> io::Result<()> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

/// A unique anonymous mapping, locked before any secret can be written.
/// It deliberately implements neither formatting, cloning nor serialization.
///
/// ```compile_fail
/// use pico2_kes_agent::memory::SecretBuffer;
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<SecretBuffer>();
/// ```
/// ```compile_fail
/// use pico2_kes_agent::memory::SecretBuffer;
/// fn requires_display<T: std::fmt::Display>() {}
/// requires_display::<SecretBuffer>();
/// ```
/// ```compile_fail
/// use pico2_kes_agent::memory::SecretBuffer;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<SecretBuffer>();
/// ```
/// ```compile_fail
/// use pico2_kes_agent::memory::SecretBuffer;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<SecretBuffer>();
/// ```
pub struct SecretBuffer {
    ptr: NonNull<u8>,
    len: usize,
}
// SAFETY: the mapping is uniquely owned, has process-wide lifetime independent
// of a thread, and mutation requires `&mut SecretBuffer`.
unsafe impl Send for SecretBuffer {}
// SAFETY: shared access exposes only immutable bytes; unmapping requires unique
// ownership during `Drop`.
unsafe impl Sync for SecretBuffer {}

impl SecretBuffer {
    /// Disable process dumps and establish a nonempty locked mapping. Failure is
    /// fatal to readiness; no unlocked buffer is returned. This is also the
    /// real initializer used by isolated RLIMIT_MEMLOCK qualification children.
    pub fn new(len: usize) -> io::Result<Self> {
        if len == 0 || len > isize::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid secret buffer length",
            ));
        }
        set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )?;
        // SAFETY: anonymous mapping has no backing fd; the returned range is owned here.
        let ptr = unsafe {
            mmap_anonymous(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )?
        };
        // SAFETY: ptr denotes the entire newly allocated readable mapping.
        if let Err(error) = unsafe { mlock(ptr, len) } {
            // SAFETY: the mapping is owned here and no references exist.
            let _ = unsafe { munmap(ptr, len) };
            return Err(error.into());
        }
        // Linux cannot return a null mapping without MAP_FIXED at address zero.
        let Some(ptr) = NonNull::new(ptr.cast::<u8>()) else {
            // SAFETY: this is the mapping just returned by mmap.
            let _ = unsafe { munlock(ptr, len) };
            // SAFETY: no references exist to this mapping.
            let _ = unsafe { munmap(ptr, len) };
            return Err(io::Error::other("null secret mapping"));
        };
        Ok(Self { ptr, len })
    }
    pub fn copy_from_slice(bytes: &[u8]) -> io::Result<Self> {
        let mut secret = Self::new(bytes.len())?;
        secret.as_mut_slice().copy_from_slice(bytes);
        Ok(secret)
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: mapping stays allocated and locked for the lifetime of self.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the mapping is uniquely owned and &mut self prevents aliasing.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Explicitly wipe on completion, failure, or disconnect before reuse.
    pub fn clear(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        DROP_WIPED.with(|observed| observed.set(self.as_slice().iter().all(|&byte| byte == 0)));
        // SAFETY: the mapping is still owned, and no references survive drop.
        unsafe {
            let _ = munlock(self.ptr.as_ptr().cast(), self.len);
            let _ = munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(test)]
thread_local! {
    static DROP_WIPED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{getrlimit, setrlimit};
    use std::process::Command;

    #[test]
    fn wipe_is_observable_before_unmapping() {
        let mut secret = SecretBuffer::new(32).unwrap();
        secret.as_mut_slice().fill(0xa5);
        secret.clear();
        assert!(secret.as_slice().iter().all(|&byte| byte == 0));
        secret.as_mut_slice().fill(0x5a);
        DROP_WIPED.with(|observed| observed.set(false));
        drop(secret);
        DROP_WIPED.with(|observed| assert!(observed.get()));
    }

    #[test]
    fn lock_denial_in_isolated_child() {
        const CHILD: &str = "KES_MEMLOCK_DENIAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let limit = getrlimit(Resource::Memlock);
            setrlimit(
                Resource::Memlock,
                Rlimit {
                    current: Some(0),
                    maximum: limit.maximum,
                },
            )
            .unwrap();
            assert!(
                SecretBuffer::new(32).is_err(),
                "memory lock denial was not enforced"
            );
            return;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "memory::tests::lock_denial_in_isolated_child"])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
