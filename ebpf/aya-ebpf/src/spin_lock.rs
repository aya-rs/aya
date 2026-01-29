pub use aya_common::SpinLock;

use crate::helpers;

/// An RAII implementation of a scope of a spin lock. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
#[must_use = "if unused the spin lock will immediately unlock"]
pub struct SpinLockGuard<'a> {
    spin_lock: &'a mut SpinLock,
}

impl Drop for SpinLockGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            helpers::bpf_spin_unlock(core::ptr::from_mut(self.spin_lock));
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Extension trait for [`SpinLock`] exposing eBPF-only helpers. These helpers
/// are not available in user-space.
pub trait EbpfSpinLock: sealed::Sealed {
    /// Acquires a spin lock and returns a [`SpinLockGuard`]. The lock is
    /// acquired as long as the guard is alive.
    fn lock(&mut self) -> SpinLockGuard<'_>;
}

impl sealed::Sealed for SpinLock {}

impl EbpfSpinLock for SpinLock {
    fn lock(&mut self) -> SpinLockGuard<'_> {
        unsafe {
            helpers::bpf_spin_lock(core::ptr::from_mut(self));
        }
        SpinLockGuard { spin_lock: self }
    }
}
