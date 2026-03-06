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
        // SAFETY: Call to an eBPF helper. `self.spin_lock` is always
        // initialized.
        unsafe {
            helpers::bpf_spin_unlock(core::ptr::from_mut(self.spin_lock));
        }
    }
}

mod sealed {
    use super::{SpinLock, SpinLockGuard, helpers};

    pub trait EbpfSpinLock {
        fn lock(&mut self) -> SpinLockGuard<'_>;
    }

    impl EbpfSpinLock for SpinLock {
        fn lock(&mut self) -> SpinLockGuard<'_> {
            // SAFETY: Call to an eBPF helper. `self` is always initialized.
            unsafe {
                helpers::bpf_spin_lock(core::ptr::from_mut(self));
            }
            SpinLockGuard { spin_lock: self }
        }
    }
}

/// Extension trait for [`SpinLock`] exposing eBPF-only helpers. These helpers
/// are not available in user-space.
pub trait EbpfSpinLockExt: sealed::EbpfSpinLock {
    fn lock(&mut self) -> SpinLockGuard<'_>;
}

impl<T> EbpfSpinLockExt for T
where
    T: sealed::EbpfSpinLock,
{
    /// Acquires a spin lock and returns a [`SpinLockGuard`]. The lock is
    /// acquired as long as the guard is alive.
    #[inline]
    fn lock(&mut self) -> SpinLockGuard<'_> {
        sealed::EbpfSpinLock::lock(self)
    }
}
