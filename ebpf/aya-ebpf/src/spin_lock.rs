pub use aya_common::spin_lock::SpinLock;

use crate::{bindings, helpers};

/// An RAII implementation of a scope of a spin lock. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
pub struct SpinLockGuard<'a> {
    spin_lock: &'a SpinLock,
}

impl Drop for SpinLockGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            helpers::bpf_spin_unlock(self.spin_lock.as_ptr().cast::<bindings::bpf_spin_lock>());
        }
    }
}

/// Extension trait allowing to acquire a [`SpinLock`] in an eBPF program.
pub trait EbpfSpinLock {
    /// Acquires a spin lock and returns a [`SpinLockGuard`]. The lock is
    /// acquired as long as the guard is alive.
    fn lock(&self) -> SpinLockGuard<'_>;
}

impl EbpfSpinLock for SpinLock {
    fn lock(&self) -> SpinLockGuard<'_> {
        unsafe {
            helpers::bpf_spin_lock(self.as_ptr().cast::<bindings::bpf_spin_lock>());
        }
        SpinLockGuard { spin_lock: self }
    }
}
