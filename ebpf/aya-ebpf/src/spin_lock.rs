pub use aya_common::spin_lock::SpinLock;

use core::mem::size_of;

use crate::{bindings::bpf_spin_lock, helpers};

const _: [(); size_of::<SpinLock>()] = [(); size_of::<bpf_spin_lock>()];

/// An RAII implementation of a scope of a spin lock. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
pub struct SpinLockGuard<'a> {
    spin_lock: &'a SpinLock,
}

impl Drop for SpinLockGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            helpers::bpf_spin_unlock(core::ptr::from_ref(self.spin_lock).cast_mut().cast());
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
            helpers::bpf_spin_lock(core::ptr::from_ref(self).cast_mut().cast());
        }
        SpinLockGuard { spin_lock: self }
    }
}
