#![expect(
    deprecated,
    reason = "this module implements the deprecated cgroup storage map types"
)]

use crate::{
    bindings::bpf_cgroup_storage_key, btf_maps::btf_map_def, helpers::bpf_get_local_storage,
};

macro_rules! define_cgroup_storage {
    ($(#[$doc:meta])* $name:ident, $map_type:ident $(,)?) => {
        btf_map_def!(
            $(#[$doc])*
            #[deprecated = "use the `BPF_MAP_TYPE_CGRP_STORAGE` map type, available since Linux 6.2"]
            pub struct $name<V>,
            map_type: $map_type,
            max_entries: 0,
            map_flags: 0,
            key_type: bpf_cgroup_storage_key,
            value_type: V,
        );

        impl<V> $name<V> {
            /// Returns a mutable pointer to the storage of the cgroup the program
            /// is running in.
            ///
            /// Wraps the `bpf_get_local_storage` helper, which the kernel keys
            /// implicitly by the current cgroup; there is no lookup that can fail,
            /// so the returned pointer is always valid for the duration of the
            /// program.
            #[inline(always)]
            pub fn get_ptr_mut(&self) -> *mut V {
                // SAFETY: `self` is a valid pointer managed by aya, and the
                // `flags` argument is reserved and must be zero.
                unsafe { bpf_get_local_storage(self.as_ptr().cast(), 0) }.cast()
            }
        }
    };
}

define_cgroup_storage!(
    /// A BTF-compatible cgroup local storage map.
    ///
    /// Stores a value owned by the cgroup the program is attached to. The kernel
    /// allocates one entry per cgroup on attach; eBPF programs read and write it
    /// with [`get_ptr_mut`], and user space accesses it by
    /// `bpf_cgroup_storage_key`.
    ///
    /// The kernel keeps one value per cgroup with no implicit synchronization, so
    /// programs on different CPUs share it; read-modify-write updates can lose
    /// writes under load. Use [`PerCpuCgroupStorage`] for lock-free per-CPU
    /// accumulation, or guard the value with a `bpf_spin_lock`.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.19.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![expect(deprecated, reason = "documenting the deprecated cgroup storage map type")]
    /// use aya_ebpf::{btf_maps::CgroupStorage, macros::btf_map, programs::SkBuffContext};
    ///
    /// #[btf_map]
    /// static STORAGE: CgroupStorage<u64> = CgroupStorage::new();
    ///
    /// # unsafe fn try_test(_ctx: SkBuffContext) -> Result<(), i64> {
    /// let counter = STORAGE.get_ptr_mut();
    /// unsafe { *counter += 1 };
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`get_ptr_mut`]: CgroupStorage::get_ptr_mut
    CgroupStorage,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
);

define_cgroup_storage!(
    /// A BTF-compatible per-CPU cgroup local storage map.
    ///
    /// Like [`CgroupStorage`] but each CPU holds its own copy of the value, which
    /// lets programs accumulate without locking. [`get_ptr_mut`] returns the
    /// running CPU's copy; user space reads back one value per CPU.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.20.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #![expect(deprecated, reason = "documenting the deprecated cgroup storage map type")]
    /// use aya_ebpf::{btf_maps::PerCpuCgroupStorage, macros::btf_map, programs::SkBuffContext};
    ///
    /// #[btf_map]
    /// static STORAGE: PerCpuCgroupStorage<u64> = PerCpuCgroupStorage::new();
    ///
    /// # unsafe fn try_test(_ctx: SkBuffContext) -> Result<(), i64> {
    /// let counter = STORAGE.get_ptr_mut();
    /// unsafe { *counter += 1 };
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`get_ptr_mut`]: PerCpuCgroupStorage::get_ptr_mut
    PerCpuCgroupStorage,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
);
