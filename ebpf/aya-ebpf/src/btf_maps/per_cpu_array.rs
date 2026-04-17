use core::{borrow::Borrow, ptr::NonNull};

use crate::{btf_maps::btf_map_def, insert, lookup};

btf_map_def!(
    /// A BTF-compatible BPF per-CPU array map.
    ///
    /// This map type stores a distinct value of type `T` per CPU, indexed by
    /// `u32` keys. Reads and writes from eBPF programs always reference the
    /// slot belonging to the CPU that executes the program; other CPUs' slots
    /// are accessible only from user space.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.18.
    /// `BPF_MAP_TYPE_PERCPU_ARRAY` itself dates back to 4.6, but BTF-style
    /// map declarations require BTF map-create support in `BPF_MAP_CREATE`,
    /// which landed in 4.18.
    ///
    /// # Flag and size restrictions
    ///
    /// The kernel rejects per-CPU arrays with any of these flags set and
    /// returns `EINVAL` at load time:
    /// - `BPF_F_MMAPABLE` — accepted only on `BPF_MAP_TYPE_ARRAY`.
    /// - `BPF_F_INNER_MAP` — accepted only on `BPF_MAP_TYPE_ARRAY`.
    /// - `BPF_F_NUMA_NODE` — per-CPU maps require `NUMA_NO_NODE`.
    /// - `BPF_F_PRESERVE_ELEMS` — accepted only on
    ///   `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
    ///
    /// Each per-CPU value must also satisfy
    /// `round_up(size_of::<T>(), 8) <= PCPU_MIN_UNIT_SIZE` (32 KiB on most
    /// kernel builds) and `size_of::<T>() <= INT_MAX`. Violations fail with
    /// `E2BIG` at load time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::PerCpuArray, macros::btf_map};
    ///
    /// #[btf_map]
    /// static COUNTERS: PerCpuArray<u64, 8> = PerCpuArray::new();
    /// ```
    pub struct PerCpuArray<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0>,
    map_type: BPF_MAP_TYPE_PERCPU_ARRAY,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: u32,
    value_type: T,
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize> PerCpuArray<T, MAX_ENTRIES, FLAGS> {
    // Enforces kernel constraints from kernel/bpf/arraymap.c and the
    // per-CPU allocator alignment invariant. `const _: ()` is forbidden in
    // a generic impl, and a named associated const is lazy without a
    // reference, hence `let () = Self::_CHECK` in every method.
    const _CHECK: () = {
        assert!(
            size_of::<T>() >= 1,
            "per-CPU array value must be non-zero sized.",
        );
        assert!(
            MAX_ENTRIES > 0,
            "per-CPU array max_entries must be greater than zero.",
        );
        // The kernel per-CPU allocator aligns slots to 8 bytes
        // (bpf_array_alloc_percpu -> bpf_map_alloc_percpu(..., 8, ...)).
        // Values with stricter alignment would be under-aligned for `&T`
        // returned by `get`.
        assert!(
            align_of::<T>() <= 8,
            "per-CPU array value alignment must be at most 8 bytes.",
        );
    };

    /// Returns a reference to the current CPU's slot at `index`, or `None`
    /// if `index` is out of bounds.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        let () = Self::_CHECK;
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    /// Returns a const pointer to the current CPU's slot at `index`.
    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Option<*const T> {
        let () = Self::_CHECK;
        unsafe { self.lookup(index).map(|p| p.as_ptr().cast_const()) }
    }

    /// Returns a mutable pointer to the current CPU's slot at `index`.
    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        let () = Self::_CHECK;
        unsafe { self.lookup(index).map(NonNull::as_ptr) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.as_ptr(), &index)
    }

    /// Overwrites the current CPU's slot at `index`.
    ///
    /// `flags` is forwarded to `bpf_map_update_elem`; `BPF_NOEXIST` is
    /// rejected by the kernel for arrays.
    #[inline(always)]
    pub fn set(&self, index: u32, value: impl Borrow<T>, flags: u64) -> Result<(), i32> {
        let () = Self::_CHECK;
        insert(self.as_ptr(), &index, value.borrow(), flags)
    }
}
