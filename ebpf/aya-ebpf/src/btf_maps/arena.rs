use crate::{
    arena::ArenaPtr,
    bindings::{BPF_F_MMAPABLE, bpf_map_type::BPF_MAP_TYPE_ARENA},
};

/// A BPF arena map (`BPF_MAP_TYPE_ARENA`): a `PAGES`-page region of memory
/// shared between the BPF program and userspace.
///
/// Userspace accesses the region by `mmap`ing the map fd (aya's loader does
/// this automatically) and can allocate pages simply by touching them; the
/// BPF side accesses it through [`ArenaPtr`]s anchored via
/// [`Arena::ptr_from_user_va`].
///
/// A program may use at most one arena map.
///
/// # Map flags
///
/// The default value of `FLAGS` sets the required [`BPF_F_MMAPABLE`] bit.
/// Callers that override `FLAGS` must keep `BPF_F_MMAPABLE` set or the map
/// will fail to load with `EINVAL`.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.9.
///
/// # Example
///
/// ```rust,ignore
/// use aya_ebpf::{btf_maps::Arena, macros::btf_map};
///
/// #[btf_map]
/// static ARENA: Arena<16> = Arena::new();
/// ```
// repr(C) is required to ensure fields maintain their declared order in BTF.
// Unlike other map definitions, an arena has no `key`/`value` fields: the
// kernel requires key_size == value_size == 0, which loaders infer from the
// members' absence. `map_flags` must include BPF_F_MMAPABLE.
#[repr(C)]
pub struct Arena<const PAGES: usize, const FLAGS: usize = { BPF_F_MMAPABLE as usize }> {
    r#type: *const [i32; BPF_MAP_TYPE_ARENA as usize],
    max_entries: *const [i32; PAGES],
    map_flags: *const [i32; FLAGS],
}

// SAFETY: The struct fields are placeholder raw pointers that the BTF loader
// patches at load time; they are never dereferenced from Rust code, so the
// wrapper has no aliasable state.
unsafe impl<const PAGES: usize, const FLAGS: usize> Sync for Arena<PAGES, FLAGS> {}

impl<const PAGES: usize, const FLAGS: usize> Default for Arena<PAGES, FLAGS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PAGES: usize, const FLAGS: usize> Arena<PAGES, FLAGS> {
    /// Returns a placeholder definition that the BPF loader patches at load time.
    pub const fn new() -> Self {
        Self {
            r#type: ::core::ptr::null(),
            max_entries: ::core::ptr::null(),
            map_flags: ::core::ptr::null(),
        }
    }

    #[inline(always)]
    const fn as_ptr(&self) -> *mut ::core::ffi::c_void {
        ::core::ptr::from_ref(self).cast_mut().cast()
    }

    /// Returns an [`ArenaPtr`] for a user-space virtual address within this
    /// arena's mapping.
    ///
    /// The kernel places the arena's user mapping at an arbitrary (not
    /// 4GiB-aligned) base address, so BPF programs cannot address the arena
    /// by plain offsets: every pointer chain must be anchored at an address
    /// obtained from userspace (e.g. the arena base or a root object
    /// address, communicated through a regular map) or, on newer kernels,
    /// from the arena page allocation kfuncs.
    ///
    /// Prefer this method over [`ArenaPtr::from_user_va`] for the anchor
    /// pointer: it additionally references the arena map so that the
    /// verifier finds the arena in the program's `used_maps` (required for
    /// every `addr_space_cast` to be accepted). Pointers *derived* from an
    /// anchored one (e.g. loaded from arena memory) can use
    /// [`ArenaPtr::from_user_va`] directly.
    #[cfg_attr(
        not(target_arch = "bpf"),
        expect(
            clippy::missing_const_for_fn,
            reason = "contains inline assembly on the bpf target"
        )
    )]
    #[inline(always)]
    pub fn ptr_from_user_va<T>(&self, user_va: u64) -> ArenaPtr<T> {
        // The verifier resolves which arena backs an addr_space_cast by
        // looking at the program's used maps, so the map must be referenced
        // by at least one surviving instruction. Feeding the map's address
        // into an empty asm block forces the LD_IMM64 (relocated to the map
        // fd at load time) to survive optimization.
        #[cfg(target_arch = "bpf")]
        unsafe {
            core::arch::asm!("/* {map} */", map = in(reg) self.as_ptr(), options(nostack));
        }
        #[cfg(not(target_arch = "bpf"))]
        let _: *mut ::core::ffi::c_void = self.as_ptr();
        ArenaPtr::from_user_va(user_va)
    }
}
