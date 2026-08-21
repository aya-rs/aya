//! Types for working with BPF arena memory (`BPF_MAP_TYPE_ARENA`).
//!
//! A BPF arena is a sparse region of memory shared between a BPF program and
//! userspace. Userspace accesses it through `mmap(2)` on the map fd; the BPF
//! side accesses it through pointers that the verifier tracks as
//! `PTR_TO_ARENA`. The verifier only accepts a dereference if the pointer's
//! dataflow goes through a BPF `addr_space_cast` instruction (or an arena
//! kfunc return); the JIT then sandboxes every access to the arena region
//! and faults are handled gracefully (loads read 0, stores are skipped).
//!
//! [`ArenaPtr`] encapsulates that contract: it stores an arena address in
//! user-space form (valid on both sides, since only the low 32 bits address
//! the arena) and re-emits the cast on every dereference, mirroring what
//! clang does for C's `__arena` address-space-qualified pointers.

use core::marker::PhantomData;

/// Emits a BPF `addr_space_cast` from address space 1 (arena/user view) to 0
/// (kernel view). The verifier marks the result `PTR_TO_ARENA`, making
/// dereferences through it legal, runtime-sandboxed arena accesses.
///
/// The cast must remain on the dataflow path between the address and the
/// dereference; inline assembly guarantees that, since LLVM cannot prove the
/// output equals the input and thus can never substitute the uncast value.
#[inline(always)]
pub(crate) fn cast_kern(addr: u64) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        let out: u64;
        unsafe {
            core::arch::asm!(
                "{dst} = addr_space_cast({src}, 0, 1)",
                src = in(reg) addr,
                dst = out(reg) out,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    // We only need this for doc tests which are compiled for the host target
    #[expect(clippy::unreachable, reason = "only used for doc tests")]
    #[cfg(not(target_arch = "bpf"))]
    {
        unreachable!("addr_space_cast is only available on the bpf target: addr={addr}");
    }
}

/// Emits a BPF `addr_space_cast` from address space 0 (kernel view) to 1
/// (arena/user view). The JIT rewrites this to fold in the arena's user-space
/// base address, producing a pointer that userspace can dereference through
/// its mapping of the arena.
#[expect(
    dead_code,
    reason = "needed once BPF-side page allocation (bpf_arena_alloc_pages) lands"
)]
#[inline(always)]
pub(crate) fn cast_user(addr: u64) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        let out: u64;
        unsafe {
            core::arch::asm!(
                "{dst} = addr_space_cast({src}, 1, 0)",
                src = in(reg) addr,
                dst = out(reg) out,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    // We only need this for doc tests which are compiled for the host target
    #[expect(clippy::unreachable, reason = "only used for doc tests")]
    #[cfg(not(target_arch = "bpf"))]
    {
        unreachable!("addr_space_cast is only available on the bpf target: addr={addr}");
    }
}

/// A pointer into BPF arena memory.
///
/// The address is stored in user-space form so that pointer-carrying data
/// structures in the arena are traversable from userspace as well; every
/// dereference on the BPF side re-establishes verifier provenance via
/// `cast_kern`. Because of that, `ArenaPtr` fields can be freely embedded
/// in `#[repr(C)]` structs living in arena memory and loaded back — the Rust
/// analog of C's `struct foo __arena *`.
///
/// # Example
///
/// ```ignore
/// #[repr(C)]
/// struct Node {
///     value: u64,
///     next: ArenaPtr<Node>,
/// }
/// ```
#[repr(transparent)]
pub struct ArenaPtr<T> {
    addr: u64,
    _ty: PhantomData<*mut T>,
}

// Manual impls: derives would bound on `T: Copy`/`T: Clone`, but the pointer
// is copyable regardless of the pointee.
impl<T> Copy for ArenaPtr<T> {}

impl<T> Clone for ArenaPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> ArenaPtr<T> {
    /// The null arena pointer.
    pub const fn null() -> Self {
        Self::from_user_va(0)
    }

    /// Creates an arena pointer from a user-space virtual address (or a raw
    /// arena offset — only the low 32 bits address the arena).
    pub const fn from_user_va(addr: u64) -> Self {
        Self {
            addr,
            _ty: PhantomData,
        }
    }

    /// Returns the user-space form of this pointer.
    pub const fn as_user_va(self) -> u64 {
        self.addr
    }

    /// Returns whether this pointer is null.
    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// Converts to a raw pointer with verifier arena provenance
    /// (`PTR_TO_ARENA`) established via `addr_space_cast`.
    ///
    /// Accesses through the result are runtime-sandboxed by the kernel to the
    /// arena region: out-of-bounds or unmapped accesses read 0 / are skipped
    /// rather than faulting.
    ///
    /// Verifier provenance is attached to the pointer's dataflow, not its
    /// numeric address. Converting the result to plain data and later
    /// reconstructing a pointer from it may lose `PTR_TO_ARENA` provenance.
    #[inline(always)]
    pub fn as_ptr(self) -> *mut T {
        cast_kern(self.addr) as *mut T
    }

    /// Reads the pointee.
    ///
    /// Signed narrow integer reads may produce sign-extending BPF loads, which
    /// are not supported for arena memory by some kernels.
    ///
    /// # Safety
    ///
    /// The address must be properly aligned for `T` and valid for reading
    /// `size_of::<T>()` bytes. Those bytes must represent a valid `T`, and the
    /// read must not race with a conflicting non-atomic access from userspace
    /// or another BPF program invocation.
    #[inline(always)]
    pub unsafe fn read(self) -> T
    where
        T: Copy,
    {
        unsafe { self.as_ptr().read() }
    }

    /// Writes the pointee. Writes to unmapped arena pages are skipped.
    ///
    /// # Safety
    ///
    /// The address must be properly aligned for `T` and valid for writing
    /// `size_of::<T>()` bytes. The write must not race with a conflicting
    /// non-atomic access from userspace or another BPF program invocation.
    #[inline(always)]
    pub unsafe fn write(self, value: T)
    where
        T: Copy,
    {
        unsafe { self.as_ptr().write(value) }
    }
}
