//! A BPF arena map: memory shared between userspace and BPF programs.

use std::borrow::Borrow;
#[cfg(target_has_atomic = "32")]
use std::sync::atomic::AtomicU32;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;

use crate::{
    Pod,
    maps::{MapData, MapError},
};

/// A BPF arena map (`BPF_MAP_TYPE_ARENA`): a region of memory shared between
/// userspace and BPF programs.
///
/// The arena region is `mmap`ed automatically when the map is created. A
/// reused arena is mapped when its definition specifies a fixed userspace
/// address through `map_extra`; otherwise its userspace address cannot be
/// recovered and conversion to this type returns
/// [`MapError::ArenaNotMmapped`].
/// With the default map flags, userspace allocates pages on first touch through
/// this mapping. BPF programs allocate pages with the arena allocation kfunc;
/// a BPF load from an unallocated page returns zero and a store is skipped.
///
/// Values read from or written to the arena are shared memory concurrently
/// accessible by BPF programs — reads may observe concurrent updates, and no
/// synchronization is performed. Pointers stored in the arena by userspace
/// must be in user-space virtual address form (addresses between
/// [`Self::user_base`] and `user_base + len`), which is what the BPF-side
/// `ArenaPtr` expects.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 6.9.
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::Arena;
///
/// let arena = Arena::try_from(bpf.map_mut("ARENA").unwrap())?;
/// // SAFETY: no BPF program or other thread accesses this location while the
/// // value is written or read.
/// unsafe {
///     arena.write_at::<u64>(0, 42)?;
///     let value = arena.read_at::<u64>(0)?;
///     assert_eq!(value, 42);
/// }
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_ARENA")]
#[derive(Debug)]
pub struct Arena<T> {
    inner: T,
}

impl<T: Borrow<MapData>> Arena<T> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        map.borrow().arena_mmap().ok_or(MapError::ArenaNotMmapped)?;
        Ok(Self { inner: map })
    }

    /// Returns the size of the arena in bytes.
    pub fn len(&self) -> usize {
        // Unwrap: checked in `new`.
        self.inner.borrow().arena_mmap().unwrap().len()
    }

    /// Returns whether the arena is empty (it never is).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the user-space virtual address of the start of the arena.
    ///
    /// Add an offset to this to build pointer values that BPF-side
    /// `ArenaPtr`s and userspace can both dereference.
    pub fn user_base(&self) -> u64 {
        self.as_ptr() as u64
    }

    /// Returns a raw pointer to the start of the arena's userspace mapping.
    ///
    /// Creating or inspecting the pointer is safe. Dereferencing it requires
    /// the caller to uphold the synchronization and validity requirements of
    /// the operation being performed.
    pub fn as_ptr(&self) -> *mut u8 {
        // Unwrap: checked in `new`.
        self.inner
            .borrow()
            .arena_mmap()
            .unwrap()
            .ptr()
            .as_ptr()
            .cast()
    }

    /// Reads a value at the given byte offset within the arena.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the bytes are not concurrently written for
    /// the duration of the read and that any synchronization required to make
    /// prior writes visible has occurred. In particular, eBPF programs and
    /// other processes can access the arena independently of Rust borrowing.
    pub unsafe fn read_at<V: Pod>(&self, offset: usize) -> Result<V, MapError> {
        let ptr = self.checked_ptr::<V>(offset)?;
        Ok(unsafe { ptr.read_unaligned() })
    }

    /// Writes a value at the given byte offset within the arena.
    ///
    /// With the default map flags, writing allocates arena pages on first touch.
    /// An arena created with `BPF_F_SEGV_ON_FAULT` instead faults when the page
    /// has not already been allocated by BPF.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no conflicting access occurs for the
    /// duration of the write and must provide any synchronization needed to
    /// publish the completed value to eBPF or other processes.
    pub unsafe fn write_at<V: Pod>(&self, offset: usize, value: V) -> Result<(), MapError> {
        let ptr = self.checked_ptr::<V>(offset)?;
        unsafe {
            ptr.write_unaligned(value);
        }
        Ok(())
    }

    /// Returns an atomic 32-bit integer at the given byte offset.
    ///
    /// # Safety
    ///
    /// For the returned reference's lifetime, every concurrent access to this
    /// location must be atomic and use the same access width. The underlying
    /// arena page must not be freed during an access.
    #[cfg(target_has_atomic = "32")]
    pub unsafe fn atomic_u32_at(&self, offset: usize) -> Result<&AtomicU32, MapError> {
        let ptr = self.checked_ptr::<u32>(offset)?;
        let alignment = align_of::<AtomicU32>();
        if !ptr.addr().is_multiple_of(alignment) {
            return Err(MapError::UnalignedArenaAccess { offset, alignment });
        }

        Ok(unsafe { AtomicU32::from_ptr(ptr) })
    }

    /// Returns an atomic 64-bit integer at the given byte offset.
    ///
    /// # Safety
    ///
    /// For the returned reference's lifetime, every concurrent access to this
    /// location must be atomic and use the same access width. The underlying
    /// arena page must not be freed during an access.
    #[cfg(target_has_atomic = "64")]
    pub unsafe fn atomic_u64_at(&self, offset: usize) -> Result<&AtomicU64, MapError> {
        let ptr = self.checked_ptr::<u64>(offset)?;
        let alignment = align_of::<AtomicU64>();
        if !ptr.addr().is_multiple_of(alignment) {
            return Err(MapError::UnalignedArenaAccess { offset, alignment });
        }

        Ok(unsafe { AtomicU64::from_ptr(ptr) })
    }

    fn checked_ptr<V>(&self, offset: usize) -> Result<*mut V, MapError> {
        let size = size_of::<V>();
        let arena_size = self.len();
        let end = offset.checked_add(size).ok_or(MapError::ArenaOutOfBounds {
            offset,
            size,
            arena_size,
        })?;
        if end > arena_size {
            return Err(MapError::ArenaOutOfBounds {
                offset,
                size,
                arena_size,
            });
        }

        Ok(unsafe { self.as_ptr().add(offset).cast() })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use assert_matches::assert_matches;
    use aya_obj::generated::{BPF_F_MMAPABLE, bpf_cmd, bpf_map_type};

    use super::*;
    use crate::{
        sys::{Syscall, TEST_MMAP_RET, override_syscall},
        util::page_size,
    };

    fn test_arena(backing: &mut [u64]) -> Arena<MapData> {
        assert_eq!(size_of_val(backing), page_size());
        override_syscall(|call| match call {
            Syscall::Ebpf {
                cmd: bpf_cmd::BPF_MAP_CREATE,
                ..
            } => Ok(crate::MockableFd::mock_signed_fd().into()),
            call => panic!("unexpected syscall {call:?}"),
        });
        TEST_MMAP_RET.with(|ret| *ret.borrow_mut() = backing.as_mut_ptr().cast());

        let obj = aya_obj::Map::new_from_params(
            bpf_map_type::BPF_MAP_TYPE_ARENA as u32,
            0,
            0,
            1,
            BPF_F_MMAPABLE,
        );
        Arena::new(MapData::create(obj, "arena", None).unwrap()).unwrap()
    }

    #[test]
    fn read_write_unaligned_value() {
        let mut backing = vec![0; page_size() / size_of::<u64>()];
        let arena = test_arena(&mut backing);
        let value = 0x0102_0304_0506_0708u64;

        unsafe {
            arena.write_at(1, value).unwrap();
        }
        assert_eq!(unsafe { arena.read_at::<u64>(1).unwrap() }, value);
    }

    #[test]
    fn read_write_check_bounds_and_overflow() {
        let mut backing = vec![0; page_size() / size_of::<u64>()];
        let arena = test_arena(&mut backing);

        assert_matches!(
            unsafe { arena.read_at::<u64>(page_size() - size_of::<u64>() + 1) },
            Err(MapError::ArenaOutOfBounds { .. })
        );
        assert_matches!(
            unsafe { arena.write_at::<u64>(usize::MAX, 0) },
            Err(MapError::ArenaOutOfBounds { .. })
        );
    }

    #[test]
    #[cfg(target_has_atomic = "32")]
    fn atomic_u32_access() {
        let mut backing = vec![0; page_size() / size_of::<u64>()];
        let arena = test_arena(&mut backing);
        let value = unsafe { arena.atomic_u32_at(0).unwrap() };

        value.store(7, Ordering::Release);
        assert_eq!(value.fetch_add(5, Ordering::Relaxed), 7);
        assert_eq!(value.load(Ordering::Acquire), 12);
    }

    #[test]
    #[cfg(target_has_atomic = "64")]
    fn atomic_u64_access() {
        let mut backing = vec![0; page_size() / size_of::<u64>()];
        let arena = test_arena(&mut backing);
        let value = unsafe { arena.atomic_u64_at(0).unwrap() };

        value.store(7, Ordering::Release);
        assert_eq!(value.fetch_add(5, Ordering::Relaxed), 7);
        assert_eq!(value.load(Ordering::Acquire), 12);
    }

    #[test]
    #[cfg(all(target_has_atomic = "32", target_has_atomic = "64"))]
    fn atomic_access_checks_bounds_and_alignment() {
        let mut backing = vec![0; page_size() / size_of::<u64>()];
        let arena = test_arena(&mut backing);

        assert_matches!(
            unsafe { arena.atomic_u32_at(1) },
            Err(MapError::UnalignedArenaAccess { offset: 1, .. })
        );
        assert_matches!(
            unsafe { arena.atomic_u64_at(page_size() - size_of::<u64>() + 1) },
            Err(MapError::ArenaOutOfBounds { .. })
        );
    }
}
