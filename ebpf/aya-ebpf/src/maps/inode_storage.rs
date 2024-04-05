use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_ebpf_bindings::{
    bindings::{
        bpf_map_def, bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE, BPF_LOCAL_STORAGE_GET_F_CREATE,
    },
    helpers::{bpf_inode_storage_delete, bpf_inode_storage_get},
};
use aya_ebpf_cty::{c_int, c_void};

use crate::maps::PinningType;

/// A BPF map of type BPF_MAP_TYPE_INODE_STORAGE, used for attaching local storage data to an inode.
/// See bpf_inode_storage_get in bpf-helpers(7) for details.
#[repr(transparent)]
pub struct InodeStorage<V> {
    def: UnsafeCell<bpf_map_def>,
    _v: PhantomData<V>,
}

unsafe impl<T: Sync> Sync for InodeStorage<T> {}

impl<V> InodeStorage<V> {
    /// Instantiate a [`InodeStorage`] map with the provided flags.
    pub const fn new(flags: u32) -> InodeStorage<V> {
        InodeStorage {
            def: UnsafeCell::new(build_def::<V>(
                BPF_MAP_TYPE_INODE_STORAGE,
                flags,
                PinningType::None,
            )),
            _v: PhantomData,
        }
    }

    /// Instantiate a pinned [`InodeStorage`] map with the provided flags.
    pub const fn pinned(flags: u32) -> InodeStorage<V> {
        InodeStorage {
            def: UnsafeCell::new(build_def::<V>(
                BPF_MAP_TYPE_INODE_STORAGE,
                flags,
                PinningType::ByName,
            )),
            _v: PhantomData,
        }
    }

    /// Get a local storage entry associated with this inode, or insert the provided value and get
    /// the mutable reference to the information stored within the inode. Returns [`None`] if there
    /// was an issue with inserting the new value.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same inode's local storage multiple times
    /// would create multiple mutable references to the same data, which is not supported by Rust's
    /// memory model.
    #[inline]
    pub unsafe fn get_or_insert(&self, inode: *mut c_void, initial: &V) -> Option<&mut V> {
        self.get_or_insert_ptr(inode, initial).map(|p| &mut *p)
    }

    /// Get a pointer to the local storage entry associated with this inode, or insert the provided
    /// value and get the mutable reference to the information stored within the inode. Returns
    /// [`None`] if there was an issue with inserting the new value.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_or_insert_ptr(&self, inode: *mut c_void, initial: &V) -> Option<*mut V> {
        unsafe {
            let ptr = bpf_inode_storage_get(
                self.def.get() as *mut c_void,
                inode,
                initial as *const V as *const c_void as *mut c_void,
                u64::from(BPF_LOCAL_STORAGE_GET_F_CREATE),
            );
            NonNull::new(ptr as *mut V).map(|p| p.as_ptr())
        }
    }

    /// Get a local storage entry associated with this inode, or [`None`] if no such value exists.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same inode's local storage immutably at the
    /// same time as mutably (e.g., but way of [`InodeStorage::get_mut`]) is not supported by Rust's
    /// memory model.
    #[inline]
    pub unsafe fn get(&self, inode: *mut c_void) -> Option<&V> {
        self.get_ptr(inode).map(|p| &*p)
    }

    /// Mutably access a local storage entry associated with this inode, or [`None`] if no such
    /// value exists.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same inode's local storage mutably multiple
    /// times is not supported by Rust's memory model.
    #[inline]
    pub unsafe fn get_mut(&self, inode: *mut c_void) -> Option<&mut V> {
        self.get_ptr_mut(inode).map(|p| &mut *p)
    }

    /// Get a pointer to the local storage entry associated with this inode, or [`None`] if no such
    /// value exists.
    #[inline]
    pub fn get_ptr(&self, inode: *mut c_void) -> Option<*const V> {
        self.get_ptr_mut(inode).map(|p| p as *const V)
    }

    /// Get a mutable pointer to the local storage entry associated with this inode, or [`None`] if
    /// no such value exists. You are responsible for ensuring that at most one mutable reference to
    /// the same inode local storage exists at a given time.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_ptr_mut(&self, inode: *mut c_void) -> Option<*mut V> {
        unsafe {
            let ptr = bpf_inode_storage_get(
                self.def.get() as *mut c_void,
                inode,
                core::ptr::null_mut(),
                0,
            );
            NonNull::new(ptr as *mut V).map(|p| p.as_ptr())
        }
    }

    /// Remove a local storage entry associated with this inode. Returns `Err(-ENOENT)` if no such
    /// value was present.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn remove(&self, inode: *mut c_void) -> Result<(), c_int> {
        let ret = unsafe { bpf_inode_storage_delete(self.def.get() as *mut c_void, inode) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

const fn build_def<V>(ty: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<c_int>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries: 1,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}
