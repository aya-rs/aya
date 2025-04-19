use core::{cell::UnsafeCell, fmt, marker::PhantomData, mem, ptr::NonNull};

use aya_ebpf_cty::c_long;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_ARRAY},
    insert, lookup,
    maps::PinningType,
};

#[repr(transparent)]
pub struct Array<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

#[derive(Debug)]
pub struct OutOfBounds {
    length: u32,
    index: u32,
}

impl core::error::Error for OutOfBounds {}

impl fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Array index {} is out of bounds; length = {}",
            self.index, self.length
        )
    }
}

unsafe impl<T: Sync> Sync for Array<T> {}

impl<T> Array<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Array<T> {
        Array {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Result<&T, OutOfBounds> {
        // FIXME: alignment
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Result<*const T, OutOfBounds> {
        unsafe { self.lookup(index).map(|p| p.as_ptr() as *const T) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Result<*mut T, OutOfBounds> {
        unsafe { self.lookup(index).map(|p| p.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Result<NonNull<T>, OutOfBounds> {
        let map_def = self.def.get();

        lookup(map_def, &index).ok_or(OutOfBounds {
            length: unsafe { (*map_def).max_entries },
            index,
        })
    }

    /// Sets the value of the element at the given index.
    #[inline(always)]
    pub fn set(&self, index: u32, value: &T, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), &index, value, flags)
    }
}
