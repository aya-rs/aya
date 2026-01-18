use core::{borrow::Borrow, marker::PhantomData, ptr::NonNull};

use aya_ebpf_cty::c_long;

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_ARRAY,
    insert, lookup,
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct Array<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T> Array<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::None)
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self::new(max_entries, flags, PinningType::ByName)
    }

    const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<u32, T>(BPF_MAP_TYPE_ARRAY, max_entries, flags, pinning),
            _t: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&T> {
        unsafe { self.lookup(index).map(|p| p.as_ref()) }
    }

    #[inline(always)]
    pub fn get_ptr(&self, index: u32) -> Option<*const T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr().cast_const()) }
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> Option<*mut T> {
        unsafe { self.lookup(index).map(|p| p.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        lookup(self.def.as_ptr(), &index)
    }

    /// Sets the value of the element at the given index.
    #[inline(always)]
    pub fn set(&self, index: u32, value: impl Borrow<T>, flags: u64) -> Result<(), c_long> {
        insert(self.def.as_ptr(), &index, value.borrow(), flags)
    }
}
