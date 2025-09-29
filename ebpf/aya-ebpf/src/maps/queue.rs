use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_QUEUE},
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct Queue<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for Queue<T> {}

impl<T> Queue<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_QUEUE,
                key_size: 0,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_QUEUE,
                key_size: 0,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    pub fn push(&self, value: &T, flags: u64) -> Result<(), i64> {
        let ret =
            unsafe { bpf_map_push_elem(self.def.get().cast(), ptr::from_ref(value).cast(), flags) };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn pop(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_pop_elem(self.def.get().cast(), value.as_mut_ptr().cast());
            (ret == 0).then_some(value.assume_init())
        }
    }

    pub fn peek(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_peek_elem(self.def.get().cast(), value.as_mut_ptr().cast());
            (ret == 0).then_some(value.assume_init())
        }
    }
}
