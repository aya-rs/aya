use core::{cell::UnsafeCell, marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_QUEUE},
    helpers::{bpf_map_pop_elem, bpf_map_push_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct Queue<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for Queue<T> {}

impl<T> Queue<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Queue<T> {
        Queue {
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

    pub const fn pinned(max_entries: u32, flags: u32) -> Queue<T> {
        Queue {
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
        let ret = unsafe {
            bpf_map_push_elem(
                self.def.get() as *mut _,
                value as *const _ as *const _,
                flags,
            )
        };
        (ret >= 0).then(|| ()).ok_or(ret)
    }

    pub fn pop(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::uninit();
            let ret = bpf_map_pop_elem(self.def.get() as *mut _, value.as_mut_ptr() as *mut _);
            (ret >= 0).then(|| value.assume_init())
        }
    }
}
