use core::{marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_QUEUE},
    helpers::{bpf_map_pop_elem, bpf_map_push_elem},
    maps::PinningType,
};

#[repr(transparent)]
pub struct Queue<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> Queue<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Queue<T> {
        Queue {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_QUEUE,
                key_size: 0,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> Queue<T> {
        Queue {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_QUEUE,
                key_size: 0,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
            _t: PhantomData,
        }
    }

    pub unsafe fn push(&mut self, value: &T, flags: u64) -> Result<(), i64> {
        let ret = bpf_map_push_elem(
            &mut self.def as *mut _ as *mut _,
            value as *const _ as *const _,
            flags,
        );
        if ret < 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }

    pub unsafe fn pop(&mut self) -> Option<T> {
        let mut value = mem::MaybeUninit::uninit();
        let ret = bpf_map_pop_elem(
            &mut self.def as *mut _ as *mut _,
            &mut value as *mut _ as *mut _,
        );
        if ret < 0 {
            None
        } else {
            Some(value.assume_init())
        }
    }
}
