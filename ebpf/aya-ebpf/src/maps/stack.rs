use core::{borrow::Borrow, marker::PhantomData, mem, ptr};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_STACK},
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
    maps::{InnerMap, PinningType},
};

#[repr(transparent)]
pub struct Stack<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

unsafe impl<T> InnerMap for Stack<T> {}

impl<T> Stack<T> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_STACK,
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

    pub const fn pinned(max_entries: u32, flags: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_STACK,
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

    pub fn push(&self, value: impl Borrow<T>, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(
                ptr::from_ref(&self.def).cast_mut().cast(),
                ptr::from_ref(value.borrow()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn pop(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_pop_elem(
                ptr::from_ref(&self.def).cast_mut().cast(),
                value.as_mut_ptr().cast(),
            );
            (ret == 0).then_some(value.assume_init())
        }
    }

    pub fn peek(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_peek_elem(
                ptr::from_ref(&self.def).cast_mut().cast(),
                value.as_mut_ptr().cast(),
            );
            (ret == 0).then_some(value.assume_init())
        }
    }
}
