use core::{borrow::Borrow, marker::PhantomData, mem, ptr};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK,
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct Stack<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl_private_map!(<T> Stack<T>, (), T);

impl<T> Stack<T> {
    map_constructors!((), T, BPF_MAP_TYPE_STACK, phantom _t);

    pub fn push(&self, value: impl Borrow<T>, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_push_elem(
                self.def.as_ptr().cast(),
                ptr::from_ref(value.borrow()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret)
    }

    pub fn pop(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_pop_elem(self.def.as_ptr().cast(), value.as_mut_ptr().cast());
            (ret == 0).then_some(value.assume_init())
        }
    }

    pub fn peek(&self) -> Option<T> {
        unsafe {
            let mut value = mem::MaybeUninit::<T>::uninit();
            let ret = bpf_map_peek_elem(self.def.as_ptr().cast(), value.as_mut_ptr().cast());
            (ret == 0).then_some(value.assume_init())
        }
    }
}
