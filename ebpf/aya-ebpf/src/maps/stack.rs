use core::{borrow::Borrow, marker::PhantomData, mem::MaybeUninit, ptr};

use crate::{
    ENOENT,
    bindings::bpf_map_type::BPF_MAP_TYPE_STACK,
    helpers::{bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem},
    maps::{MapDef, PinningType},
};

#[repr(transparent)]
pub struct Stack<T> {
    def: MapDef,
    _t: PhantomData<T>,
}

impl<T> super::private::Map for Stack<T> {
    type Key = ();
    type Value = T;
}

impl<T> Stack<T> {
    map_constructors!((), T, BPF_MAP_TYPE_STACK, phantom _t);

    pub fn push(&self, value: impl Borrow<T>, flags: u64) -> Result<(), i32> {
        let ret = unsafe {
            bpf_map_push_elem(
                self.def.as_ptr().cast(),
                ptr::from_ref(value.borrow()).cast(),
                flags,
            )
        };
        (ret == 0).then_some(()).ok_or(ret as i32)
    }

    /// Removes and returns the top of the stack.
    ///
    /// Returns `Ok(None)` when the stack is empty.
    ///
    /// # Errors
    ///
    /// Propagates any non-zero errno from [`bpf_map_pop_elem`] (e.g.
    /// `-EBUSY` under lock contention).
    ///
    /// [`bpf_map_pop_elem`]: https://docs.ebpf.io/linux/helper-function/bpf_map_pop_elem/
    pub fn pop(&self) -> Result<Option<T>, i32> {
        unsafe {
            let mut value = MaybeUninit::<T>::uninit();
            match bpf_map_pop_elem(self.def.as_ptr().cast(), value.as_mut_ptr().cast()) as i32 {
                0 => Ok(Some(value.assume_init())),
                err if err == -ENOENT => Ok(None),
                err => Err(err),
            }
        }
    }

    /// Returns the top of the stack without removing it.
    ///
    /// Returns `Ok(None)` when the stack is empty.
    ///
    /// # Errors
    ///
    /// Propagates any non-zero errno from [`bpf_map_peek_elem`] (e.g.
    /// `-EBUSY` under lock contention).
    ///
    /// [`bpf_map_peek_elem`]: https://docs.ebpf.io/linux/helper-function/bpf_map_peek_elem/
    pub fn peek(&self) -> Result<Option<T>, i32> {
        unsafe {
            let mut value = MaybeUninit::<T>::uninit();
            match bpf_map_peek_elem(self.def.as_ptr().cast(), value.as_mut_ptr().cast()) as i32 {
                0 => Ok(Some(value.assume_init())),
                err if err == -ENOENT => Ok(None),
                err => Err(err),
            }
        }
    }
}
