//! A LIFO stack.
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsFd as _,
};

use crate::{
    maps::{check_kv_size, MapData, MapError},
    sys::{bpf_map_lookup_and_delete_elem, bpf_map_update_elem, SyscallError},
    Pod,
};

/// A LIFO stack.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.20.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use aya::maps::Stack;
///
/// let mut stack = Stack::try_from(bpf.map_mut("STACK").unwrap())?;
/// stack.push(42, 0)?;
/// stack.push(43, 0)?;
/// assert_eq!(stack.pop(0)?, 43);
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_STACK")]
pub struct Stack<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> Stack<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<(), V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the stack can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.inner.borrow().def.max_entries()
    }
}

impl<T: BorrowMut<MapData>, V: Pod> Stack<T, V> {
    /// Removes the last element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the stack is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.borrow().fd().as_fd();

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(_, io_error)| SyscallError {
                call: "bpf_map_lookup_and_delete_elem",
                io_error,
            },
        )?;
        value.ok_or(MapError::ElementNotFound)
    }

    /// Pushes an element on the stack.
    ///
    /// # Errors
    ///
    /// [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn push(&mut self, value: impl Borrow<V>, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        bpf_map_update_elem(fd, None::<&u32>, value.borrow(), flags).map_err(|(_, io_error)| {
            SyscallError {
                call: "bpf_map_update_elem",
                io_error,
            }
        })?;
        Ok(())
    }
}
