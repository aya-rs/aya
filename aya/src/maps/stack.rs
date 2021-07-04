//! A LIFO stack.
use std::{
    convert::TryFrom,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_STACK,
    maps::{Map, MapError, MapRef, MapRefMut},
    sys::{bpf_map_lookup_and_delete_elem, bpf_map_update_elem},
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
/// # let bpf = aya::Bpf::load(&[], None)?;
/// use aya::maps::Stack;
/// use std::convert::TryFrom;
///
/// let mut stack = Stack::try_from(bpf.map_mut("STACK")?)?;
/// stack.push(42, 0)?;
/// stack.push(43, 0)?;
/// assert_eq!(stack.pop(0)?, 43);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_STACK")]
pub struct Stack<T: Deref<Target = Map>, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: Deref<Target = Map>, V: Pod> Stack<T, V> {
    fn new(map: T) -> Result<Stack<T, V>, MapError> {
        let map_type = map.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_STACK as u32 {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            });
        }
        let expected = 0;
        let size = map.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<V>();
        let size = map.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }
        let _fd = map.fd_or_err()?;

        Ok(Stack {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the stack can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.inner.obj.def.max_entries
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>, V: Pod> Stack<T, V> {
    /// Removes the last element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the stack is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.fd_or_err()?;

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(code, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_and_delete_elem".to_owned(),
                code,
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
    pub fn push(&mut self, value: V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.fd_or_err()?;
        bpf_map_update_elem(fd, &0, &value, flags).map_err(|(code, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                code,
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<V: Pod> TryFrom<MapRef> for Stack<MapRef, V> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<Stack<MapRef, V>, MapError> {
        Stack::new(a)
    }
}

impl<V: Pod> TryFrom<MapRefMut> for Stack<MapRefMut, V> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<Stack<MapRefMut, V>, MapError> {
        Stack::new(a)
    }
}
