//! A LIFO stack.
use std::{
    convert::{AsMut, AsRef},
    marker::PhantomData,
};

use crate::{
    maps::{check_kv_size, MapData, MapError},
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
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::Stack;
///
/// let mut stack = Stack::try_from(bpf.map_mut("STACK").unwrap())?;
/// stack.push(42, 0)?;
/// stack.push(43, 0)?;
/// assert_eq!(stack.pop(0)?, 43);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_STACK")]
pub struct Stack<T, V: Pod> {
    inner: T,
    _v: PhantomData<V>,
}

impl<T: AsRef<MapData>, V: Pod> Stack<T, V> {
    pub(crate) fn new(map: T) -> Result<Stack<T, V>, MapError> {
        let data = map.as_ref();
        check_kv_size::<(), V>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(Stack {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the number of elements the stack can hold.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn capacity(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }
}

impl<T: AsMut<MapData>, V: Pod> Stack<T, V> {
    /// Removes the last element and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::ElementNotFound`] if the stack is empty, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_and_delete_elem` fails.
    pub fn pop(&mut self, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.as_mut().fd_or_err()?;

        let value = bpf_map_lookup_and_delete_elem::<u32, _>(fd, None, flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_lookup_and_delete_elem".to_owned(),
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
        let fd = self.inner.as_mut().fd_or_err()?;
        bpf_map_update_elem(fd, None::<&u32>, &value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }
}
