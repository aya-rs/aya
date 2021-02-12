use std::{
    convert::TryFrom,
    mem,
    ops::{Deref, DerefMut},
    os::unix::prelude::RawFd,
};

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY,
    maps::{IterableMap, Map, MapError, MapIter, MapKeys, MapRef, MapRefMut},
    programs::ProgramFd,
    sys::{
        bpf_map_delete_elem, bpf_map_lookup_and_delete_elem, bpf_map_lookup_elem,
        bpf_map_update_elem,
    },
};

pub struct ProgramArray<T: Deref<Target = Map>> {
    inner: T,
}

impl<T: Deref<Target = Map>> ProgramArray<T> {
    pub fn new(map: T) -> Result<ProgramArray<T>, MapError> {
        let inner = map.deref();
        let map_type = inner.obj.def.map_type;
        if map_type != BPF_MAP_TYPE_PROG_ARRAY {
            return Err(MapError::InvalidMapType {
                map_type: map_type as u32,
            })?;
        }
        let expected = mem::size_of::<RawFd>();
        let size = inner.obj.def.key_size as usize;
        if size != expected {
            return Err(MapError::InvalidKeySize { size, expected });
        }

        let expected = mem::size_of::<RawFd>();
        let size = inner.obj.def.value_size as usize;
        if size != expected {
            return Err(MapError::InvalidValueSize { size, expected });
        }

        Ok(ProgramArray { inner: map })
    }

    pub unsafe fn get(&self, key: &u32, flags: u64) -> Result<Option<RawFd>, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        let fd = bpf_map_lookup_elem(fd, key, flags)
            .map_err(|(code, io_error)| MapError::LookupElementFailed { code, io_error })?;
        Ok(fd)
    }

    pub unsafe fn iter<'coll>(&'coll self) -> MapIter<'coll, u32, RawFd> {
        MapIter::new(self)
    }

    pub unsafe fn keys<'coll>(&'coll self) -> MapKeys<'coll, u32, RawFd> {
        MapKeys::new(self)
    }

    fn check_bounds(&self, index: u32) -> Result<(), MapError> {
        let max_entries = self.inner.deref().obj.def.max_entries;
        if index >= self.inner.deref().obj.def.max_entries {
            Err(MapError::OutOfBounds { index, max_entries })
        } else {
            Ok(())
        }
    }
}

impl<T: Deref<Target = Map> + DerefMut<Target = Map>> ProgramArray<T> {
    pub fn insert(
        &mut self,
        index: u32,
        program: &dyn ProgramFd,
        flags: u64,
    ) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        self.check_bounds(index)?;
        let prog_fd = program.fd().ok_or(MapError::ProgramNotLoaded)?;

        bpf_map_update_elem(fd, &index, &prog_fd, flags)
            .map_err(|(code, io_error)| MapError::UpdateElementFailed { code, io_error })?;
        Ok(())
    }

    pub unsafe fn pop(&mut self, index: &u32) -> Result<Option<RawFd>, MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        self.check_bounds(*index)?;
        bpf_map_lookup_and_delete_elem(fd, index)
            .map_err(|(code, io_error)| MapError::LookupAndDeleteElementFailed { code, io_error })
    }

    pub fn remove(&mut self, index: &u32) -> Result<(), MapError> {
        let fd = self.inner.deref().fd_or_err()?;
        self.check_bounds(*index)?;
        bpf_map_delete_elem(fd, index)
            .map(|_| ())
            .map_err(|(code, io_error)| MapError::DeleteElementFailed { code, io_error })
    }
}

impl<T: Deref<Target = Map>> IterableMap<u32, RawFd> for ProgramArray<T> {
    fn fd(&self) -> Result<RawFd, MapError> {
        self.inner.deref().fd_or_err()
    }

    unsafe fn get(&self, index: &u32) -> Result<Option<RawFd>, MapError> {
        self.get(index, 0)
    }
}

impl TryFrom<MapRef> for ProgramArray<MapRef> {
    type Error = MapError;

    fn try_from(a: MapRef) -> Result<ProgramArray<MapRef>, MapError> {
        ProgramArray::new(a)
    }
}

impl TryFrom<MapRefMut> for ProgramArray<MapRefMut> {
    type Error = MapError;

    fn try_from(a: MapRefMut) -> Result<ProgramArray<MapRefMut>, MapError> {
        ProgramArray::new(a)
    }
}
