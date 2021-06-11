use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crate::maps::Map;

pub(crate) struct MapLockError;

/* FIXME: write a full RwLock implementation that doesn't use borrowing guards
 * so that try_read() and try_write() don't have to use the ugly lifetime
 * extension hack */

#[derive(Debug)]
pub(crate) struct MapLock {
    inner: Arc<RwLock<Map>>,
}

impl MapLock {
    pub(crate) fn new(map: Map) -> MapLock {
        MapLock {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    pub(crate) fn try_read(&self) -> Result<MapRef, MapLockError> {
        let lock: Option<RwLockReadGuard<'static, Map>> =
            unsafe { mem::transmute(self.inner.try_read()) };
        lock.map(|guard| MapRef {
            _lock: self.inner.clone(),
            guard,
        })
        .ok_or(MapLockError)
    }

    pub(crate) fn try_write(&self) -> Result<MapRefMut, MapLockError> {
        let lock: Option<RwLockWriteGuard<'static, Map>> =
            unsafe { mem::transmute(self.inner.try_write()) };
        lock.map(|guard| MapRefMut {
            _lock: self.inner.clone(),
            guard,
        })
        .ok_or(MapLockError)
    }
}

/// A borrowed reference to a BPF map.
pub struct MapRef {
    _lock: Arc<RwLock<Map>>,
    guard: RwLockReadGuard<'static, Map>,
}

/// A mutable borrowed reference to a BPF map.
pub struct MapRefMut {
    _lock: Arc<RwLock<Map>>,
    guard: RwLockWriteGuard<'static, Map>,
}

impl Deref for MapRef {
    type Target = Map;

    fn deref(&self) -> &Map {
        &*self.guard
    }
}

impl Deref for MapRefMut {
    type Target = Map;

    fn deref(&self) -> &Map {
        &*self.guard
    }
}

impl DerefMut for MapRefMut {
    fn deref_mut(&mut self) -> &mut Map {
        &mut *self.guard
    }
}
