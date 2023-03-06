use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_bindings::bindings::bpf_map_type::{
    BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
};
use aya_bpf_cty::{c_long, c_void};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH},
    helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    maps::PinningType,
};

/// A hash map that can be shared between eBPF programs and user-space.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
///
/// XDP program using a `HashMap<u32, u32>` to block traffic from IP addresses
/// defined in it:
///
/// ```no_run
/// # use core::ffi::c_long;
/// use aya_bpf::{bindings::xdp_action, macros::map, maps::HashMap};
/// # use aya_bpf::programs::XdpContext;
///
/// /// A map which stores IP addresses to block.
/// #[map]
/// static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
///
/// # fn parse_src_addr(ctx: &XdpContext) -> u32 { 0 }
/// # fn try_test(ctx: &XdpContext) -> Result<i32, c_long> {
/// let src_addr: u32 = parse_src_addr(&ctx);
/// if BLOCKLIST.get(&src_addr).is_some() {
///     return Ok(xdp_action::XDP_DROP);
/// }
/// Ok(xdp_action::XDP_PASS)   
/// # }
/// ```
#[repr(transparent)]
pub struct HashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for HashMap<K, V> {}

impl<K, V> HashMap<K, V> {
    /// Creates an empty `HashMap<K, V>` with the specified maximum number of
    /// elements.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    ///
    /// #[map]
    /// static mut REDIRECT_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(1024, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Creates an empty `HashMap<K, V>` with the specified maximum number of
    /// elements, and pins it to the BPF file system (BPFFS).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    ///
    /// #[map]
    /// static mut REDIRECT_PORTS: HashMap<u32, u32> = HashMap::pinned(1024, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieves the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of [`HashMap::insert`] or
    /// [`HashMap::remove`], and any element removed from the map might get
    /// aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    ///
    /// There is no guarantee that the reference returned by this method is
    /// aligned.
    ///
    /// The value contained in the map must be of type `T`. Calling this method
    /// with the incorrect type is *undefined behavior*.
    ///
    /// # Examples
    ///
    /// XDP program using a `HashMap<u16, u16>` to store port redirection rules:
    ///
    /// ```no_run
    /// # use core::ffi::c_long;
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::XdpContext;
    ///
    /// #[map]
    /// static REDIRECT_PORTS: HashMap<u16, u16> = HashMap::with_max_entries(1024, 0);
    ///
    /// # fn parse_source(ctx: &XdpContext) -> u16 { 0 }
    /// # fn try_test(ctx: &XdpContext) -> Result<i32, c_long> {
    /// // Source port of the packet.
    /// let source: u16 = parse_source(&ctx);
    /// // Port to which we want redirect the packet to.
    /// let redirect = REDIRECT_PORTS.get(&source);
    ///
    /// // Redirect the packet.
    /// # Ok(0)
    /// # }
    /// ```
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of [`HashMap::insert`] or
    /// [`HashMap::remove`], and any element removed from the map might get
    /// aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    ///
    /// This method is safe, but it returns a raw pointer and deferefencing it
    /// is an unsafe operation.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    ///
    /// # Safety
    ///
    /// Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of [`HashMap::insert`] or
    /// [`HashMap::remove`], and any element removed from the map might get
    /// aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    ///
    /// This method is safe, but it returns a raw pointer and deferefencing it
    /// is an unsafe operation.
    ///
    /// # Examples
    ///
    /// Tracepoint program (attached to `syscall/sys_enter_read`) which counts
    /// the number of reads performed by each process in a `HashMap<u32, u32>`:
    ///
    /// ```no_run
    /// # use core::ffi::c_long;
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::TracePointContext;
    ///
    /// /// A maps which maps processes to the number of reads they performed.
    /// #[map]
    /// static PROCESS_READS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # fn try_test(ctx: &TracePointContext) -> Result<(), c_long> {
    /// let pid = ctx.pid();
    /// match PROCESS_READS.get_ptr_mut(&pid) {
    ///    Some(count) => unsafe { *count += 1 },
    ///    None => PROCESS_READS.insert(&pid, &1, 0)?,
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key)
    }

    /// Insert the given key and value into the map.
    ///
    /// # Examples
    ///
    /// Tracepoint program (attached to `syscall/sys_enter_bind`) which maps
    /// processes to the port they are listening on in a `HashMap<u32, u16>`:
    ///
    /// ```no_run
    /// # use core::ffi::c_long;
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::TracePointContext;
    ///
    /// /// A maps which maps processes to the port they are listening on.
    /// #[map]
    /// static PROCESS_PORT: HashMap<u32, u16> = HashMap::with_max_entries(1024, 0);
    ///
    /// # fn parse_local_port(ctx: &TracePointContext) -> u16 { 0 }
    /// # fn try_test(ctx: &TracePointContext) -> Result<(), c_long> {
    /// let pid = ctx.pid();
    /// let port = parse_local_port(&ctx);
    /// PROCESS_PORT.insert(&pid, &port, 0)?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), key, value, flags)
    }

    /// Remove the given key from the map.
    ///
    /// # Examples
    ///
    /// Tracepoint program (attached to `sched/sched_process_exit`) which
    /// removes the process from a `HashMap<u32, u32>` once it exits:
    ///
    /// ```no_run
    /// # use core::ffi::c_long;
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::TracePointContext;
    ///
    /// /// A maps which maps PIDs to the number of reads they performed.
    /// #[map]
    /// static PROCESS_READS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # fn try_test(ctx: &TracePointContext) -> Result<(), c_long> {
    /// let pid = ctx.pid();
    /// PROCESS_READS.remove(&pid)?;
    /// # Ok(())
    /// # }
    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.def.get(), key)
    }
}

#[repr(transparent)]
pub struct LruHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for LruHashMap<K, V> {}

impl<K, V> LruHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.def.get(), key)
    }
}

#[repr(transparent)]
pub struct PerCpuHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K, V> Sync for PerCpuHashMap<K, V> {}

impl<K, V> PerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.def.get(), key)
    }
}

#[repr(transparent)]
pub struct LruPerCpuHashMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K, V> Sync for LruPerCpuHashMap<K, V> {}

impl<K, V> LruPerCpuHashMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.def.get(), key)
    }
}

const fn build_def<K, V>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*mut V> {
    unsafe {
        let value = bpf_map_lookup_elem(def as *mut _, key as *const _ as *const c_void);
        // FIXME: alignment
        NonNull::new(value as *mut V).map(|p| p.as_ptr())
    }
}

#[inline]
fn get_ptr<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*const V> {
    get_ptr_mut(def, key).map(|p| p as *const V)
}

#[inline]
unsafe fn get<'a, K, V>(def: *mut bpf_map_def, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| &*p)
}

#[inline]
fn insert<K, V>(def: *mut bpf_map_def, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let ret = unsafe {
        bpf_map_update_elem(
            def as *mut _,
            key as *const _ as *const _,
            value as *const _ as *const _,
            flags,
        )
    };
    (ret == 0).then_some(()).ok_or(ret)
}

#[inline]
fn remove<K>(def: *mut bpf_map_def, key: &K) -> Result<(), c_long> {
    let ret = unsafe { bpf_map_delete_elem(def as *mut _, key as *const _ as *const c_void) };
    (ret == 0).then_some(()).ok_or(ret)
}
