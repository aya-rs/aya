//! Socket load balancing with `SO_REUSEPORT`.

use core::ptr;

use crate::{
    EbpfContext,
    bindings::sk_reuseport_md,
    cty::{c_long, c_void},
    helpers::bpf_sk_select_reuseport,
    programs::SockContext,
};

mod sealed {
    use crate::{
        btf_maps::ReusePortSockArray as BtfReusePortSockArray, cty::c_void,
        maps::ReusePortSockArray as LegacyReusePortSockArray,
    };

    #[expect(unnameable_types, reason = "this is the sealed trait pattern")]
    pub trait ReusePortMap {
        fn as_map_ptr(&self) -> *mut c_void;
    }

    impl ReusePortMap for LegacyReusePortSockArray {
        fn as_map_ptr(&self) -> *mut c_void {
            self.as_ptr()
        }
    }

    impl<const MAX_ENTRIES: usize, const FLAGS: usize> ReusePortMap
        for BtfReusePortSockArray<MAX_ENTRIES, FLAGS>
    {
        fn as_map_ptr(&self) -> *mut c_void {
            self.as_ptr()
        }
    }
}

#[doc(hidden)]
pub trait ReusePortMap: sealed::ReusePortMap {}

impl<T: sealed::ReusePortMap> ReusePortMap for T {}

/// Allow the kernel's default `SO_REUSEPORT` socket selection.
pub const SK_PASS: u32 = 1;

/// Drop the packet instead of selecting a socket.
pub const SK_DROP: u32 = 0;

pub struct SkReuseportContext {
    pub md: *mut sk_reuseport_md,
}

impl SkReuseportContext {
    pub const fn new(md: *mut sk_reuseport_md) -> Self {
        Self { md }
    }

    /// Returns the start of the directly accessible data.
    #[inline]
    pub fn data(&self) -> usize {
        unsafe { (*self.md).__bindgen_anon_1.data as usize }
    }

    /// Returns the end of the directly accessible data.
    #[inline]
    pub fn data_end(&self) -> usize {
        unsafe { (*self.md).__bindgen_anon_2.data_end as usize }
    }

    /// Returns the total packet length.
    #[inline]
    pub fn len(&self) -> usize {
        unsafe { (*self.md).len as usize }
    }

    /// Returns whether the packet length is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the Ethernet protocol from the packet in network byte order.
    #[inline]
    pub fn eth_protocol(&self) -> u32 {
        unsafe { (*self.md).eth_protocol }
    }

    /// Returns the IP protocol.
    #[inline]
    pub fn ip_protocol(&self) -> u32 {
        unsafe { (*self.md).ip_protocol }
    }

    /// Returns whether the socket is bound to an INANY address.
    #[inline]
    pub fn bind_inany(&self) -> u32 {
        unsafe { (*self.md).bind_inany }
    }

    /// Returns the hash of the packet's 4-tuple.
    #[inline]
    pub fn hash(&self) -> u32 {
        unsafe { (*self.md).hash }
    }

    /// Returns a socket from the current `SO_REUSEPORT` group.
    ///
    /// This socket can be used to inspect the local listener that is being
    /// considered for selection.
    ///
    /// Available on Linux 5.14 and later.
    #[inline]
    pub fn sk(&self) -> SockContext {
        SockContext::new(unsafe { (*self.md).__bindgen_anon_3.sk })
    }

    /// Returns the socket being migrated, if the program is running in a
    /// migrate path.
    ///
    /// When this returns `None`, the program is handling initial socket
    /// selection for a new packet or connection.
    ///
    /// Available on Linux 5.14 and later.
    #[inline]
    pub fn migrating_sk(&self) -> Option<SockContext> {
        let sock = unsafe { (*self.md).__bindgen_anon_4.migrating_sk };
        if sock.is_null() {
            None
        } else {
            Some(SockContext::new(sock))
        }
    }

    /// Selects a socket from `map` using `key`.
    ///
    /// `map` may be a legacy [`maps::ReusePortSockArray`](crate::maps::ReusePortSockArray)
    /// or a BTF-compatible [`btf_maps::ReusePortSockArray`](crate::btf_maps::ReusePortSockArray).
    /// Userspace must populate it with sockets from the same `SO_REUSEPORT`
    /// group before calling this helper.
    ///
    /// The `flags` argument is forwarded to `bpf_sk_select_reuseport()`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_ebpf::{
    ///     macros::{map, sk_reuseport},
    ///     maps::ReusePortSockArray,
    ///     programs::{SkReuseportContext, SK_DROP, SK_PASS},
    /// };
    ///
    /// const IPPROTO_TCP: u32 = 6;
    /// const SOCKET_COUNT: u32 = 4;
    ///
    /// #[map(name = "SOCKETS")]
    /// static SOCKETS: ReusePortSockArray = ReusePortSockArray::with_max_entries(SOCKET_COUNT, 0);
    ///
    /// #[sk_reuseport]
    /// pub fn select_socket(ctx: SkReuseportContext) -> u32 {
    ///     if ctx.ip_protocol() != IPPROTO_TCP {
    ///         return SK_PASS;
    ///     }
    ///
    ///     let index = ctx.hash() % SOCKET_COUNT;
    ///     if ctx.select_reuseport(&SOCKETS, index, 0).is_err() {
    ///         return SK_DROP;
    ///     }
    ///
    ///     SK_PASS
    /// }
    /// ```
    #[inline]
    pub fn select_reuseport<M: ReusePortMap>(
        &self,
        map: &M,
        key: u32,
        flags: u64,
    ) -> Result<(), c_long> {
        let mut key = key;
        let ret = unsafe {
            bpf_sk_select_reuseport(
                self.as_ptr().cast(),
                map.as_map_ptr(),
                ptr::from_mut(&mut key).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}

impl EbpfContext for SkReuseportContext {
    fn as_ptr(&self) -> *mut c_void {
        self.md.cast()
    }
}
