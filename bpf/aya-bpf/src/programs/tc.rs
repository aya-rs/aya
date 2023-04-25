use aya_bpf_cty::{c_long, c_void};

use crate::{bindings::__sk_buff, programs::sk_buff::SkBuff, BpfContext};

pub struct TcContext {
    pub skb: SkBuff,
}

impl TcContext {
    pub fn new(skb: *mut __sk_buff) -> TcContext {
        let skb = SkBuff { skb };
        TcContext { skb }
    }

    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> u32 {
        self.skb.len()
    }

    #[inline]
    pub fn data(&self) -> usize {
        self.skb.data()
    }

    #[inline]
    pub fn data_end(&self) -> usize {
        self.skb.data_end()
    }

    #[inline]
    pub fn set_mark(&mut self, mark: u32) {
        self.skb.set_mark(mark)
    }

    #[inline]
    pub fn cb(&self) -> &[u32] {
        self.skb.cb()
    }

    #[inline]
    pub fn cb_mut(&mut self) -> &mut [u32] {
        self.skb.cb_mut()
    }

    /// Returns the owner UID of the socket associated to the SKB context.
    #[inline]
    pub fn get_socket_uid(&self) -> u32 {
        self.skb.get_socket_uid()
    }

    #[inline]
    pub fn load<T>(&self, offset: usize) -> Result<T, c_long> {
        self.skb.load(offset)
    }

    /// Reads some bytes from the packet into the specified buffer, returning
    /// how many bytes were read.
    ///
    /// Starts reading at `offset` and reads at most `dst.len()` or
    /// `self.len() - offset` bytes, depending on which one is smaller.
    ///
    /// # Examples
    ///
    /// Read into a `PerCpuArray`.
    ///
    /// ```no_run
    /// use core::mem;
    ///
    /// use aya_bpf::{bindings::TC_ACT_PIPE, macros::map, maps::PerCpuArray, programs::TcContext};
    /// # #[allow(non_camel_case_types)]
    /// # struct ethhdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct iphdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct tcphdr {};
    ///
    /// const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
    /// const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
    /// const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
    ///
    /// #[repr(C)]
    /// pub struct Buf {
    ///    pub buf: [u8; 1500],
    /// }
    ///
    /// #[map]
    /// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
    ///
    /// fn try_classifier(ctx: TcContext) -> Result<i32, i32> {
    ///     let buf = unsafe {
    ///         let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
    ///         &mut *ptr
    ///     };
    ///     let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    ///     ctx.load_bytes(offset, &mut buf.buf).map_err(|_| TC_ACT_PIPE)?;
    ///
    ///     // do something with `buf`
    ///
    ///     Ok(TC_ACT_PIPE)
    /// }
    /// ```
    #[inline(always)]
    pub fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
        self.skb.load_bytes(offset, dst)
    }

    #[inline]
    pub fn store<T>(&mut self, offset: usize, v: &T, flags: u64) -> Result<(), c_long> {
        self.skb.store(offset, v, flags)
    }

    #[inline]
    pub fn l3_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        size: u64,
    ) -> Result<(), c_long> {
        self.skb.l3_csum_replace(offset, from, to, size)
    }

    #[inline]
    pub fn l4_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        flags: u64,
    ) -> Result<(), c_long> {
        self.skb.l4_csum_replace(offset, from, to, flags)
    }

    #[inline]
    pub fn adjust_room(&self, len_diff: i32, mode: u32, flags: u64) -> Result<(), c_long> {
        self.skb.adjust_room(len_diff, mode, flags)
    }

    #[inline]
    pub fn clone_redirect(&self, if_index: u32, flags: u64) -> Result<(), c_long> {
        self.skb.clone_redirect(if_index, flags)
    }

    #[inline]
    pub fn change_proto(&self, proto: u16, flags: u64) -> Result<(), c_long> {
        self.skb.change_proto(proto, flags)
    }

    #[inline]
    pub fn change_type(&self, ty: u32) -> Result<(), c_long> {
        self.skb.change_type(ty)
    }

    /// Pulls in non-linear data in case the skb is non-linear.
    ///
    /// Make len bytes from skb readable and writable. If a zero value is passed for
    /// `len`, then the whole length of the skb is pulled. This helper is only needed
    /// for reading and writing with direct packet access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// mod bindings;
    /// use bindings::{ethhdr, iphdr, udphdr};
    ///
    /// const ETH_HLEN: usize = core::mem::size_of::<ethhdr>();
    /// const IP_HLEN: usize = core::mem::size_of::<iphdr>();
    /// const UDP_HLEN: usize = core::mem::size_of::<udphdr>();
    ///
    /// fn try_classifier(ctx: TcContext) -> Result<i32, i32> {
    ///     let len = ETH_HLEN + IP_HLEN + UDP_HLEN;
    ///     match ctx.pull_data(len as u32) {
    ///         Ok(_) => return Ok(0),
    ///         Err(ret) => return Err(ret as i32),
    ///     }
    /// }
    /// ```
    #[inline(always)]
    pub fn pull_data(&self, len: u32) -> Result<(), c_long> {
        self.skb.pull_data(len)
    }
}

impl BpfContext for TcContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb.as_ptr()
    }
}
