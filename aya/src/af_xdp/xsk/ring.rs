use core::{ops::RangeInclusive, ptr::NonNull, sync::atomic::Ordering};

use aya_obj::generated::{
    xdp_desc, xdp_ring_offset, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING,
};

use crate::af_xdp::{
    xsk::{BufIdx, RingCons, RingProd, SocketFd, SocketMmapOffsets, XskRing},
    XskError,
};

impl XskRing {
    /// Construct a ring from an mmap given by the kernel.
    ///
    /// # Safety
    ///
    /// The caller is responsible for ensuring that the memory mapping is valid, and **outlives**
    /// the ring itself. Please attach a reference counted pointer to the controller or something
    /// of that sort.
    ///
    /// The caller must ensure that the memory region is not currently mutably aliased. That's
    /// wrong anyways because the kernel may write to it, i.e. it is not immutable! A shared
    /// aliasing is okay.
    unsafe fn new(tx_map: NonNull<u8>, off: &xdp_ring_offset, count: u32) -> Self {
        debug_assert!(count.is_power_of_two());
        let tx_map: *mut u8 = tx_map.as_ptr();
        let trust_offset = |off: u64| NonNull::new_unchecked(tx_map.offset(off as isize));

        let producer = trust_offset(off.producer).cast().as_ref();
        let consumer = trust_offset(off.consumer).cast().as_ref();

        let ring = trust_offset(off.desc).cast();
        let flags = trust_offset(off.flags).cast();

        Self {
            mask: count - 1,
            size: count,
            producer,
            consumer,
            ring,
            flags,
            cached_producer: producer.load(Ordering::Relaxed),
            cached_consumer: consumer.load(Ordering::Relaxed),
        }
    }

    unsafe fn map(
        fd: &SocketFd,
        off: &xdp_ring_offset,
        count: u32,
        sz: u64,
        offset: libc::off_t,
    ) -> Result<(Self, NonNull<[u8]>), XskError> {
        let len = (off.desc + u64::from(count) * sz) as usize;

        let mmap = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.0,
                offset,
            )
        };

        if mmap == libc::MAP_FAILED {
            return Err(XskError::last_os_error())?;
        }

        assert!(!mmap.is_null());
        // Safety: as by MMap this pointer is valid.
        let mmap_addr = core::ptr::slice_from_raw_parts_mut(mmap as *mut u8, len);
        let mmap_addr = unsafe { NonNull::new_unchecked(mmap_addr) };
        let nn = mmap_addr.cast();

        Ok((Self::new(nn, off, count), mmap_addr))
    }
}

impl RingProd {
    /// # Safety
    ///
    /// The caller must only pass `fd` and `off` if they correspond as they were returned by the
    /// kernel.
    pub(crate) unsafe fn fill(
        fd: &SocketFd,
        off: &SocketMmapOffsets,
        count: u32,
    ) -> Result<Self, XskError> {
        let (inner, mmap_addr) = XskRing::map(
            fd,
            &off.inner.fr,
            count,
            core::mem::size_of::<u64>() as u64,
            XDP_UMEM_PGOFF_FILL_RING as i64,
        )?;

        Ok(Self { inner, mmap_addr })
    }

    /// # Safety
    ///
    /// The caller must only pass `fd` and `off` if they correspond as they were returned by the
    /// kernel.
    pub(crate) unsafe fn tx(
        fd: &SocketFd,
        off: &SocketMmapOffsets,
        count: u32,
    ) -> Result<Self, XskError> {
        let (inner, mmap_addr) = XskRing::map(
            fd,
            &off.inner.tx,
            count,
            core::mem::size_of::<xdp_desc>() as u64,
            XDP_PGOFF_TX_RING as i64,
        )?;

        Ok(Self { inner, mmap_addr })
    }

    /// Return the address of an address descriptor.
    ///
    /// # Safety
    ///
    /// To be used only in fill and complete rings. Further, the caller guarantees that the `idx`
    /// parameter is valid for the ring.
    pub(crate) unsafe fn fill_addr(&self, idx: BufIdx) -> NonNull<u64> {
        let offset = (idx.0 & self.inner.mask) as isize;
        let base = self.inner.ring.cast::<u64>().as_ptr();
        unsafe { NonNull::new_unchecked(base.offset(offset)) }
    }

    /// Return the address of a buffer descriptor.
    ///
    /// # Safety
    ///
    /// To be used only in fill and complete rings. Further, the caller guarantees that the `idx`
    /// parameter is valid for the ring.
    pub(crate) unsafe fn tx_desc(&self, idx: BufIdx) -> NonNull<xdp_desc> {
        let offset = (idx.0 & self.inner.mask) as isize;
        let base = self.inner.ring.cast::<xdp_desc>().as_ptr();
        unsafe { NonNull::new_unchecked(base.offset(offset)) }
    }

    /// Query for up to `nb` free entries.
    ///
    /// Serves small requests based on cached state about the kernel's consumer head. Large
    /// requests may thus incur an extra refresh of the consumer head.
    pub fn count_free(&mut self, mininmum: u32) -> u32 {
        let free_entries = self
            .inner
            .cached_consumer
            .wrapping_sub(self.inner.cached_producer);

        if free_entries >= mininmum {
            return free_entries;
        }

        self.inner.cached_consumer = self.inner.consumer.load(Ordering::Acquire);
        // No-op module the size, but ensures our view of the consumer is always ahead of the
        // producer, no matter buffer counts and mask.
        // TODO: actually, I don't _quite_ understand. This algorithm is copied from libxdp.
        self.inner.cached_consumer += self.inner.size;

        self.inner.cached_consumer - self.inner.cached_producer
    }

    /// Prepare consuming some buffers on our-side, not submitting to the kernel yet.
    ///
    /// Writes the index of the next available buffer into `idx`. Fails if less than the requested
    /// amount of buffers can be reserved. Returns the number of actual buffers reserved.
    pub fn reserve(&mut self, nb: RangeInclusive<u32>, idx: &mut BufIdx) -> u32 {
        let (start, end) = (*nb.start(), *nb.end());
        let free = self.count_free(start);

        if free < start {
            return 0;
        }

        let free = free.min(end);
        *idx = BufIdx(self.inner.cached_producer);
        self.inner.cached_producer += free;

        free
    }

    /// Cancel a previous `reserve`.
    ///
    /// If passed a smaller number, the remaining reservation stays active.
    pub fn cancel(&mut self, nb: u32) {
        self.inner.cached_producer -= nb;
    }

    /// Submit a number of buffers.
    ///
    /// Note: the client side state is _not_ adjusted. If you've called `reserve` before please
    /// check to maintain a consistent view.
    ///
    /// TODO: interestingly this could be implemented on a shared reference. But is doing so
    /// useful? There's no affirmation that the _intended_ buffers are submitted.
    pub fn submit(&mut self, nb: u32) {
        // We are the only writer, all other writes are ordered before.
        let cur = self.inner.producer.load(Ordering::Relaxed);
        // When the kernel reads it, all writes to buffers must be ordered before this write to the
        // head, this represents the memory synchronization edge.
        self.inner
            .producer
            .store(cur.wrapping_add(nb), Ordering::Release);
    }

    /// Get the raw difference between consumer and producer heads in shared memory.
    ///
    /// Both variables are loaded with _relaxed_ loads. No synchronization with any other memory
    /// operations is implied by calling this method. For this, you would need make sure to have
    /// some form of barrier, acquire on receiving and release on transmitting, for operations
    /// within chunks.
    pub fn count_pending(&self) -> u32 {
        let comitted = self.inner.producer.load(Ordering::Relaxed);
        let consumed = self.inner.consumer.load(Ordering::Relaxed);

        comitted.wrapping_sub(consumed)
    }

    /// Return the bits behind the `flags` register in the mmap.
    pub fn check_flags(&self) -> u32 {
        unsafe { *self.inner.flags.as_ptr() }
    }
}

impl RingCons {
    /// Create a completion ring.
    /// # Safety
    ///
    /// The caller must only pass `fd` and `off` if they correspond as they were returned by the
    /// kernel.
    pub(crate) unsafe fn comp(
        fd: &SocketFd,
        off: &SocketMmapOffsets,
        count: u32,
    ) -> Result<Self, XskError> {
        let (inner, mmap_addr) = XskRing::map(
            fd,
            &off.inner.cr,
            count,
            core::mem::size_of::<u64>() as u64,
            XDP_UMEM_PGOFF_COMPLETION_RING as i64,
        )?;

        Ok(Self { inner, mmap_addr })
    }

    /// Create a receive ring.
    /// # Safety
    ///
    /// The caller must only pass `fd` and `off` if they correspond as they were returned by the
    /// kernel.
    pub(crate) unsafe fn rx(
        fd: &SocketFd,
        off: &SocketMmapOffsets,
        count: u32,
    ) -> Result<Self, XskError> {
        let (inner, mmap_addr) = XskRing::map(
            fd,
            &off.inner.rx,
            count,
            core::mem::size_of::<xdp_desc>() as u64,
            XDP_PGOFF_RX_RING as i64,
        )?;

        Ok(Self { inner, mmap_addr })
    }

    /// Get a pointer to an address descriptor in the ring.
    ///
    /// # Safety
    ///
    /// This ring must be a Fill or Completion ring.
    pub unsafe fn comp_addr(&self, idx: BufIdx) -> NonNull<u64> {
        let offset = (idx.0 & self.inner.mask) as isize;
        let base = self.inner.ring.cast::<u64>().as_ptr();
        // Safety: all offsets within `self.inner.mask` are valid in our mmap.
        unsafe { NonNull::new_unchecked(base.offset(offset)) }
    }

    /// Get a pointer to an XDP frame descriptor in the ring.
    ///
    /// # Safety
    ///
    /// This ring must be a Receive or Transmit ring.
    pub unsafe fn rx_desc(&self, idx: BufIdx) -> NonNull<xdp_desc> {
        let offset = (idx.0 & self.inner.mask) as isize;
        let base = self.inner.ring.cast::<xdp_desc>().as_ptr();
        // Safety: all offsets within `self.inner.mask` are valid in our mmap.
        unsafe { NonNull::new_unchecked(base.offset(offset)) }
    }

    /// Find the number of available entries.
    ///
    /// Any count lower than `expected` will try to refresh the consumer.
    pub fn count_available(&mut self, expected: u32) -> u32 {
        let mut available = self
            .inner
            .cached_producer
            .wrapping_sub(self.inner.cached_consumer);

        if available < expected {
            let new_val = self.inner.producer.load(Ordering::Relaxed);
            available = new_val.wrapping_sub(self.inner.cached_consumer);
            self.inner.cached_producer = self.inner.producer.load(Ordering::Acquire);
        }

        available
    }

    /// Get the raw difference between consumer and producer heads in shared memory.
    ///
    /// Both variables are loaded with _relaxed_ loads. No synchronization with any other memory
    /// operations is implied by calling this method. For this, you would need make sure to have
    /// some form of barrier, acquire on receiving and release on transmitting, for operations
    /// within chunks.
    pub fn count_pending(&self) -> u32 {
        let available = self.inner.producer.load(Ordering::Relaxed);
        let consumed = self.inner.consumer.load(Ordering::Relaxed);

        available.wrapping_sub(consumed)
    }

    pub(crate) fn peek(&mut self, nb: RangeInclusive<u32>, idx: &mut BufIdx) -> u32 {
        let (start, end) = (*nb.start(), *nb.end());
        let count = self.count_available(start);

        if count < start {
            return 0;
        }

        let count = count.min(end);
        *idx = BufIdx(self.inner.cached_consumer);
        self.inner.cached_consumer += count;

        count
    }

    /// Cancel a previous `peek`.
    ///
    /// If passed a smaller number, the remaining reservation stays active.
    pub fn cancel(&mut self, nb: u32) {
        self.inner.cached_consumer -= nb;
    }

    /// Mark some buffers as processed.
    ///
    /// TODO: interestingly this could be implemented on a shared reference. But is doing so
    /// useful? There's no affirmation that the _intended_ buffers are submitted.
    pub fn release(&mut self, nb: u32) {
        // We are the only writer, all other writes are ordered before.
        let cur = self.inner.consumer.load(Ordering::Relaxed);
        // All our reads from buffers must be ordered before this write to the head, this
        // represents the memory synchronization edge.
        self.inner
            .consumer
            .store(cur.wrapping_add(nb), Ordering::Release);
    }

    /// Return the flags, as indicated by the kernel in shared memory.
    pub fn check_flags(&self) -> u32 {
        unsafe { *self.inner.flags.as_ptr() }
    }
}

impl Drop for RingProd {
    fn drop(&mut self) {
        let len = super::ptr_len(self.mmap_addr.as_ptr());
        unsafe { libc::munmap(self.mmap_addr.as_ptr() as *mut _, len) };
    }
}

impl Drop for RingCons {
    fn drop(&mut self) {
        let len = super::ptr_len(self.mmap_addr.as_ptr());
        unsafe { libc::munmap(self.mmap_addr.as_ptr() as *mut _, len) };
    }
}

// Safety; `NonNull` here controls an `mmap`. All other values are almost trivally safe to send to
// a different thread. Indeed, we hold no shared reference `&_` to any non-´Sync` resource which
// makes this sound by definition.
unsafe impl Send for XskRing {}
unsafe impl Send for RingProd {}
unsafe impl Send for RingCons {}
