use aya_obj::generated::xdp_desc;

use crate::af_xdp::{
    xsk::Frame, BufIdx, DeviceQueue, RingCons, RingProd, RingRx, RingTx, Umem, XskError,
};

impl DeviceQueue {
    /// Prepare some buffers for the fill ring.
    ///
    /// The argument is an upper bound of buffers. Use the resulting object to pass specific
    /// buffers to the fill queue and commit the write.
    pub fn fill(&mut self, max: u32) -> WriteFill<'_> {
        WriteFill {
            idx: BufIdxIter::reserve(&mut self.fcq.prod, max),
            queue: &mut self.fcq.prod,
        }
    }

    /// Reap some buffers from the completion ring.
    ///
    /// Return an iterator over completed buffers.
    ///
    /// The argument is an upper bound of buffers. Use the resulting object to dequeue specific
    /// buffers from the completion queue and commit the read.
    pub fn complete(&mut self, n: u32) -> ReadComplete<'_> {
        ReadComplete {
            idx: BufIdxIter::peek(&mut self.fcq.cons, n),
            queue: &mut self.fcq.cons,
        }
    }

    /// Return the difference between our the kernel's producer state and our consumer head.
    pub fn available(&self) -> u32 {
        self.fcq.cons.count_pending()
    }

    /// Return the difference between our committed consumer state and the kernel's producer state.
    pub fn pending(&self) -> u32 {
        self.fcq.prod.count_pending()
    }

    /// Get the raw file descriptor of this ring.
    ///
    /// # Safety
    ///
    /// Use the file descriptor to attach the ring to an XSK map, for instance, but do not close it
    /// and avoid modifying it (unless you know what you're doing). It should be treated as a
    /// `BorrowedFd<'_>`. That said, it's not instant UB but probably delayed UB when the
    /// `DeviceQueue` modifies a reused file descriptor that it assumes to own.
    pub fn as_raw_fd(&self) -> libc::c_int {
        self.socket.fd.0
    }

    /// Query if the fill queue needs to be woken to proceed receiving.
    ///
    /// This is only accurate if `Umem::XDP_BIND_NEED_WAKEUP` was set.
    pub fn needs_wakeup(&self) -> bool {
        self.fcq.prod.check_flags() & RingTx::XDP_RING_NEED_WAKEUP != 0
    }

    /// Poll the fill queue descriptor, to wake it up.
    pub fn wake(&mut self) {
        // A bit more complex than TX, here we do a full poll on the FD.
        let mut poll = libc::pollfd {
            fd: self.socket.fd.0,
            events: 0,
            revents: 0,
        };

        // FIXME: should somehow log this, right?
        let _err = unsafe { libc::poll(&mut poll as *mut _, 1, 0) };
    }
}

impl Drop for DeviceQueue {
    fn drop(&mut self) {
        self.devices.remove(&self.socket.info.ctx);
    }
}

impl RingRx {
    /// Receive some buffers.
    ///
    /// Returns an iterator over the descriptors.
    pub fn receive(&mut self, n: u32) -> ReadRx<'_> {
        ReadRx {
            idx: BufIdxIter::peek(&mut self.ring, n),
            queue: &mut self.ring,
        }
    }

    /// Query the number of available descriptors.
    ///
    /// This operation is advisory only. It performs a __relaxed__ atomic load of the kernel
    /// producer. An `acquire` barrier, such as performed by [`RingRx::receive`], is always needed
    /// before reading any of the written descriptors to ensure that these reads do not race with
    /// the kernel's writes.
    pub fn available(&self) -> u32 {
        self.ring.count_pending()
    }

    /// Get the raw file descriptor of this RX ring.
    ///
    /// # Safety
    ///
    /// Use the file descriptor to attach the ring to an XSK map, for instance, but do not close it
    /// and avoid modifying it (unless you know what you're doing). It should be treated as a
    /// `BorrowedFd<'_>`. That said, it's not instant UB but probably delayed UB when the `RingRx`
    /// modifies a reused file descriptor that it assumes to own...
    pub fn as_raw_fd(&self) -> libc::c_int {
        self.fd.0
    }

    /// Safely extract a frame descriptor from the RX ring.
    ///
    /// Returns a reference to the frame data if available, or `None` if no frames are ready.
    pub fn extract_frame<'a>(&mut self, umem: &'a Umem) -> Option<Frame<'a>> {
        // Check if there are any available descriptors
        if self.ring.count_available(1) < 1 {
            return None;
        }

        // Peek at the next descriptor
        let mut idx = BufIdx(0);
        let count = self.ring.peek(1..=1, &mut idx);
        if count == 0 {
            return None;
        }

        // Get the descriptor safely
        let desc = unsafe { self.ring.rx_desc(idx).as_ref() };

        // Calculate the frame address and length
        let addr = desc.addr as usize;
        let len = desc.len as usize;

        // Ensure that the address and length are within bounds
        let buffer = unsafe {
            umem.umem_buffer
                .as_ref()
                .get(addr..addr + len)
                .expect("Invalid frame bounds")
        };

        // Create a Frame abstraction
        Some(Frame {
            buffer,
            idx,
            ring: self,
        })
    }
}

impl RingTx {
    const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

    /// Transmit some buffers.
    ///
    /// Returns a proxy that can be fed descriptors.
    pub fn transmit(&mut self, n: u32) -> WriteTx<'_> {
        WriteTx {
            idx: BufIdxIter::reserve(&mut self.ring, n),
            queue: &mut self.ring,
        }
    }

    /// Return the difference between our committed producer state and the kernel's consumer head.
    pub fn pending(&self) -> u32 {
        self.ring.count_pending()
    }

    /// Query if the transmit queue needs to be woken to proceed receiving.
    ///
    /// This is only accurate if `Umem::XDP_BIND_NEED_WAKEUP` was set.
    pub fn needs_wakeup(&self) -> bool {
        self.ring.check_flags() & Self::XDP_RING_NEED_WAKEUP != 0
    }

    /// Send a message (with `MSG_DONTWAIT`) to wake up the transmit queue.
    pub fn wake(&self) {
        // FIXME: should somehow log this on failure, right?
        let _ = unsafe {
            libc::sendto(
                self.fd.0,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            )
        };
    }

    /// Get the raw file descriptor of this TX ring.
    ///
    /// # Safety
    ///
    /// Use the file descriptor to attach the ring to an XSK map, for instance, but do not close it
    /// and avoid modifying it (unless you know what you're doing). It should be treated as a
    /// `BorrowedFd<'_>`. That said, it's not instant UB but probably delayed UB when the
    /// `RingTx` modifies a reused file descriptor that it assumes to own (for instance, `wake`
    /// sends a message to it).
    pub fn as_raw_fd(&self) -> libc::c_int {
        self.fd.0
    }

    /// Submit a frame back to the kernel for transmission or reuse.
    pub fn submit_frame(&mut self, addr: u64) -> Result<(), XskError> {
        // Ensure there is space in the ring
        if self.ring.count_free(1) < 1 {
            return Err(XskError::Errno {
                errno: libc::ENOBUFS,
            });
        }

        // Reserve space in the ring
        let mut idx = BufIdx(0);
        self.ring.reserve(1..=1, &mut idx);

        // Write the address into the descriptor
        unsafe {
            *self.ring.fill_addr(idx).as_mut() = addr;
        }

        // Commit the submission
        self.ring.submit(1);

        Ok(())
    }
}

struct BufIdxIter {
    /// The base of our operation.
    base: BufIdx,
    /// The number of peeked buffers.
    buffers: u32,
    /// The number of buffers still left.
    remain: u32,
}

/// A writer to a fill queue.
///
/// Created with [`DeviceQueue::fill`].
///
/// The owner of this value should call some of the insertion methods in any order, then release
/// the writes by [`WriteFill::commit`] which performs an atomic release in the Umem queue.
#[must_use = "Does nothing unless the writes are committed"]
pub struct WriteFill<'queue> {
    idx: BufIdxIter,
    /// The queue we read from.
    queue: &'queue mut RingProd,
}

/// A reader from a completion queue.
///
/// Created with [`DeviceQueue::complete`].
///
/// The owner of this value should call some of the reader methods or iteration in any order, then
/// mark the reads by [`ReadComplete::release`], which performs an atomic release in the Umem
/// queue.
#[must_use = "Does nothing unless the reads are committed"]
pub struct ReadComplete<'queue> {
    idx: BufIdxIter,
    /// The queue we read from.
    queue: &'queue mut RingCons,
}

/// A writer to a transmission (TX) queue.
///
/// Created with [`RingTx::transmit`].
///
/// The owner of this value should call some of the insertion methods in any order, then release
/// the writes by [`WriteTx::commit`] which performs an atomic release in the Umem queue.
#[must_use = "Does nothing unless the writes are committed"]
pub struct WriteTx<'queue> {
    idx: BufIdxIter,
    /// The queue we read from.
    queue: &'queue mut RingProd,
}

/// A reader from an receive (RX) queue.
///
/// Created with [`RingRx::receive`].
///
/// The owner of this value should call some of the reader methods or iteration in any order, then
/// mark the reads by [`ReadRx::release`], which performs an atomic release in the Umem queue.
#[must_use = "Does nothing unless the reads are committed"]
pub struct ReadRx<'queue> {
    idx: BufIdxIter,
    /// The queue we read from.
    queue: &'queue mut RingCons,
}

impl Iterator for BufIdxIter {
    type Item = BufIdx;
    fn next(&mut self) -> Option<BufIdx> {
        let next = self.remain.checked_sub(1)?;
        self.remain = next;
        let ret = self.base;
        self.base.0 = self.base.0.wrapping_add(1);
        Some(ret)
    }
}

impl BufIdxIter {
    fn peek(queue: &mut RingCons, n: u32) -> Self {
        let mut this = Self {
            buffers: 0,
            remain: 0,
            base: BufIdx(0),
        };
        this.buffers = queue.peek(1..=n, &mut this.base);
        this.remain = this.buffers;
        this
    }

    fn reserve(queue: &mut RingProd, n: u32) -> Self {
        let mut this = Self {
            buffers: 0,
            remain: 0,
            base: BufIdx(0),
        };
        this.buffers = queue.reserve(1..=n, &mut this.base);
        this.remain = this.buffers;
        this
    }

    fn commit_prod(&mut self, queue: &mut RingProd) {
        // This contains an atomic write, which LLVM won't even try to optimize away.
        // But, as long as queues are filled there's a decent chance that we didn't manage to
        // reserve or fill a single buffer.
        //
        // FIXME: Should we expose this as a hint to the user? I.e. `commit_likely_empty` with a
        // hint. As well as better ways to avoid doing any work at all.
        if self.buffers > 0 {
            let count = self.buffers - self.remain;
            queue.submit(count);
            self.buffers -= count;
            self.base.0 += count;
        }
    }

    fn release_cons(&mut self, queue: &mut RingCons) {
        // See also `commit_prod`.
        if self.buffers > 0 {
            let count = self.buffers - self.remain;
            queue.release(count);
            self.buffers -= count;
            self.base.0 += count;
        }
    }
}

impl WriteFill<'_> {
    /// The total number of available slots.
    pub fn capacity(&self) -> u32 {
        self.idx.buffers
    }

    /// Fill one device descriptor to be filled.
    ///
    /// A descriptor is an offset in the respective Umem's memory. Any offset within a chunk can
    /// be used to mark the chunk as available for fill. The kernel will overwrite the contents
    /// arbitrarily until the chunk is returned via the RX queue.
    ///
    /// Returns if the insert was successful, that is false if the ring is full. It's guaranteed
    /// that the first [`WriteFill::capacity`] inserts with this function succeed.
    pub fn insert_once(&mut self, nr: u64) -> bool {
        self.insert(core::iter::once(nr)) > 0
    }

    /// Fill additional slots that were reserved.
    ///
    /// The iterator is polled only for each available slot until either is empty. Returns the
    /// total number of slots filled.
    pub fn insert(&mut self, it: impl Iterator<Item = u64>) -> u32 {
        let mut n = 0;
        for (item, bufidx) in it.zip(self.idx.by_ref()) {
            n += 1;
            unsafe { *self.queue.fill_addr(bufidx).as_ptr() = item };
        }
        n
    }

    /// Commit the previously written buffers to the kernel.
    pub fn commit(&mut self) {
        self.idx.commit_prod(self.queue)
    }
}

impl Drop for WriteFill<'_> {
    fn drop(&mut self) {
        // Unless everything is committed, roll back the cached queue state.
        if self.idx.buffers != 0 {
            self.queue.cancel(self.idx.buffers)
        }
    }
}

impl ReadComplete<'_> {
    /// The total number of available buffers.
    pub fn capacity(&self) -> u32 {
        self.idx.buffers
    }

    /// Read the next descriptor, an address of a chunk that was transmitted.
    pub fn read(&mut self) -> Option<u64> {
        let bufidx = self.idx.next()?;
        // Safety: the buffer is from that same queue by construction.
        Some(unsafe { *self.queue.comp_addr(bufidx).as_ptr() })
    }

    /// Commit some of the written buffers to the kernel.
    pub fn release(&mut self) {
        self.idx.release_cons(self.queue)
    }
}

impl Drop for ReadComplete<'_> {
    fn drop(&mut self) {
        // Unless everything is committed, roll back the cached queue state.
        if self.idx.buffers != 0 {
            self.queue.cancel(self.idx.buffers)
        }
    }
}

impl Iterator for ReadComplete<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        self.read()
    }
}

impl WriteTx<'_> {
    /// The total number of available slots.
    pub fn capacity(&self) -> u32 {
        self.idx.buffers
    }

    /// Insert a chunk descriptor to be sent.
    ///
    /// Returns if the insert was successful, that is false if the ring is full. It's guaranteed
    /// that the first [`WriteTx::capacity`] inserts with this function succeed.
    pub fn insert_once(&mut self, nr: xdp_desc) -> bool {
        self.insert(core::iter::once(nr)) > 0
    }

    /// Fill the transmit ring from an iterator.
    ///
    /// Returns the total number of enqueued descriptor. This is a `u32` as it is the common
    /// integral type for describing cardinalities of descriptors in a ring. Use an inspecting
    /// iterator for a more intrusive callback.
    pub fn insert(&mut self, it: impl Iterator<Item = xdp_desc>) -> u32 {
        let mut n = 0;
        // FIXME: incorrect iteration order? Some items may get consumed but not inserted.
        for (item, bufidx) in it.zip(self.idx.by_ref()) {
            n += 1;
            unsafe { *self.queue.tx_desc(bufidx).as_ptr() = item };
        }
        n
    }

    /// Commit the previously written buffers to the kernel.
    pub fn commit(&mut self) {
        self.idx.commit_prod(self.queue);
    }
}

impl Drop for WriteTx<'_> {
    fn drop(&mut self) {
        // Unless everything is committed, roll back the cached queue state.
        if self.idx.buffers != 0 {
            self.queue.cancel(self.idx.buffers)
        }
    }
}

impl ReadRx<'_> {
    /// The total number of available buffers.
    pub fn capacity(&self) -> u32 {
        self.idx.buffers
    }

    /// Read one descriptor from the receive ring.
    pub fn read(&mut self) -> Option<xdp_desc> {
        let bufidx = self.idx.next()?;
        // Safety: the buffer is from that same queue by construction, by assumption this is within
        // the valid memory region of the mapping.
        // FIXME: queue could validate that this is aligned.
        Some(unsafe { *self.queue.rx_desc(bufidx).as_ptr() })
    }

    /// Commit some of the written buffers to the kernel.
    pub fn release(&mut self) {
        self.idx.release_cons(self.queue)
    }
}

impl Drop for ReadRx<'_> {
    fn drop(&mut self) {
        // Unless everything is committed, roll back the cached queue state.
        if self.idx.buffers != 0 {
            self.queue.cancel(self.idx.buffers)
        }
    }
}

impl Iterator for ReadRx<'_> {
    type Item = xdp_desc;

    fn next(&mut self) -> Option<xdp_desc> {
        self.read()
    }
}
