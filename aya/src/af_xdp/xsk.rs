//! XSK user-space ring implementation.
//!
//! Where it makes sense, some structs are bindings to a C header.

mod iface;
mod ring;
mod socket;
mod umem;
mod user;

use std::{
    num::NonZeroU32,
    ptr::NonNull,
    sync::{atomic::AtomicU32, Arc},
};

use aya_obj::generated::{xdp_mmap_offsets, xdp_ring_offset};
use libc::SOL_XDP;

pub use self::user::{ReadComplete, ReadRx, WriteFill, WriteTx};
use super::XskError;
use crate::af_xdp::AllocationError;

/// Internal structure shared for all rings.
///
/// TODO: copied from <xdp.h>, does everything make sense in Rust?
#[repr(C)]
#[derive(Debug)]
struct XskRing {
    /// _owned_ version of the producer head, may lag.
    cached_producer: u32,
    /// _owned_ version of the consumer head, may lag.
    cached_consumer: u32,
    /// Bit mask to quickly validate/force entry IDs.
    mask: u32,
    /// Number of entries (= mask + 1).
    size: u32,
    /// The mmaped-producer base.
    ///
    /// Note: Using lifetime static here, but we point into an `mmap` area and it is important that
    /// we do not outlive the binding. The constructor promises this.
    producer: &'static AtomicU32,
    /// The mmaped-consumer base.
    consumer: &'static AtomicU32,
    /// The mmaped-consumer ring control base.
    ring: NonNull<core::ffi::c_void>,
    /// The mmaped-consumer flags base.
    flags: NonNull<u32>,
}

/// Stuct for configuring the UMEM
#[derive(Debug, Clone)]
pub struct UmemConfig {
    /// Number of entries in the fill queue.
    pub fill_size: u32,
    /// Number of entries in the completion queue.
    pub complete_size: u32,
    /// Size of data chunks in each of the ring queues.
    pub frame_size: u32,
    /// Reserved area at the start of the kernel area.
    pub headroom: u32,
    /// Flags to set with the creation calls.
    pub flags: u32,
}

/// Wrapper around a socket file descriptor
pub(crate) struct SocketFd(libc::c_int);

/// Config for an XSK socket
#[derive(Debug, Default, Clone)]
pub struct SocketConfig {
    /// The number of receive descriptors in the ring.
    pub rx_size: Option<NonZeroU32>,
    /// The number of transmit descriptors in the ring.
    pub tx_size: Option<NonZeroU32>,
    /// Additional flags to pass to the `bind` call as part of `sockaddr_xdp`.
    pub bind_flags: u16,
}

/// Prior version of XdpMmapOffsets (<= Linux 5.3).
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub(crate) struct XdpRingOffsetsV1 {
    /// the relative address of the producer.
    pub producer: u64,
    /// the relative address of the consumer.
    pub consumer: u64,
    /// the relative address of the descriptor.
    pub desc: u64,
}

/// Prior version of XdpMmapOffsets (<= Linux 5.3).
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub(crate) struct XdpMmapOffsetsV1 {
    /// Offsets for the receive ring (kernel produced).
    pub rx: XdpRingOffsetsV1,
    /// Offsets for the transmit ring (user produced).
    pub tx: XdpRingOffsetsV1,
    /// Offsets for the fill ring (user produced).
    pub fr: XdpRingOffsetsV1,
    /// Offsets for the completion ring (kernel produced).
    pub cr: XdpRingOffsetsV1,
}

/// Represents a single frame extracted from the RX ring.
#[allow(dead_code)]
pub struct Frame<'a> {
    /// A slice of the frame's data.
    pub buffer: &'a [u8],
    /// The index of this frame in the ring.
    idx: BufIdx,
    /// A reference to the RX ring for releasing this frame later.
    ring: *mut RingRx,
}

impl Frame<'_> {
    /// Release this frame back to the kernel.
    pub fn release(self) {
        unsafe {
            (*self.ring).ring.release(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct SocketMmapOffsets {
    inner: xdp_mmap_offsets,
}

impl Default for SocketMmapOffsets {
    fn default() -> Self {
        Self {
            inner: xdp_mmap_offsets {
                rx: xdp_ring_offset {
                    producer: u64::default(),
                    consumer: u64::default(),
                    desc: u64::default(),
                    flags: u64::default(),
                },
                tx: xdp_ring_offset {
                    producer: u64::default(),
                    consumer: u64::default(),
                    desc: u64::default(),
                    flags: u64::default(),
                },
                fr: xdp_ring_offset {
                    producer: u64::default(),
                    consumer: u64::default(),
                    desc: u64::default(),
                    flags: u64::default(),
                },
                cr: xdp_ring_offset {
                    producer: u64::default(),
                    consumer: u64::default(),
                    desc: u64::default(),
                    flags: u64::default(),
                },
            },
        }
    }
}

/// The basic Umem descriptor.
///
/// This struct manages the buffers themselves, in a high-level sense, not any of the
/// communication or queues.
///
/// Compared to `libxdp` there's no link to where the queues are stored. Such a struct would necessitate
/// thread-safe access to the ring's producer and consumer queues. Instead, a `DeviceQueue` is the
/// owner of a device queue's fill/completion ring, but _not_ receive and transmission rings. All
/// other sockets with the same interface/queue depend on it but have their own packet rings.
///
/// You'll note that the fill ring and completion are a shared liveness requirement but under
/// unique control. Exactly one process has the responsibility of maintaining them and ensuring the
/// rings progress. Failing to do so impacts _all_ sockets sharing this `Umem`. The converse is not
/// true. A single socket can starve its transmission buffer or refuse accepting received packets
/// but the worst is packet loss in this queue.
///
/// The controller of the fill/completion pair also controls the associated bpf program which maps
/// packets onto the set of sockets (aka. 'XSKMAP').
pub struct Umem {
    /// The allocated shared memory region
    umem_buffer: NonNull<[u8]>,
    /// the config for the shared memory region
    config: UmemConfig,
    /// The socket
    fd: Arc<SocketFd>,
    /// wrapper around a `ControlSet`
    devices: DeviceControl,
}

/// A raw pointer to a specific chunk in a Umem.
///
/// It's unsafe to access the frame, by design. All aspects of _managing_ the contents of the
/// kernel-shared memory are left to the user of the module.
#[derive(Clone, Copy, Debug)]
pub struct UmemChunk {
    /// The address range associated with the chunk.
    pub addr: NonNull<[u8]>,
    /// The absolute offset of this chunk from the start of the Umem.
    /// This is the basis of the address calculation shared with the kernel.
    pub offset: u64,
}

#[derive(Clone)]
struct DeviceControl {
    inner: Arc<dyn ControlSet>,
}

/// A synchronized set for tracking which `IfCtx` are taken.
trait ControlSet: Send + Sync + 'static {
    fn insert(&self, _: IfCtx) -> bool;
    #[allow(dead_code)]
    fn contains(&self, _: &IfCtx) -> bool;
    fn remove(&self, _: &IfCtx);
}

/// One prepared socket for a receive/transmit pair.
///
/// Note: it is not yet _bound_ to a specific `AF_XDP` address (device queue).
pub struct Socket {
    /// Information about the socket
    info: Arc<IfInfo>,
    /// Socket file descriptor
    fd: Arc<SocketFd>,
}

/// One device queue associated with an XDP socket.
///
/// A socket is more specifically a set of receive and transmit queues for packets (mapping to some
/// underlying hardware mapping those bytes with a network). The fill and completion queue can, in
/// theory, be shared with other sockets of the same `Umem`.
pub struct DeviceQueue {
    /// Fill and completion queues.
    fcq: DeviceRings,
    /// This is also a socket.
    socket: Socket,
    /// Reference to de-register.
    devices: DeviceControl,
}

/// An owner of receive/transmit queues.
///
/// This represents a configured version of the raw `Socket`. It allows you to map the required
/// rings and _then_ [`Umem::bind`] the socket, enabling the operations of the queues with the
/// interface.
pub struct User {
    /// A clone of the socket it was created from.
    pub socket: Socket,
    /// The configuration with which it was created.
    config: Arc<SocketConfig>,
    /// A cached version of the map describing receive/tranmit queues.
    map: SocketMmapOffsets,
}

/// A receiver queue.
///
/// This also maintains the mmap of the associated queue.
// Implemented in <xsk/user.rs>
pub struct RingRx {
    ring: RingCons,
    fd: Arc<SocketFd>,
}

/// A transmitter queue.
///
/// This also maintains the mmap of the associated queue.
// Implemented in <xsk/user.rs>
pub struct RingTx {
    ring: RingProd,
    fd: Arc<SocketFd>,
}

/// A complete (cached) information about a socket.
///
/// Please allocate this, the struct is quite large. For instance, put it into an `Arc` as soon as
/// it is no longer mutable, or initialize it in-place with [`Arc::get_mut`].
#[derive(Clone, Copy)]
pub struct IfInfo {
    ctx: IfCtx,
    ifname: [libc::c_char; libc::IFNAMSIZ],
}

/// Reduced version of `IfCtx`, only retaining numeric IDs for the kernel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct IfCtx {
    ifindex: libc::c_uint,
    queue_id: u32,
    /// The namespace cookie, associated with a *socket*.
    /// This field is filled by some surrounding struct containing the info.
    netnscookie: u64,
}

pub(crate) struct DeviceRings {
    pub prod: RingProd,
    pub cons: RingCons,
    // Proof that we obtained this. Not sure if and where we'd use it.
    #[allow(dead_code)]
    pub(crate) map: SocketMmapOffsets,
}

/// An index to an XDP buffer.
///
/// Usually passed from a call of reserved or available buffers(in [`RingProd`] and
/// [`RingCons`] respectively) to one of the access functions. This resolves the raw index to a
/// memory address in the ring buffer.
///
/// This is _not_ a pure offset, a masking is needed to access the raw offset! The kernel requires
/// the buffer count to be a power-of-two for this to be efficient. Then, producer and consumer
/// heads operate on the 32-bit number range, _silently_ mapping to the same range of indices.
/// (Similar to TCP segments, actually). Well-behaving sides will maintain the order of the two
/// numbers in this wrapping space, which stays perfectly well-defined as long as less than `2**31`
/// buffer are identified in total.
///
/// In other words, you need a configured ring to determine an exact offset or compare two indices.
///
/// This type does _not_ implement comparison traits or hashing! Nevertheless, there's nothing
/// unsafe about creating or observing this detail, so feel free to construct your own or use the
/// transparent layout to (unsafely) treat the type as a `u32` instead.
#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct BufIdx(pub u32);

/// A producer ring.
///
/// Here, user space maintains the write head and the kernel the read tail.
#[derive(Debug)]
pub struct RingProd {
    inner: XskRing,
    mmap_addr: NonNull<[u8]>,
}

/// A consumer ring.
///
/// Here, kernel maintains the write head and user space the read tail.
#[derive(Debug)]
pub struct RingCons {
    inner: XskRing,
    mmap_addr: NonNull<[u8]>,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            fill_size: 1 << 11,
            complete_size: 1 << 11,
            frame_size: 1 << 12,
            headroom: 0,
            flags: 0,
        }
    }
}

impl Drop for SocketFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
    }
}

// FIXME: pending stabilization, use pointer::len directly.
// <https://doc.rust-lang.org/stable/std/primitive.pointer.html#method.len>
//
// FIXME: In 1.79 this was stabilized. Bump MSRV fine?
fn ptr_len(ptr: *mut [u8]) -> usize {
    unsafe { (*(ptr as *mut [()])).len() }
}

impl Socket {
    /// Get the raw file descriptor number underlying this socket.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.0
    }
}

impl User {
    /// Get the raw file descriptor number underlying this socket.
    pub fn as_raw_fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }
}

/// Builder struct for setting up a [`Umem`] shared with the kernel,
/// and a [`User`] to enable userspace operations on the rings and socket.
///
/// /// # Examples
///
/// ```no_run
/// # let mut bpf = Ebpf::load_file("ebpf_programs.o")?;
/// use aya::{Ebpf, programs::{Xdp, XdpFlags}};
///
/// let program: &mut Xdp = bpf.program_mut("intercept_packets").unwrap().try_into()?;
/// let mut socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();
/// program.attach("eth0", XdpFlags::default())?;
///
/// let (umem, user) = XdpSocketBuilder::new()
///     .with_iface("eth0") // The interface to attach to
///     .with_queue_id(0)
///     .with_umem_config(umem_config) // If not provided, a default one is used
///     .with_rx_size(NonZeroU32::new(32).unwrap()) // One of rx_size or tx_size must be nonzero
///     .build()
///     .unwrap();
///
/// let mut fq_cq = umem.fq_cq(&user.socket).unwrap(); // Fill Queue / Completion Queue
///
/// let mut rx = user.map_rx().unwrap(); // map the RX ring into memory, get handle
///
/// umem.bind(&user).unwrap(); // bind the socket to a device
///
/// socks.set(0, rx.as_raw_fd(), 0).unwrap(); // set the socket at the given index
///
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Default)]
pub struct XdpSocketBuilder {
    /// The interface name
    iface: Option<String>,
    queue_id: Option<u32>,
    /// Size of the RX queue
    rx_size: Option<NonZeroU32>,
    /// Size of the TX queue
    tx_size: Option<NonZeroU32>,
    umem_config: UmemConfig,
    bind_flags: u16,
    user_memory: Option<NonNull<[u8]>>,
    page_size: usize,
}

impl XdpSocketBuilder {
    /// Creates a new builder with default configurations.
    pub fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        Self {
            iface: None,
            queue_id: None,
            rx_size: None,
            tx_size: None,
            umem_config: UmemConfig::default(),
            bind_flags: 0, // Default bind flags
            user_memory: None,
            page_size,
        }
    }

    /// Sets the network interface name (e.g., "eth0").
    pub fn with_iface(mut self, iface: &str) -> Self {
        self.iface = Some(iface.to_string());
        self
    }

    /// Sets the queue ID for the socket.
    pub fn with_queue_id(mut self, queue_id: u32) -> Self {
        self.queue_id = Some(queue_id);
        self
    }

    /// Sets the RX ring size.
    pub fn with_rx_size(mut self, rx_size: NonZeroU32) -> Self {
        self.rx_size = Some(rx_size);
        self
    }

    /// Sets the TX ring size.
    pub fn with_tx_size(mut self, tx_size: NonZeroU32) -> Self {
        self.tx_size = Some(tx_size);
        self
    }

    /// Configures UMEM settings.
    pub fn with_umem_config(mut self, config: UmemConfig) -> Self {
        self.umem_config = config;
        self
    }

    /// Sets additional bind flags.
    pub fn with_bind_flags(mut self, flags: u16) -> Self {
        self.bind_flags = flags;
        self
    }

    /// Use user-provided memory for UMEM.
    ///
    /// # Safety
    /// The caller must ensure that the provided memory is valid, properly aligned, and large enough
    /// for the UMEM configuration (e.g., `frame_size * fill_size`).
    pub unsafe fn with_user_memory(mut self, mem: NonNull<[u8]>) -> Result<Self, XskError> {
        let addr = mem.as_ptr() as *mut u8 as usize;
        if addr & (self.page_size - 1) != 0 {
            return Err(AllocationError::UmemUnaligned.into()); // Memory must be page-aligned
        }

        if mem.len() < (self.umem_config.frame_size * self.umem_config.fill_size) as usize {
            return Err(AllocationError::UmemSize.into());
        }
        self.user_memory = Some(mem);
        Ok(self)
    }

    /// Allocate page-aligned memory for Umem.
    fn allocate_page_aligned_memory(&self, size: usize) -> Result<NonNull<[u8]>, XskError> {
        let aligned_mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };

        if aligned_mem == libc::MAP_FAILED {
            return Err(XskError::last_os_error());
        }

        Ok(unsafe {
            NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(
                aligned_mem as *mut u8,
                size,
            ))
        })
    }

    /// Builds and returns a configured `Socket` and its associated rings.
    ///
    /// If a user-allocated memory region is not provided, one will be allocated
    /// and used as the shared UMEM region.
    pub fn build(self) -> Result<(Umem, User), XskError> {
        let iface_name = self.iface.as_ref().ok_or(XskError::Errno {
            errno: libc::EINVAL,
        })?;

        // Create IfInfo from interface name
        let mut iface_info = IfInfo::invalid();
        iface_info.from_name(iface_name)?;

        // Set queue ID if provided
        if let Some(queue_id) = self.queue_id {
            iface_info.set_queue(queue_id);
        }

        // Check that at least one of rx_size or tx_size is Some
        if self.rx_size.is_none() && self.tx_size.is_none() {
            return Err(XskError::SocketOptionError(
                "both rx_size and tx_size are None".into(),
            ));
        }

        // Determine memory size based on UMEM configuration
        let mem_size = (self.umem_config.frame_size * self.umem_config.fill_size) as usize;

        // Use user-provided memory or allocate internally
        let mem = match self.user_memory {
            Some(mem) => mem,
            None => self.allocate_page_aligned_memory(mem_size)?,
        };
        // Allocate UMEM using the provided or allocated memory
        let umem = unsafe { Umem::new(self.umem_config.clone(), mem)? };

        // Create Socket
        let socket_config = SocketConfig {
            rx_size: self.rx_size,
            tx_size: self.tx_size,
            bind_flags: self.bind_flags,
        };

        let socket = Socket::with_shared(&iface_info, &umem)?;
        let rxtx = umem.rx_tx(&socket, &socket_config)?;

        Ok((umem, rxtx))
    }
}
