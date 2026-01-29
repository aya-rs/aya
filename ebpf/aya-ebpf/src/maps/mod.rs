pub(crate) mod def {
    use core::cell::UnsafeCell;

    use aya_ebpf_cty::c_void;

    use crate::bindings::bpf_map_def;

    #[repr(u32)]
    pub(crate) enum PinningType {
        None = 0,
        ByName = 1,
    }

    #[repr(transparent)]
    pub(crate) struct MapDef(UnsafeCell<bpf_map_def>);

    unsafe impl Sync for MapDef {}

    impl MapDef {
        /// Creates a new map definition with key type `K` and value type `V`.
        pub(crate) const fn new<K, V>(
            type_: u32,
            max_entries: u32,
            map_flags: u32,
            pinning: PinningType,
        ) -> Self {
            let key_size = size_of::<K>() as u32;
            let value_size = size_of::<V>() as u32;
            Self(UnsafeCell::new(bpf_map_def {
                type_,
                key_size,
                value_size,
                max_entries,
                map_flags,
                id: 0,
                pinning: pinning as u32,
            }))
        }

        pub(crate) const fn as_ptr(&self) -> *mut c_void {
            self.0.get().cast()
        }
    }
}

pub(crate) use def::{MapDef, PinningType};

macro_rules! map_constructors {
    (
        $key:ty,
        $value:ty,
        $map_type:expr
        $(, extra_flags $extra_flags:expr)?
        $(, phantom $phantom:ident)?
        $(, with_docs { $($with_doc:tt)* })?
        $(, pinned_docs { $($pinned_doc:tt)* })?
        $(,)?
    ) => {
        $($($with_doc)*)?
        pub const fn with_max_entries(max_entries: u32, flags: u32) -> Self {
            Self::new(max_entries, flags, PinningType::None)
        }

        $($($pinned_doc)*)?
        pub const fn pinned(max_entries: u32, flags: u32) -> Self {
            Self::new(max_entries, flags, PinningType::ByName)
        }

        const fn new(max_entries: u32, flags: u32, pinning: PinningType) -> Self {
            $(let flags = flags | $extra_flags;)?
            Self {
                def: MapDef::new::<$key, $value>($map_type, max_entries, flags, pinning),
                $($phantom: core::marker::PhantomData,)?
            }
        }
    };
}

pub mod array;
pub mod array_of_maps;
pub mod bloom_filter;
pub mod hash_map;
pub mod hash_of_maps;
pub mod lpm_trie;
pub mod per_cpu_array;
pub mod perf;
pub mod program_array;
pub mod queue;
pub mod ring_buf;
pub mod sock_hash;
pub mod sock_map;
pub mod stack;
pub mod stack_trace;
pub mod xdp;

pub use array::Array;
pub use array_of_maps::ArrayOfMaps;
pub use bloom_filter::BloomFilter;
pub use hash_map::{HashMap, LruHashMap, LruPerCpuHashMap, PerCpuHashMap};
pub use hash_of_maps::HashOfMaps;
pub use lpm_trie::LpmTrie;
pub use per_cpu_array::PerCpuArray;
pub use perf::{PerfEventArray, PerfEventByteArray};
pub use program_array::ProgramArray;
pub use queue::Queue;
pub use ring_buf::RingBuf;
pub use sock_hash::SockHash;
pub use sock_map::SockMap;
pub use stack::Stack;
pub use stack_trace::StackTrace;
pub use xdp::{CpuMap, DevMap, DevMapHash, XskMap};

mod private {
    /// Sealed trait to prevent external implementations of [`super::Map`].
    #[expect(
        unnameable_types,
        reason = "sealed trait pattern requires pub trait in private mod"
    )]
    pub trait Map {}
}

/// Marker trait for all eBPF maps that can be used in a map of maps.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait Map: private::Map {}

impl<T: private::Map> Map for T {}
