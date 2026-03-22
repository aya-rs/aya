use core::{borrow::Borrow, ptr};

use aya_ebpf_cty::c_long;

use crate::{
    btf_maps::btf_map_def,
    helpers::{bpf_map_peek_elem, bpf_map_push_elem},
};

btf_map_def!(
    /// A BTF-compatible BPF bloom filter map.
    ///
    /// Bloom filters are keyless maps. `HASH_FUNCS` encodes the low 4 bits of
    /// `map_extra`, so it must fit in `0..=15`. `0` delegates to the kernel
    /// default of 5 hash functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::BloomFilter, macros::btf_map};
    ///
    /// #[btf_map]
    /// static FILTER: BloomFilter<u32, 64, 0, 3> = BloomFilter::new();
    /// ```
    pub struct BloomFilter<T; const MAX_ENTRIES: usize, const FLAGS: usize = 0, const HASH_FUNCS: usize = 0>,
    map_type: BPF_MAP_TYPE_BLOOM_FILTER,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: (),
    value_type: T,
    map_extra: *const [i32; HASH_FUNCS],
);

impl<T, const MAX_ENTRIES: usize, const FLAGS: usize, const HASH_FUNCS: usize>
    BloomFilter<T, MAX_ENTRIES, FLAGS, HASH_FUNCS>
{
    #[inline(always)]
    pub fn contains(&self, value: impl Borrow<T>) -> Result<(), c_long> {
        let value = ptr::from_ref(value.borrow());
        match unsafe { bpf_map_peek_elem(self.as_ptr(), value.cast_mut().cast()) } {
            0 => Ok(()),
            ret => Err(ret),
        }
    }

    #[inline(always)]
    pub fn insert(&self, value: impl Borrow<T>, flags: u64) -> Result<(), c_long> {
        let value = ptr::from_ref(value.borrow());
        match unsafe { bpf_map_push_elem(self.as_ptr(), value.cast(), flags) } {
            0 => Ok(()),
            ret => Err(ret),
        }
    }
}
