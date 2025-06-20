// use core::mem;
//
// use crate::bindings::bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER;

// #[allow(dead_code)]
// pub struct LpmTrieDef<K, V, const M: usize, const F: usize = 0> {
//     r#type: *const [i32; BPF_MAP_TYPE_BLOOM_FILTER as usize],
//     key_size: *const [i32; mem::size_of::<Key<K>>()],
//     value_size: *const [i32; mem::size_of::<V>()],
//     max_entries: *const [i32; M],
//     map_flags: *const [i32; F],
// }

#[repr(C, packed)]
pub struct Key<K> {
    /// Represents the number of bits matched against.
    pub prefix_len: u32,
    /// Represents arbitrary data stored in the LpmTrie.
    pub data: K,
}

impl<K> Key<K> {
    pub fn new(prefix_len: u32, data: K) -> Self {
        Self { prefix_len, data }
    }
}
