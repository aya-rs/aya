use core::borrow::Borrow;

use aya_ebpf_bindings::bindings::BPF_F_NO_PREALLOC;

pub use crate::maps::lpm_trie::Key;
use crate::{btf_maps::btf_map_def, insert, lookup, remove};

btf_map_def!(
    /// A BTF-compatible BPF LPM trie map.
    ///
    /// An LPM trie stores values keyed by an arbitrary-length prefix and
    /// supports longest-prefix-match lookups. A common use case is IP routing
    /// tables.
    ///
    /// # Minimum kernel version
    ///
    /// The minimum kernel version required to use this feature is 4.11.
    ///
    /// # `BPF_F_NO_PREALLOC`
    ///
    /// The kernel rejects LPM tries that do not set `BPF_F_NO_PREALLOC`. The
    /// default value of `FLAGS` already sets this bit. Callers that override
    /// `FLAGS` must keep `BPF_F_NO_PREALLOC` set or the map will fail to load
    /// with `EINVAL`.
    ///
    /// # Key layout
    ///
    /// Keys are instances of [`Key<K>`], a `#[repr(C, packed)]` struct whose
    /// first field is a `u32` prefix length (expressed in bits) and whose
    /// second field is the `K`-typed data to match.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aya_ebpf::{btf_maps::{LpmTrie, lpm_trie::Key}, macros::btf_map};
    ///
    /// #[btf_map]
    /// static ROUTES: LpmTrie<[u8; 4], u32, 1024> = LpmTrie::new();
    /// ```
    pub struct LpmTrie<K, V; const MAX_ENTRIES: usize, const FLAGS: usize = { BPF_F_NO_PREALLOC as usize }>,
    map_type: BPF_MAP_TYPE_LPM_TRIE,
    max_entries: MAX_ENTRIES,
    map_flags: FLAGS,
    key_type: Key<K>,
    value_type: V,
);

impl<K, V, const MAX_ENTRIES: usize, const FLAGS: usize> LpmTrie<K, V, MAX_ENTRIES, FLAGS> {
    // Enforces kernel constraints (kernel/bpf/lpm_trie.c) and value
    // alignment on the returned reference. `const _: ()` is forbidden in
    // a generic impl, and a named associated const is lazy without a
    // reference, hence `let () = Self::_CHECK` in every method.
    const _CHECK: () = {
        assert!(
            size_of::<Key<K>>() >= 5,
            "LPM trie key must be at least 5 bytes (prefix_len + one data byte).",
        );
        assert!(
            size_of::<Key<K>>() <= 260,
            "LPM trie key must be at most 260 bytes (prefix_len + 256 data bytes).",
        );
        assert!(
            size_of::<V>() >= 1,
            "LPM trie value must be non-zero sized.",
        );
        assert!(
            MAX_ENTRIES > 0,
            "LPM trie max_entries must be greater than zero."
        );
        // The kernel stores `V` at offset `size_of::<K>()` inside the trie
        // node data area (see `trie_lookup_elem` in kernel/bpf/lpm_trie.c,
        // which returns `found->data + trie->data_size`). Two conditions must
        // hold for the returned pointer to be naturally aligned for `V`:
        //
        // 1. The trie node's `data[]` base must be aligned to
        //    `align_of::<V>()`. `lpm_trie_node` contains an `rcu_head` and
        //    raw pointers, so its overall alignment is
        //    `align_of::<*mut ()>()`, which is 8 on 64-bit Linux. Values with
        //    stricter alignment would be under-aligned.
        // 2. The offset `size_of::<K>()` must be a multiple of
        //    `align_of::<V>()`.
        assert!(
            align_of::<V>() <= 8,
            "LPM trie value alignment must be at most 8 bytes.",
        );
        assert!(
            size_of::<K>().is_multiple_of(align_of::<V>()),
            "LPM trie value alignment requires size_of::<K>() to be a multiple of align_of::<V>().",
        );
    };

    /// Looks up the value for the longest prefix in the trie that matches `key`.
    ///
    /// Returns `None` if no prefix in the trie matches.
    #[inline(always)]
    pub fn get(&self, key: &Key<K>) -> Option<&V> {
        let () = Self::_CHECK;
        lookup(self.as_ptr(), key).map(|p| unsafe { p.as_ref() })
    }

    /// Inserts or updates the value for the exact `(prefix_len, data)` pair.
    #[inline(always)]
    pub fn insert(&self, key: &Key<K>, value: impl Borrow<V>, flags: u64) -> Result<(), i32> {
        let () = Self::_CHECK;
        insert(self.as_ptr(), key, value.borrow(), flags)
    }

    /// Removes the entry for the exact `(prefix_len, data)` pair.
    #[inline(always)]
    pub fn remove(&self, key: &Key<K>) -> Result<(), i32> {
        let () = Self::_CHECK;
        remove(self.as_ptr(), key)
    }
}
