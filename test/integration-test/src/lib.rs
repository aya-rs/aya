macro_rules! bpf_file {
    ($($uppercase:ident => $lowercase:literal),* $(,)?) => {
        $(
            pub const $uppercase: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/", $lowercase));
        )*
    };
}

bpf_file!(
    EXT => "ext.bpf.o",
    ITER_TASK => "iter.bpf.o",
    MAIN => "main.bpf.o",
    MULTIMAP_BTF => "multimap-btf.bpf.o",
    KCONFIG => "kconfig.bpf.o",
    KCONFIG_MISSING_STRONG => "kconfig_missing_strong.bpf.o",
    KCONFIG_UNKNOWN_WEAK => "kconfig_unknown_weak.bpf.o",
    KCONFIG_UNSIGNED_U8 => "kconfig_unsigned_u8.bpf.o",
    KCONFIG_SIGNED_I8 => "kconfig_signed_i8.bpf.o",
    KCONFIG_INVALID_BOOL => "kconfig_invalid_bool.bpf.o",
    KCONFIG_INVALID_ARRAY => "kconfig_invalid_array.bpf.o",
    KCONFIG_NON_TRISTATE_ENUM => "kconfig_non_tristate_enum.bpf.o",
    RINGBUF_BTF => "ringbuf-btf.bpf.o",

    ENUM_SIGNED_32_RELOC_BPF => "enum_signed_32_reloc.bpf.o",
    ENUM_SIGNED_32_RELOC_BTF => "enum_signed_32_reloc.bpf.target.o",
    ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF => "enum_signed_32_checked_variants_reloc.bpf.o",
    ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BTF => "enum_signed_32_checked_variants_reloc.bpf.target.o",
    ENUM_SIGNED_64_RELOC_BPF => "enum_signed_64_reloc.bpf.o",
    ENUM_SIGNED_64_RELOC_BTF => "enum_signed_64_reloc.bpf.target.o",
    ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF => "enum_signed_64_checked_variants_reloc.bpf.o",
    ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BTF => "enum_signed_64_checked_variants_reloc.bpf.target.o",
    ENUM_UNSIGNED_32_RELOC_BPF => "enum_unsigned_32_reloc.bpf.o",
    ENUM_UNSIGNED_32_RELOC_BTF => "enum_unsigned_32_reloc.bpf.target.o",
    ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BPF => "enum_unsigned_32_checked_variants_reloc.bpf.o",
    ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BTF => "enum_unsigned_32_checked_variants_reloc.bpf.target.o",
    ENUM_UNSIGNED_64_RELOC_BPF => "enum_unsigned_64_reloc.bpf.o",
    ENUM_UNSIGNED_64_RELOC_BTF => "enum_unsigned_64_reloc.bpf.target.o",
    ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF => "enum_unsigned_64_checked_variants_reloc.bpf.o",
    ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BTF => "enum_unsigned_64_checked_variants_reloc.bpf.target.o",
    FIELD_RELOC_BPF => "field_reloc.bpf.o",
    FIELD_RELOC_BTF => "field_reloc.bpf.target.o",
    POINTER_RELOC_BPF => "pointer_reloc.bpf.o",
    POINTER_RELOC_BTF => "pointer_reloc.bpf.target.o",
    STRUCT_FLAVORS_RELOC_BPF => "struct_flavors_reloc.bpf.o",
    STRUCT_FLAVORS_RELOC_BTF => "struct_flavors_reloc.bpf.target.o",

    TEXT_64_64_RELOC => "text_64_64_reloc.o",
    VARIABLES_RELOC => "variables_reloc.bpf.o",

    ARRAY => "array",
    BLOOM_FILTER => "bloom_filter",
    BPF_PROBE_READ => "bpf_probe_read",
    BTF_MAPS_PLAIN => "btf_maps_plain",
    KPROBE => "kprobe",
    LINEAR_DATA_STRUCTURES => "linear_data_structures",
    LOG => "log",
    LPM_TRIE => "lpm_trie",
    MAP_TEST => "map_test",
    MEMMOVE_TEST => "memmove_test",
    NAME_TEST => "name_test",
    PASS => "pass",
    PER_CPU_ARRAY => "per_cpu_array",
    PERF_EVENT_BP => "perf_event_bp",
    RAW_TRACEPOINT => "raw_tracepoint",
    REDIRECT => "redirect",
    RELOCATIONS => "relocations",
    RING_BUF => "ring_buf",
    SIMPLE_PROG => "simple_prog",
    SK_REUSEPORT => "sk_reuseport",
    SK_STORAGE => "sk_storage",
    STRNCMP => "strncmp",
    TCX => "tcx",
    TEST => "test",
    TWO_PROGS => "two_progs",
    XDP_SEC => "xdp_sec",
    UPROBE_COOKIE => "uprobe_cookie",
    PRINTK_TEST => "printk_test",
    PROG_ARRAY => "prog_array",
);

#[cfg(test)]
mod tests;
#[cfg(test)]
mod utils;
