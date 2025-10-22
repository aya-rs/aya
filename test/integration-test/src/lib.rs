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
    BPF_PROBE_READ => "bpf_probe_read",
    LINEAR_DATA_STRUCTURES => "linear_data_structures",
    LOG => "log",
    MAP_TEST => "map_test",
    MEMMOVE_TEST => "memmove_test",
    NAME_TEST => "name_test",
    PASS => "pass",
    PERF_EVENT_BP => "perf_event_bp",
    RAW_TRACEPOINT => "raw_tracepoint",
    REDIRECT => "redirect",
    RELOCATIONS => "relocations",
    RING_BUF => "ring_buf",
    SIMPLE_PROG => "simple_prog",
    SK_STORAGE => "sk_storage",
    STRNCMP => "strncmp",
    TCX => "tcx",
    TEST => "test",
    TWO_PROGS => "two_progs",
    XDP_SEC => "xdp_sec",
    UPROBE_COOKIE => "uprobe_cookie",
);

#[cfg(test)]
mod tests;
#[cfg(test)]
mod utils;
