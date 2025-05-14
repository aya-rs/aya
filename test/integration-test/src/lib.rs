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
    RELOC_BPF => "reloc.bpf.o",
    RELOC_BTF => "reloc.bpf.target.o",
    TEXT_64_64_RELOC => "text_64_64_reloc.o",
    VARIABLES_RELOC => "variables_reloc.bpf.o",

    BPF_PROBE_READ => "bpf_probe_read",
    LOG => "log",
    MAP_TEST => "map_test",
    MEMMOVE_TEST => "memmove_test",
    NAME_TEST => "name_test",
    PASS => "pass",
    RAW_TRACEPOINT => "raw_tracepoint",
    REDIRECT => "redirect",
    RELOCATIONS => "relocations",
    RING_BUF => "ring_buf",
    SIMPLE_PROG => "simple_prog",
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
