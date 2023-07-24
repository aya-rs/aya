use aya::include_bytes_aligned;

pub const EXT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ext.bpf.o"));
pub const MAIN: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/main.bpf.o"));
pub const MULTIMAP_BTF: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/multimap-btf.bpf.o"));
pub const TEXT_64_64_RELOC: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/text_64_64_reloc.o"));

pub const LOG: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/log"));
pub const MAP_TEST: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/map_test"));
pub const NAME_TEST: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/name_test"));
pub const PASS: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/pass"));
pub const TEST: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/test"));
pub const RELOCATIONS: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/relocations"));
pub const TWO_PROGS: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/two_progs"));
pub const BPF_PROBE_READ: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bpf_probe_read"));

#[cfg(test)]
mod tests;
