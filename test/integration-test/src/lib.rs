use aya::include_bytes_aligned;

pub const EXT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ext.bpf.o"));
pub const MAIN: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/main.bpf.o"));
pub const MULTIMAP_BTF: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/multimap-btf.bpf.o"));
pub const TEXT_64_64_RELOC: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/text_64_64_reloc.o"));
