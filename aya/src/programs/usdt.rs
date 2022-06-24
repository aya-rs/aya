//! User statically-defined tracepoints.
use aya_common::{UsdtSpec, USDT_MAX_SPEC_COUNT};
use libc::pid_t;
use object::{elf::*, read::elf::*, Endianness};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    ffi::CStr,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

use crate::{
    generated::{bpf_prog_type::BPF_PROG_TYPE_KPROBE, BPF_NOEXIST},
    maps::{MapError, MapRefMut},
    programs::{
        define_link_wrapper, load_program,
        perf_attach::{perf_attach, PerfLinkIdInner, PerfLinkInner},
        probe::create_as_probe,
        utils::{ProcMap, ProcMapError, LD_SO_CACHE, LD_SO_CACHE_FILE},
        Link, OwnedLink, ProbeKind, ProgramData, ProgramError,
    },
    Pod, FEATURES,
};

unsafe impl Pod for UsdtSpec {}

/// Name of the map used for USDT specs.
pub const USDT_SPEC_MAP: &str = "__bpf_usdt_specs";
/// Name of the map used for USDT to IP mappings.
pub const USDT_IP_TO_SPEC_MAP: &str = "__bpf_usdt_ip_to_spec_id";

/// A user statically-defined tracepoint
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct Usdt {
    pub(crate) data: ProgramData<UsdtLink>,
}

impl Usdt {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// Attaches the uprobe to the tracepoint `tp_provider`/`tp_name` defined in the `target`.
    /// If `pid` is not `None`, the program executes only when the target
    /// function is executed by the given `pid`.
    ///
    /// The `target` argument can be an absolute path to a binary or library, or
    /// a library name (eg: `"libc"`).
    ///
    /// The returned value can be used to detach, see [Usdt::detach].
    pub fn attach<T: AsRef<Path>>(
        &mut self,
        mut spec_map: crate::maps::Array<MapRefMut, UsdtSpec>,
        mut ip_to_spec_map: crate::maps::HashMap<MapRefMut, i64, u32>,
        tp_provider: &str,
        tp_name: &str,
        target: T,
        pid: Option<pid_t>,
    ) -> Result<UsdtLinkId, ProgramError> {
        let target = target.as_ref();
        let target_str = &*target.as_os_str().to_string_lossy();

        let mut path = if let Some(pid) = pid {
            let proc_map_libs =
                ProcMap::new(pid).map_err(|e| UsdtError::ProcMapError { pid, source: e })?;
            proc_map_libs
                .find_by_name(target_str)
                .map_err(|io_error| UsdtError::FileError {
                    filename: format!("/proc/{}/maps", pid),
                    io_error,
                })?
        } else {
            None
        };

        if path.is_none() {
            path = if target.is_absolute() {
                Some(target_str)
            } else {
                let cache = LD_SO_CACHE
                    .as_ref()
                    .map_err(|error| UsdtError::InvalidLdSoCache {
                        io_error: error.clone(),
                    })?;
                cache.resolve(target_str)
            }
            .map(String::from)
        };

        let path = path.ok_or(UsdtError::InvalidTarget {
            path: target.to_owned(),
        })?;

        let tracepoints = collect_usdts(&path, tp_provider, tp_name, pid)?;
        let mut perf_links = vec![];
        let mut spec_ids = VecDeque::with_capacity(USDT_MAX_SPEC_COUNT as usize);
        for i in 0..USDT_MAX_SPEC_COUNT {
            spec_ids.push_back(i)
        }
        let mut spec_id_map = HashMap::new();
        for t in tracepoints {
            let id = if spec_id_map.contains_key(&t.args) {
                *(spec_id_map.get(&t.args).unwrap())
            } else {
                let id = spec_ids.pop_front().unwrap();
                spec_id_map.insert(t.args.clone(), id);
                spec_map.set(id, t.spec, 0)?;
                id
            };
            let mut cookie = Some(id as u64);
            if !FEATURES.bpf_cookie {
                cookie.take();
                if let Err(e) =
                    ip_to_spec_map.insert(t.abs_ip.try_into().unwrap(), id, BPF_NOEXIST.into())
                {
                    if let MapError::SyscallError { code, .. } = e {
                        if code != (-libc::EEXIST).into() {
                            return Err(ProgramError::MapError(e));
                        }
                    }
                }
            }
            let fd = create_as_probe(ProbeKind::UProbe, &path, t.rel_ip, pid, Some(t.sem_off))?;
            let link = perf_attach(self.data.fd_or_err()?, fd, cookie)?;
            perf_links.push(link);
        }
        let link = UsdtLink(MultiPerfLink { perf_links });
        self.data.links.insert(link)
    }

    /// Detaches the program.
    ///
    /// See [UProbe::attach].
    pub fn detach(&mut self, link_id: UsdtLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: UsdtLinkId) -> Result<OwnedLink<UsdtLink>, ProgramError> {
        Ok(OwnedLink::new(self.data.take_link(link_id)?))
    }
}

/// The identifer of a MultiPerfLink.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct MultiPerfLinkId(Vec<PerfLinkIdInner>);

/// The attachment type of USDT programs.
#[derive(Debug)]
pub struct MultiPerfLink {
    perf_links: Vec<PerfLinkInner>,
}

impl Link for MultiPerfLink {
    type Id = MultiPerfLinkId;

    fn id(&self) -> Self::Id {
        let ids = self.perf_links.iter().map(|p| p.id()).collect();
        MultiPerfLinkId(ids)
    }

    fn detach(self) -> Result<(), ProgramError> {
        for l in self.perf_links {
            l.detach()?;
        }
        Ok(())
    }
}

define_link_wrapper!(
    /// The link used by [Usdt] programs.
    UsdtLink,
    /// The type returned by [Usdt::attach]. Can be passed to [Usdt::detach].
    UsdtLinkId,
    MultiPerfLink,
    MultiPerfLinkId
);

/// The type returned when attaching an [`UProbe`] fails.
#[derive(Debug, Error)]
pub enum UsdtError {
    /// There was an error parsing `/etc/ld.so.cache`.
    #[error("error reading `{}` file", LD_SO_CACHE_FILE)]
    InvalidLdSoCache {
        /// the original [`io::Error`]
        #[source]
        io_error: Arc<io::Error>,
    },

    /// The target program could not be found.
    #[error("could not resolve uprobe target `{path}`")]
    InvalidTarget {
        /// path to target
        path: PathBuf,
    },

    /// There was an error resolving the target symbol.
    #[error("error resolving symbol")]
    SymbolError {
        /// symbol name
        symbol: String,
        /// the original error
        #[source]
        error: Box<dyn std::error::Error + Send + Sync>,
    },

    /// There was an error accessing `filename`.
    #[error("`{filename}`")]
    FileError {
        /// The file name
        filename: String,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },

    /// There was en error resolving a path
    #[error("error fetching libs for {pid}")]
    ProcMapError {
        /// The pid
        pid: i32,
        /// The [`ProcMapError`] that caused the error
        #[source]
        source: ProcMapError,
    },

    /// Unsupported file type
    #[error("unsupported file type")]
    Unsupported,

    /// An [`io::Error`]
    #[error("io error")]
    Io(#[from] io::Error),

    /// An [`object::Error`]
    #[error("error parsing ELF")]
    Object(#[from] object::Error),

    /// Can't find matching offset in shard libs
    #[error("can't find matching offset in shared libs")]
    OffsetError,

    /// Section is not executable
    #[error("section is not executable")]
    NoExec,

    /// Segment is not found
    #[error("segment not found")]
    SegmentNotFound,

    /// BPF Cookies are not supported
    #[error("bpf cookies are required to support attachment without a pid")]
    NoCookie,
}

fn collect_usdts(
    path: &str,
    provider: &str,
    name: &str,
    pid: Option<pid_t>,
) -> Result<Vec<UsdtTarget>, UsdtError> {
    let file = fs::read(path)?;
    let data = &*file;
    if let Ok(elf) = object::elf::FileHeader32::parse(data) {
        if mem::size_of::<usize>() != 4 {
            return Err(UsdtError::Unsupported);
        }
        return collect_usdts_from_elf(elf, data, provider, name, pid);
    } else if let Ok(elf) = object::elf::FileHeader64::parse(data) {
        if mem::size_of::<usize>() != 8 {
            return Err(UsdtError::Unsupported);
        }
        return collect_usdts_from_elf(elf, data, provider, name, pid);
    }
    Err(UsdtError::Unsupported)
}

fn collect_usdts_from_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
    provider: &str,
    name: &str,
    pid: Option<pid_t>,
) -> Result<Vec<UsdtTarget>, UsdtError> {
    let endian = elf.endian()?;
    let sections = elf.sections(endian, data)?;
    let program_headers = elf.program_headers(endian, data)?;
    let mut results = vec![];
    let mut base_addr: Option<u64> = None;
    if let Some((_, base_section)) = sections.section_by_name(endian, b".stapsdt.base") {
        base_addr = Some(base_section.sh_addr(endian).into())
    };
    if let Some((_, notes_section)) = sections.section_by_name(endian, b".note.stapsdt") {
        if let Some(mut notes) = notes_section.notes(endian, data)? {
            while let Ok(Some(note)) = notes.next() {
                if note.name() != b"stapsdt" {
                    continue;
                }
                if note.n_type(endian) != 3 {
                    continue;
                }
                let note_data = note.desc();
                let n = UsdtNote::parse(endian, note_data)?;
                if n.provider != provider || n.name != name {
                    continue;
                }

                let mut abs_ip = n.loc_addr;
                if let Some(addr) = base_addr {
                    abs_ip += addr - n.base_addr;
                }

                let seg = find_segment_by_address::<Elf>(program_headers, endian, abs_ip)
                    .ok_or(UsdtError::SegmentNotFound)?;
                if seg.p_flags(endian) & PF_X == 0 {
                    return Err(UsdtError::NoExec);
                }
                let rel_ip = abs_ip - seg.p_vaddr(endian).into() + seg.p_offset(endian).into();

                // If attaching to a sharef library and bpf cookies are not supported.
                // Abs address of attach points are required
                if elf.e_type(endian) == ET_DYN && !FEATURES.bpf_cookie {
                    if pid.is_none() {
                        return Err(UsdtError::NoCookie);
                    }
                    let proc_map_libs =
                        ProcMap::new(pid.unwrap()).map_err(|e| UsdtError::ProcMapError {
                            pid: pid.unwrap(),
                            source: e,
                        })?;
                    let res = proc_map_libs
                        .find_by_offset(rel_ip)
                        .ok_or(UsdtError::OffsetError)?;
                    abs_ip = res.address - res.offset + rel_ip;
                }

                let mut sem_off = 0;
                if n.sem_addr != 0x0 {
                    // semaphore refcnt support was in 4.20, which is min supported version so we assume its supported
                    let seg = find_segment_by_address::<Elf>(program_headers, endian, n.sem_addr)
                        .ok_or(UsdtError::SegmentNotFound)?;
                    if seg.p_flags(endian) & PF_X == 0 {
                        return Err(UsdtError::NoExec);
                    }
                    sem_off = n.sem_addr - seg.p_vaddr(endian).into() + seg.p_offset(endian).into();
                }
                let spec = n.args.parse().unwrap();
                results.push(UsdtTarget {
                    abs_ip,
                    rel_ip,
                    sem_off,
                    args: n.args,
                    spec,
                })
            }
        }
    }
    Ok(results)
}

fn find_segment_by_address<Elf: FileHeader<Endian = Endianness>>(
    program_headers: &[Elf::ProgramHeader],
    endian: Endianness,
    addr: u64,
) -> Option<&Elf::ProgramHeader> {
    for header in program_headers {
        if header.p_vaddr(endian).into() < addr
            && addr < (header.p_vaddr(endian).into() + header.p_memsz(endian).into())
        {
            return Some(header);
        }
    }
    None
}

#[derive(Debug)]
pub(crate) struct UsdtTarget {
    abs_ip: u64,
    rel_ip: u64,
    sem_off: u64,
    args: String,
    spec: UsdtSpec,
}

#[derive(Debug)]
pub(crate) struct UsdtNote {
    loc_addr: u64,
    base_addr: u64,
    sem_addr: u64,
    provider: String,
    name: String,
    args: String,
}

impl UsdtNote {
    pub(crate) fn parse(endianness: Endianness, data: &[u8]) -> Result<UsdtNote, UsdtError> {
        let mut cursor = Cursor::new(data);
        let read_u64 = |cursor: &mut Cursor<_>| -> Result<u64, io::Error> {
            let mut buf = [0u8; mem::size_of::<u64>()];
            cursor.read_exact(&mut buf)?;
            match endianness {
                Endianness::Big => Ok(u64::from_be_bytes(buf)),
                Endianness::Little => Ok(u64::from_le_bytes(buf)),
            }
        };
        let read_string = |cursor: &mut Cursor<_>| -> Result<String, io::Error> {
            let mut buf = vec![];
            cursor.read_until(b'\0', &mut buf)?;
            Ok(CStr::from_bytes_with_nul(&buf)
                .unwrap()
                .to_string_lossy()
                .to_string())
        };
        let loc_addr = read_u64(&mut cursor)?;
        let base_addr = read_u64(&mut cursor)?;
        let sem_addr = read_u64(&mut cursor)?;
        let provider = read_string(&mut cursor)?;
        let name = read_string(&mut cursor)?;
        let args = read_string(&mut cursor)?;

        let res = UsdtNote {
            loc_addr,
            base_addr,
            sem_addr,
            provider,
            name,
            args,
        };
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_stapsdt() {
        /*
        /usr/bin/mariadb:     file format elf64-x86-64

        Contents of section .note.stapsdt:
         0000 08000000 34000000 03000000 73746170  ....4.......stap
         0010 73647400 34a10d00 00000000 382e3600  sdt.4.......8.6.
         0020 00000000 00000000 00000000 6c696267  ............libg
         0030 63630075 6e77696e 64003840 25726469  cc.unwind.8@%rdi
         0040 20384025 72736900                     8@%rsi
        */
        let data: &[u8] = &[
            0x34, 0xa1, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x2e, 0x36, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x69, 0x62, 0x67,
            0x63, 0x63, 0x00, 0x75, 0x6e, 0x77, 0x69, 0x6e, 0x64, 0x00, 0x38, 0x40, 0x25, 0x72,
            0x64, 0x69, 0x20, 0x38, 0x40, 0x25, 0x72, 0x73, 0x69, 0x00,
        ];
        let n = UsdtNote::parse(Endianness::Little, data).unwrap();
        assert_eq!(n.loc_addr, 0xda134);
        assert_eq!(n.base_addr, 0x362e38);
        assert_eq!(n.sem_addr, 0x0);
        assert_eq!(n.provider, "libgcc");
        assert_eq!(n.name, "unwind");
        assert_eq!(n.args, "8@%rdi 8@%rsi");
    }
}
