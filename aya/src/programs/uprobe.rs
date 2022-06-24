//! User space probes.
use libc::pid_t;
use object::{Object, ObjectSection, ObjectSymbol};
use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    ffi::CStr,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    num::ParseIntError,
    os::{fd::AsFd as _, raw::c_char},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;

use crate::{
    generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE},
    programs::{
        define_link_wrapper, load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        probe::{attach, ProbeKind},
        FdLink, LinkError, ProgramData, ProgramError,
    },
    sys::bpf_link_get_info_by_fd,
    VerifierLogLevel,
};

const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

lazy_static! {
    static ref LD_SO_CACHE: Result<LdSoCache, Arc<io::Error>> =
        LdSoCache::load(LD_SO_CACHE_FILE).map_err(Arc::new);
}
const LD_SO_CACHE_HEADER_OLD: &str = "ld.so-1.7.0\0";
const LD_SO_CACHE_HEADER_NEW: &str = "glibc-ld.so.cache1.1";

/// An user space probe.
///
/// User probes are eBPF programs that can be attached to any userspace
/// function. They can be of two kinds:
///
/// - `uprobe`: get attached to the *start* of the target functions
/// - `uretprobe`: get attached to the *return address* of the target functions
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_KPROBE")]
pub struct UProbe {
    pub(crate) data: ProgramData<UProbeLink>,
    pub(crate) kind: ProbeKind,
}

impl UProbe {
    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Returns `UProbe` if the program is a `uprobe`, or `URetProbe` if the
    /// program is a `uretprobe`.
    pub fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program.
    ///
    /// Attaches the uprobe to the function `fn_name` defined in the `target`.
    /// If `offset` is non-zero, it is added to the address of the target
    /// function. If `pid` is not `None`, the program executes only when the target
    /// function is executed by the given `pid`.
    ///
    /// The `target` argument can be an absolute path to a binary or library, or
    /// a library name (eg: `"libc"`).
    ///
    /// If the program is an `uprobe`, it is attached to the *start* address of the target
    /// function.  Instead if the program is a `uretprobe`, it is attached to the return address of
    /// the target function.
    ///
    /// The returned value can be used to detach, see [UProbe::detach].
    pub fn attach<T: AsRef<Path>>(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: T,
        pid: Option<pid_t>,
    ) -> Result<UProbeLinkId, ProgramError> {
        let path = resolve_attach_path(&target, pid)?;

        let sym_offset = if let Some(fn_name) = fn_name {
            resolve_symbol(&path, fn_name).map_err(|error| UProbeError::SymbolError {
                symbol: fn_name.to_string(),
                error: Box::new(error),
            })?
        } else {
            0
        };

        attach(&mut self.data, self.kind, &path, sym_offset + offset, pid)
    }

    /// Detaches the program.
    ///
    /// See [UProbe::attach].
    pub fn detach(&mut self, link_id: UProbeLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: UProbeLinkId) -> Result<UProbeLink, ProgramError> {
        self.data.take_link(link_id)
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(path: P, kind: ProbeKind) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, kind })
    }
}

fn resolve_attach_path<T: AsRef<Path>>(
    target: &T,
    pid: Option<pid_t>,
) -> Result<Cow<'_, str>, UProbeError> {
    // Look up the path for the target. If it there is a pid, and the target is a library name
    // that is in the process's memory map, use the path of that library. Otherwise, use the target as-is.
    let target = target.as_ref();
    let invalid_target = || UProbeError::InvalidTarget {
        path: target.to_owned(),
    };
    let target_str = target.to_str().ok_or_else(invalid_target)?;
    pid.and_then(|pid| {
        ProcMap::new(pid)
            .map_err(|source| UProbeError::ProcMapError { pid, source })
            .and_then(|proc_map_libs| {
                proc_map_libs
                    .find_library_path_by_name(target_str)
                    .map_err(|io_error| UProbeError::FileError {
                        filename: format!("/proc/{pid}/maps"),
                        io_error,
                    })
                    .map(|v| v.map(Cow::Owned))
            })
            .transpose()
    })
    .or_else(|| target.is_absolute().then(|| Ok(Cow::Borrowed(target_str))))
    .or_else(|| {
        LD_SO_CACHE
            .as_ref()
            .map_err(|error| UProbeError::InvalidLdSoCache {
                io_error: error.clone(),
            })
            .map(|cache| cache.resolve(target_str).map(Cow::Borrowed))
            .transpose()
    })
    .unwrap_or_else(|| Err(invalid_target()))
}

// Only run this test on linux with glibc because only in that configuration do we know that we'll
// be dynamically linked to libc and can exercise resolving the path to libc via the current
// process's memory map.
#[test]
#[cfg_attr(
    any(miri, not(all(target_os = "linux", target_env = "gnu"))),
    ignore = "requires glibc, doesn't work in miri"
)]
fn test_resolve_attach_path() {
    // Look up the current process's pid.
    let pid = std::process::id().try_into().unwrap();

    // Now let's resolve the path to libc. It should exist in the current process's memory map and
    // then in the ld.so.cache.
    let libc_path = resolve_attach_path(&"libc", Some(pid)).unwrap();

    // Make sure we got a path that contains libc.
    assert!(libc_path.contains("libc"), "libc_path: {}", libc_path);
}

define_link_wrapper!(
    /// The link used by [UProbe] programs.
    UProbeLink,
    /// The type returned by [UProbe::attach]. Can be passed to [UProbe::detach].
    UProbeLinkId,
    PerfLinkInner,
    PerfLinkIdInner
);

impl TryFrom<UProbeLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: UProbeLink) -> Result<Self, Self::Error> {
        if let PerfLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for UProbeLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_TRACING as u32) {
            return Ok(UProbeLink::new(PerfLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

/// The type returned when attaching an [`UProbe`] fails.
#[derive(Debug, Error)]
pub enum UProbeError {
    /// There was an error parsing `/etc/ld.so.cache`.
    #[error("error reading `{}` file", LD_SO_CACHE_FILE)]
    InvalidLdSoCache {
        /// the original [`io::Error`].
        #[source]
        io_error: Arc<io::Error>,
    },

    /// The target program could not be found.
    #[error("could not resolve uprobe target `{path}`")]
    InvalidTarget {
        /// path to target.
        path: PathBuf,
    },

    /// There was an error resolving the target symbol.
    #[error("error resolving symbol")]
    SymbolError {
        /// symbol name.
        symbol: String,
        /// the original error.
        #[source]
        error: Box<dyn Error + Send + Sync>,
    },

    /// There was an error accessing `filename`.
    #[error("`{filename}`")]
    FileError {
        /// The file name.
        filename: String,
        /// The [`io::Error`] returned from the file operation.
        #[source]
        io_error: io::Error,
    },

    /// There was en error resolving a path.
    #[error("error fetching libs for {pid}")]
    ProcMapError {
        /// The pid.
        pid: i32,
        /// The [`ProcMapError`] that caused the error.
        #[source]
        source: ProcMapError,
    },
}
#[derive(Debug)]
pub(crate) struct CacheEntry {
    key: String,
    value: String,
    _flags: i32,
}

#[derive(Debug)]
pub(crate) struct LdSoCache {
    entries: Vec<CacheEntry>,
}

impl LdSoCache {
    pub fn load<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
        let data = fs::read(path)?;
        Self::parse(&data)
    }

    fn parse(data: &[u8]) -> Result<Self, io::Error> {
        let mut cursor = Cursor::new(data);

        let read_u32 = |cursor: &mut Cursor<_>| -> Result<u32, io::Error> {
            let mut buf = [0u8; mem::size_of::<u32>()];
            cursor.read_exact(&mut buf)?;

            Ok(u32::from_ne_bytes(buf))
        };

        let read_i32 = |cursor: &mut Cursor<_>| -> Result<i32, io::Error> {
            let mut buf = [0u8; mem::size_of::<i32>()];
            cursor.read_exact(&mut buf)?;

            Ok(i32::from_ne_bytes(buf))
        };

        // Check for new format
        let mut buf = [0u8; LD_SO_CACHE_HEADER_NEW.len()];
        cursor.read_exact(&mut buf)?;
        let header = std::str::from_utf8(&buf).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid ld.so.cache header")
        })?;

        let new_format = header == LD_SO_CACHE_HEADER_NEW;

        // Check for old format
        if !new_format {
            cursor.set_position(0);
            let mut buf = [0u8; LD_SO_CACHE_HEADER_OLD.len()];
            cursor.read_exact(&mut buf)?;
            let header = std::str::from_utf8(&buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid ld.so.cache header")
            })?;

            if header != LD_SO_CACHE_HEADER_OLD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid ld.so.cache header",
                ));
            }
        }

        let num_entries = read_u32(&mut cursor)?;

        if new_format {
            cursor.consume(6 * mem::size_of::<u32>());
        }

        let offset = if !new_format {
            cursor.position() as usize + num_entries as usize * 12
        } else {
            0
        };

        let entries = (0..num_entries)
            .map(|_: u32| {
                let flags = read_i32(&mut cursor)?;
                let k_pos = read_u32(&mut cursor)? as usize;
                let v_pos = read_u32(&mut cursor)? as usize;

                if new_format {
                    cursor.consume(12);
                }

                let read_str = |pos| {
                    unsafe {
                        CStr::from_ptr(cursor.get_ref()[offset + pos..].as_ptr() as *const c_char)
                    }
                    .to_string_lossy()
                    .into_owned()
                };

                let key = read_str(k_pos);
                let value = read_str(v_pos);

                Ok::<_, io::Error>(CacheEntry {
                    key,
                    value,
                    _flags: flags,
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(LdSoCache { entries })
    }

    pub fn resolve(&self, lib: &str) -> Option<&str> {
        let lib = if !lib.contains(".so") {
            lib.to_string() + ".so"
        } else {
            lib.to_string()
        };
        self.entries
            .iter()
            .find(|entry| entry.key.starts_with(&lib))
            .map(|entry| entry.value.as_str())
    }
}

#[derive(Error, Debug)]
enum ResolveSymbolError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("error parsing ELF")]
    Object(#[from] object::Error),

    #[error("unknown symbol `{0}`")]
    Unknown(String),

    #[error("symbol `{0}` does not appear in section")]
    NotInSection(String),

    #[error("symbol `{0}` in section `{1:?}` which has no offset")]
    SectionFileRangeNone(String, Result<String, object::Error>),
}

fn resolve_symbol(path: &str, symbol: &str) -> Result<u64, ResolveSymbolError> {
    let data = fs::read(path)?;
    let obj = object::read::File::parse(&*data)?;

    let sym = obj
        .dynamic_symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().map(|name| name == symbol).unwrap_or(false))
        .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))?;

    let needs_addr_translation = matches!(
        obj.kind(),
        object::ObjectKind::Dynamic | object::ObjectKind::Executable
    );
    if !needs_addr_translation {
        Ok(sym.address())
    } else {
        let index = sym
            .section_index()
            .ok_or_else(|| ResolveSymbolError::NotInSection(symbol.to_string()))?;
        let section = obj.section_by_index(index)?;
        let (offset, _size) = section.file_range().ok_or_else(|| {
            ResolveSymbolError::SectionFileRangeNone(
                symbol.to_string(),
                section.name().map(str::to_owned),
            )
        })?;
        Ok(sym.address() - section.address() + offset)
    }
}

/// Error reading from /proc/pid/maps.
#[derive(Debug, Error)]
pub enum ProcMapError {
    /// Unable to read /proc/pid/maps.
    #[error(transparent)]
    ReadError(io::Error),

    /// Error parsing an integer.
    #[error(transparent)]
    IntError(#[from] ParseIntError),

    /// Error parsing a line of /proc/pid/maps.
    #[error("proc map entry parse error")]
    ParseError,
}

/// The memory maps of a process.
///
/// This is read from /proc/`pid`/maps.
///
/// The information here may be used to resolve addresses to paths.
pub struct ProcMap {
    entries: Vec<ProcMapEntry>,
    libraries: HashMap<String, String>,
}

impl ProcMap {
    /// Create a new [`ProcMap`] from a given pid.
    pub fn new(pid: pid_t) -> Result<Self, ProcMapError> {
        let maps_file = format!("/proc/{}/maps", pid);
        let data = fs::read_to_string(maps_file).map_err(ProcMapError::ReadError)?;
        let mut entries = vec![];
        let mut libraries = HashMap::new();
        for line in data.lines() {
            let entry = ProcMapEntry::from_str(line)?;
            if let Some(path) = &entry.path {
                let p = PathBuf::from(path);
                let filename = p.file_name().unwrap().to_string_lossy().into_owned();
                let library_path = p.to_string_lossy().to_string();
                libraries.entry(filename).or_insert(library_path);
            }
            entries.push(entry);
        }
        Ok(ProcMap { entries, libraries })
    }

    // Find the full path of a library by its name.
    //
    // This isn't part of the public API since it's really only useful for
    // attaching uprobes.
    fn find_library_path_by_name(&self, lib: &str) -> Result<Option<String>, io::Error> {
        let ret = if lib.contains(".so") {
            self.libraries
                .iter()
                .find(|(k, _)| k.as_str().starts_with(lib))
        } else {
            self.libraries.iter().find(|(k, _)| {
                k.strip_prefix(lib)
                    .map(|k| k.starts_with(".so") || k.starts_with('-'))
                    .unwrap_or_default()
            })
        };

        Ok(ret.map(|(_, v)| v.clone()))
    }

    /// Iterate parsed memory map entries for the process.
    ///
    /// This is useful to resolve instruction pointers to a the shared object
    /// they belong to.
    pub fn entries(&self) -> impl Iterator<Item = &ProcMapEntry> {
        self.entries.iter()
    }
}

/// A entry that has been parsed from /proc/`pid`/maps.
///
/// This contains information about a mapped portion of memory
/// for the process, ranging from address to address_end.
#[derive(Debug)]
pub struct ProcMapEntry {
    address: u64,
    address_end: u64,
    perms: String,
    offset: u64,
    dev: String,
    inode: u32,
    path: Option<String>,
}

impl ProcMapEntry {
    /// The start address of the mapped memory.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The end address of the mapped memory
    pub fn address_end(&self) -> u64 {
        self.address_end
    }

    /// The permissions of the mapped memory.
    pub fn perms(&self) -> &str {
        &self.perms
    }

    /// The offset of the mapped memory.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The device of the mapped memory.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// The inode of the mapped memory.
    pub fn inode(&self) -> u32 {
        self.inode
    }

    /// The destination path of the mapped memory.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl FromStr for ProcMapEntry {
    type Err = ProcMapError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut parts = line.split_whitespace();
        let mut next = || parts.next().ok_or(ProcMapError::ParseError);
        let (address, address_end) = next()?
            .split_once('-')
            .ok_or(ProcMapError::ParseError)
            .map(|(a, b)| {
                let start = u64::from_str_radix(a, 16).map_err(ProcMapError::IntError);
                let end = u64::from_str_radix(b, 16).map_err(ProcMapError::IntError);
                (start, end)
            })?;
        let perms = next()?;
        let offset = u64::from_str_radix(next()?, 16).map_err(ProcMapError::IntError)?;
        let dev = next()?;
        let inode = next()?.parse().map_err(ProcMapError::IntError)?;
        let path = parts.next().and_then(|s| {
            if s.starts_with('/') {
                Some(s.to_string())
            } else {
                None
            }
        });
        Ok(ProcMapEntry {
            address: address?,
            address_end: address_end?,
            perms: perms.to_string(),
            offset,
            dev: dev.to_string(),
            inode,
            path,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_parse_proc_map_entry_shared_lib() {
        let s = "7ffd6fbea000-7ffd6fbec000 r-xp 00000000 00:00 0                          [vdso]";
        let proc_map = ProcMapEntry::from_str(s).unwrap();
        assert_eq!(proc_map.address, 0x7ffd6fbea000);
        assert_eq!(proc_map.address_end, 0x7ffd6fbec000);
        assert_eq!(proc_map.perms, "r-xp");
        assert_eq!(proc_map.offset, 0x0);
        assert_eq!(proc_map.dev, "00:00");
        assert_eq!(proc_map.inode, 0);
        assert_eq!(proc_map.path, None);
    }

    #[test]
    fn test_parse_proc_map_entry_absolute_path() {
        let s = "7f1bca83a000-7f1bca83c000 rw-p 00036000 fd:01 2895508                    /usr/lib64/ld-linux-x86-64.so.2";
        let proc_map = ProcMapEntry::from_str(s).unwrap();
        assert_eq!(proc_map.address, 0x7f1bca83a000);
        assert_eq!(proc_map.address_end, 0x7f1bca83c000);
        assert_eq!(proc_map.perms, "rw-p");
        assert_eq!(proc_map.offset, 0x00036000);
        assert_eq!(proc_map.dev, "fd:01");
        assert_eq!(proc_map.inode, 2895508);
        assert_eq!(
            proc_map.path,
            Some("/usr/lib64/ld-linux-x86-64.so.2".to_string())
        );
    }

    #[test]
    fn test_parse_proc_map_entry_all_zeros() {
        let s = "7f1bca5f9000-7f1bca601000 rw-p 00000000 00:00 0";
        let proc_map = ProcMapEntry::from_str(s).unwrap();
        assert_eq!(proc_map.address, 0x7f1bca5f9000);
        assert_eq!(proc_map.address_end, 0x7f1bca601000);
        assert_eq!(proc_map.perms, "rw-p");
        assert_eq!(proc_map.offset, 0x0);
        assert_eq!(proc_map.dev, "00:00");
        assert_eq!(proc_map.inode, 0);
        assert_eq!(proc_map.path, None);
    }

    #[test]
    fn test_parse_proc_map_entry_parse_errors() {
        assert_matches!(
            ProcMapEntry::from_str(
                "zzzz-7ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::IntError(_))
        );

        assert_matches!(
            ProcMapEntry::from_str(
                "zzzz-7ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::IntError(_))
        );

        assert_matches!(
            ProcMapEntry::from_str(
                "7f1bca5f9000-7f1bca601000 r-xp zzzz 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::IntError(_))
        );

        assert_matches!(
            ProcMapEntry::from_str(
                "7f1bca5f9000-7f1bca601000 r-xp 00000000 00:00 zzzz                          [vdso]"
            ),
            Err(ProcMapError::IntError(_))
        );

        assert_matches!(
            ProcMapEntry::from_str(
                "7f1bca5f90007ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::ParseError)
        );

        assert_matches!(
            ProcMapEntry::from_str("7f1bca5f9000-7f1bca601000 r-xp 00000000"),
            Err(ProcMapError::ParseError)
        );
    }

    #[test]
    fn test_proc_map_find_lib_by_name() {
        let entry = ProcMapEntry::from_str(
            "7fc4a9800000-7fc4a98ad000 r--p 00000000 00:24 18147308                   /usr/lib64/libcrypto.so.3.0.9",
        ).unwrap();

        let proc_map_libs = ProcMap {
            entries: vec![entry],
            libraries: HashMap::from([(
                "libcrypto.so.3.0.9".to_owned(),
                "/usr/lib64/libcrypto.so.3.0.9".to_owned(),
            )]),
        };
        assert_eq!(
            proc_map_libs
                .find_library_path_by_name("libcrypto.so.3.0.9")
                .unwrap(),
            Some("/usr/lib64/libcrypto.so.3.0.9".to_owned())
        );
    }
}
