//! User space probes.
use std::{
    borrow::Cow,
    error::Error,
    ffi::{CStr, OsStr, OsString},
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    num::ParseIntError,
    os::{fd::AsFd as _, raw::c_char},
    path::{Path, PathBuf},
    sync::Arc,
};

use libc::pid_t;
use object::{Object, ObjectSection, ObjectSymbol};
use thiserror::Error;

use crate::{
    generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE},
    programs::{
        define_link_wrapper, load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        probe::{attach, OsStringExt as _, ProbeKind},
        FdLink, LinkError, ProgramData, ProgramError,
    },
    sys::bpf_link_get_info_by_fd,
    VerifierLogLevel,
};

const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

lazy_static::lazy_static! {
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
        let path = resolve_attach_path(target.as_ref(), pid)?;

        let sym_offset = if let Some(fn_name) = fn_name {
            resolve_symbol(&path, fn_name).map_err(|error| UProbeError::SymbolError {
                symbol: fn_name.to_string(),
                error: Box::new(error),
            })?
        } else {
            0
        };

        let fn_name = path.as_os_str();
        attach(&mut self.data, self.kind, fn_name, sym_offset + offset, pid)
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

fn resolve_attach_path(target: &Path, pid: Option<pid_t>) -> Result<Cow<'_, Path>, UProbeError> {
    // Look up the path for the target. If it there is a pid, and the target is a library name
    // that is in the process's memory map, use the path of that library. Otherwise, use the target as-is.
    pid.and_then(|pid| {
        ProcMap::new(pid)
            .map_err(|source| UProbeError::ProcMap { pid, source })
            .and_then(|proc_map_libs| {
                proc_map_libs
                    .find_library_path_by_name(target)
                    .map_err(|io_error| UProbeError::FileError {
                        filename: Path::new("/proc").join(pid.to_string()).join("maps"),
                        io_error,
                    })
                    .map(|v| v.map(|v| Cow::Owned(v.to_owned())))
            })
            .transpose()
    })
    .or_else(|| target.is_absolute().then(|| Ok(Cow::Borrowed(target))))
    .or_else(|| {
        LD_SO_CACHE
            .as_ref()
            .map_err(|error| UProbeError::InvalidLdSoCache {
                io_error: error.clone(),
            })
            .map(|cache| cache.resolve(target).map(Cow::Borrowed))
            .transpose()
    })
    .unwrap_or_else(|| {
        Err(UProbeError::InvalidTarget {
            path: target.to_owned(),
        })
    })
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
    let libc_path = resolve_attach_path("libc".as_ref(), Some(pid)).unwrap();
    let libc_path = libc_path.to_str().unwrap();

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
            return Ok(Self::new(PerfLinkInner::FdLink(fd_link)));
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
        /// The file name
        filename: PathBuf,
        /// The [`io::Error`] returned from the file operation
        #[source]
        io_error: io::Error,
    },

    /// There was en error fetching the memory map for `pid`.
    #[error("error fetching libs for {pid}")]
    ProcMap {
        /// The pid.
        pid: i32,
        /// The [`ProcMapError`] that caused the error.
        #[source]
        source: ProcMapError,
    },
}
#[derive(Debug)]
pub(crate) struct CacheEntry {
    key: OsString,
    value: OsString,
    _flags: i32,
}

#[derive(Debug)]
pub(crate) struct LdSoCache {
    entries: Vec<CacheEntry>,
}

impl LdSoCache {
    fn load<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
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
                    use std::os::unix::ffi::OsStrExt as _;
                    OsStr::from_bytes(
                        unsafe {
                            CStr::from_ptr(
                                cursor.get_ref()[offset + pos..].as_ptr() as *const c_char
                            )
                        }
                        .to_bytes(),
                    )
                    .to_owned()
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

        Ok(Self { entries })
    }

    fn resolve(&self, lib: &Path) -> Option<&Path> {
        let lib = lib.as_os_str();
        let lib = lib.strip_suffix(OsStr::new(".so")).unwrap_or(lib);
        self.entries
            .iter()
            .find_map(|CacheEntry { key, value, _flags }| {
                key.strip_prefix(lib).and_then(|suffix| {
                    suffix
                        .starts_with(OsStr::new(".so"))
                        .then_some(Path::new(value.as_os_str()))
                })
            })
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

fn resolve_symbol(path: &Path, symbol: &str) -> Result<u64, ResolveSymbolError> {
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
    Read(io::Error),

    /// Error parsing an integer.
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    /// Error parsing a line of /proc/pid/maps.
    #[error("proc map entry parse error")]
    Parse,
}

/// The memory maps of a process.
///
/// This is read from /proc/`pid`/maps.
///
/// The information here may be used to resolve addresses to paths.
struct ProcMap {
    entries: Vec<ProcMapEntry>,
}

impl ProcMap {
    /// Create a new [`ProcMap`] from a given pid.
    fn new(pid: pid_t) -> Result<Self, ProcMapError> {
        let maps_file = format!("/proc/{}/maps", pid);
        let data = fs::read(maps_file).map_err(ProcMapError::Read)?;

        let entries = data
            .split(|b| b == &b'\n')
            .filter_map(|line| ProcMapEntry::parse(line).ok())
            .collect();

        Ok(Self { entries })
    }

    #[allow(dead_code)]
    fn parse(data: &[u8]) -> Result<Self, ProcMapError> {
        let entries = data
            .split(|b| b == &b'\n')
            .filter_map(|line| ProcMapEntry::parse(line).ok())
            .collect();

        Ok(Self { entries })
    }

    // Find the full path of a library by its name.
    //
    // This isn't part of the public API since it's really only useful for
    // attaching uprobes.
    fn find_library_path_by_name(&self, lib: &Path) -> Result<Option<&PathBuf>, io::Error> {
        let lib = lib.as_os_str();
        let lib = lib.strip_suffix(OsStr::new(".so")).unwrap_or(lib);

        println!("lib: {:?}", lib);
        Ok(self.entries.iter().find_map(|e| {
            e.path.as_ref().and_then(|path| {
                path.file_name().and_then(|filename| {
                    filename.strip_prefix(lib).and_then(|suffix| {
                        (suffix.is_empty()
                            || suffix.starts_with(OsStr::new(".so"))
                            || suffix.starts_with(OsStr::new("-")))
                        .then_some(path)
                    })
                })
            })
        }))
    }
}

/// A entry that has been parsed from /proc/`pid`/maps.
///
/// This contains information about a mapped portion of memory
/// for the process, ranging from address to address_end.
#[derive(Debug)]
struct ProcMapEntry {
    _address: u64,
    _address_end: u64,
    _perms: String,
    _offset: u64,
    _dev: String,
    _inode: u32,
    path: Option<PathBuf>,
}

impl ProcMapEntry {
    fn parse(mut line: &[u8]) -> Result<Self, ProcMapError> {
        use std::os::unix::ffi::OsStrExt as _;

        while let [stripped @ .., c] = line {
            if c.is_ascii_whitespace() {
                line = stripped;
                continue;
            }
            break;
        }

        let mut parts = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|p| !p.is_empty());

        let mut next = || parts.next().ok_or(ProcMapError::Parse);

        let mut addr_parts = next()?.split(|b| b == &b'-');

        let start = addr_parts
            .next()
            .ok_or(ProcMapError::Parse)
            .and_then(|b| Ok(u64::from_str_radix(&String::from_utf8_lossy(b), 16)?))?;
        let end = addr_parts
            .next()
            .ok_or(ProcMapError::Parse)
            .and_then(|b| Ok(u64::from_str_radix(&String::from_utf8_lossy(b), 16)?))?;

        let perms = String::from_utf8_lossy(next()?);
        let offset = u64::from_str_radix(&String::from_utf8_lossy(next()?), 16)?;
        let dev = String::from_utf8_lossy(next()?);
        let inode = String::from_utf8_lossy(next()?).parse()?;

        let path = next().map_or_else(
            |_| None,
            |p| Some(Path::new(OsStr::from_bytes(p)).to_owned()),
        );

        Ok(Self {
            _address: start,
            _address_end: end,
            _perms: perms.to_string(),
            _offset: offset,
            _dev: dev.to_string(),
            _inode: inode,
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
        let s = b"7ffd6fbea000-7ffd6fbec000 r-xp 00000000 00:00 0                          [vdso]";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        assert_eq!(proc_map._address, 0x7ffd6fbea000);
        assert_eq!(proc_map._address_end, 0x7ffd6fbec000);
        assert_eq!(proc_map._perms, "r-xp");
        assert_eq!(proc_map._offset, 0x0);
        assert_eq!(proc_map._dev, "00:00");
        assert_eq!(proc_map._inode, 0);
        assert_eq!(proc_map.path, None);
    }

    #[test]
    fn test_parse_proc_map_entry_absolute_path() {
        let s = b"7f1bca83a000-7f1bca83c000 rw-p 00036000 fd:01 2895508                    /usr/lib64/ld-linux-x86-64.so.2";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        println!("{:?}", proc_map);
        assert_eq!(proc_map._address, 0x7f1bca83a000);
        assert_eq!(proc_map._address_end, 0x7f1bca83c000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map._offset, 0x00036000);
        assert_eq!(proc_map._dev, "fd:01");
        assert_eq!(proc_map._inode, 2895508);
        assert_eq!(
            proc_map.path,
            Some(PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"))
        );
    }

    #[test]
    fn test_parse_proc_map_entry_all_zeros() {
        let s = b"7f1bca5f9000-7f1bca601000 rw-p 00000000 00:00 0";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        assert_eq!(proc_map._address, 0x7f1bca5f9000);
        assert_eq!(proc_map._address_end, 0x7f1bca601000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map._offset, 0x0);
        assert_eq!(proc_map._dev, "00:00");
        assert_eq!(proc_map._inode, 0);
        assert_eq!(proc_map.path, None);
    }

    #[test]
    fn test_parse_proc_map_entry_parse_errors() {
        assert_matches!(
            ProcMapEntry::parse(
                b"zzzz-7ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::ParseInt(_))
        );

        assert_matches!(
            ProcMapEntry::parse(
                b"zzzz-7ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::ParseInt(_))
        );

        assert_matches!(
            ProcMapEntry::parse(
                b"7f1bca5f9000-7f1bca601000 r-xp zzzz 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::ParseInt(_))
        );

        assert_matches!(
            ProcMapEntry::parse(
                b"7f1bca5f9000-7f1bca601000 r-xp 00000000 00:00 zzzz                          [vdso]"
            ),
            Err(ProcMapError::ParseInt(_))
        );

        assert_matches!(
            ProcMapEntry::parse(
                b"7f1bca5f90007ffd6fbea000 r-xp 00000000 00:00 0                          [vdso]"
            ),
            Err(ProcMapError::Parse)
        );

        assert_matches!(
            ProcMapEntry::parse(b"7f1bca5f9000-7f1bca601000 r-xp 00000000"),
            Err(ProcMapError::Parse)
        );
    }

    #[test]
    fn test_proc_map_find_lib_by_name() {
        let proc_map_libs = ProcMap::parse(
            b"7fc4a9800000-7fc4a98ad000 r--p 00000000 00:24 18147308                   /usr/lib64/libcrypto.so.3.0.9"
        ).unwrap();

        assert_eq!(
            proc_map_libs
                .find_library_path_by_name(Path::new("libcrypto.so.3.0.9"))
                .unwrap(),
            Some(&PathBuf::from("/usr/lib64/libcrypto.so.3.0.9"))
        );
    }

    #[test]
    fn test_proc_map_find_lib_by_partial_name() {
        let proc_map_libs = ProcMap::parse(
            b"7fc4a9800000-7fc4a98ad000 r--p 00000000 00:24 18147308                   /usr/lib64/libcrypto.so.3.0.9"
        ).unwrap();

        assert_eq!(
            proc_map_libs
                .find_library_path_by_name(Path::new("libcrypto"))
                .unwrap(),
            Some(&PathBuf::from("/usr/lib64/libcrypto.so.3.0.9"))
        );
    }

    #[test]
    fn test_proc_map_with_multiple_lib_entries() {
        let proc_map_libs = ProcMap::parse(
            br#"7f372868000-7f3722869000 r--p 00000000 00:24 18097875                   /usr/lib64/ld-linux-x86-64.so.2
            7f3722869000-7f372288f000 r-xp 00001000 00:24 18097875                   /usr/lib64/ld-linux-x86-64.so.2
            7f372288f000-7f3722899000 r--p 00027000 00:24 18097875                   /usr/lib64/ld-linux-x86-64.so.2
            7f3722899000-7f372289b000 r--p 00030000 00:24 18097875                   /usr/lib64/ld-linux-x86-64.so.2
            7f372289b000-7f372289d000 rw-p 00032000 00:24 18097875                   /usr/lib64/ld-linux-x86-64.so.2"#)
            .unwrap();
        assert_eq!(
            proc_map_libs
                .find_library_path_by_name(Path::new("ld-linux-x86-64.so.2"))
                .unwrap(),
            Some(&PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2"))
        );
    }
}
