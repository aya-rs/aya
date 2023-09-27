//! User space probes.
use std::{
    borrow::Cow,
    error::Error,
    ffi::{CStr, OsStr, OsString},
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
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
        find_lib_in_proc_maps(pid, target)
            .map_err(|io_error| UProbeError::FileError {
                filename: Path::new("/proc").join(pid.to_string()).join("maps"),
                io_error,
            })
            .map(|v| v.map(Cow::Owned))
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
}

fn proc_maps_libs(pid: pid_t) -> Result<Vec<(OsString, PathBuf)>, io::Error> {
    use std::os::unix::ffi::OsStrExt as _;

    let maps_file = format!("/proc/{pid}/maps");
    let data = fs::read(maps_file)?;

    let libs = data
        .split(|b| b == &b'\n')
        .filter_map(|mut line| {
            while let [stripped @ .., c] = line {
                if c.is_ascii_whitespace() {
                    line = stripped;
                    continue;
                }
                break;
            }
            let path = line.split(|b| b.is_ascii_whitespace()).last()?;
            let path = Path::new(OsStr::from_bytes(path));
            path.is_absolute()
                .then(|| {
                    path.file_name()
                        .map(|file_name| (file_name.to_owned(), path.to_owned()))
                })
                .flatten()
        })
        .collect();
    Ok(libs)
}

fn find_lib_in_proc_maps(pid: pid_t, lib: &Path) -> Result<Option<PathBuf>, io::Error> {
    let libs = proc_maps_libs(pid)?;

    let lib = lib.as_os_str();
    let lib = lib.strip_suffix(OsStr::new(".so")).unwrap_or(lib);

    Ok(libs.into_iter().find_map(|(file_name, path)| {
        file_name.strip_prefix(lib).and_then(|suffix| {
            (suffix.starts_with(OsStr::new(".so")) || suffix.starts_with(OsStr::new("-")))
                .then_some(path)
        })
    }))
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
