//! User space probes.
use std::{
    borrow::Cow,
    error::Error,
    ffi::{CStr, OsStr, OsString},
    fmt::{self, Write},
    fs,
    io::{self, BufRead as _, Cursor, Read as _},
    os::{
        fd::AsFd as _,
        unix::ffi::{OsStrExt as _, OsStringExt as _},
    },
    path::{Path, PathBuf},
    sync::LazyLock,
};

use aya_obj::generated::{bpf_link_type, bpf_prog_type::BPF_PROG_TYPE_KPROBE};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, Symbol};
use thiserror::Error;

use crate::{
    VerifierLogLevel,
    programs::{
        FdLink, LinkError, ProgramData, ProgramError, ProgramType, define_link_wrapper,
        impl_try_into_fdlink, load_program,
        perf_attach::{PerfLinkIdInner, PerfLinkInner},
        probe::{OsStringExt as _, Probe, ProbeKind, attach},
    },
    sys::bpf_link_get_info_by_fd,
    util::MMap,
};

const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

static LD_SO_CACHE: LazyLock<Result<LdSoCache, io::Error>> =
    LazyLock::new(|| LdSoCache::load(LD_SO_CACHE_FILE));
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

/// The location in the target object file to which the uprobe is to be
/// attached.
pub enum UProbeAttachLocation<'a> {
    /// The location of the target function in the target object file.
    Symbol(&'a str),
    /// The location of the target function in the target object file, offset by
    /// the given number of bytes.
    SymbolOffset(&'a str, u64),
    /// The **file** offset in the target object file, in bytes.
    AbsoluteOffset(u64),
    /// Transform symbol's virtual address (absolute for binaries and relative
    /// for shared libs) into file offset, which is what kernel is expecting for
    /// uprobe/uretprobe attachment.
    /// See Documentation/trace/uprobetracer.rst for more details. This is done
    /// by looking up symbol's containing section's header and using iter's
    /// virtual address (`sh_addr`) and corresponding file offset (`sh_offset`)
    /// to transform `st_value` (virtual address) into desired final file
    /// offset.
    ///
    /// ## Formula:
    /// ```
    /// symbol_file_offset = st_value - sh_addr + sh_offset
    /// ```
    ///
    /// ## References:
    /// * [libbpf](https://github.com/libbpf/libbpf/blob/master/src/elf.c#L259C1-L270C2)
    /// * [StackOverflow](https://stackoverflow.com/questions/79478284/uprobe-symbol-adress-mapping-offset)
    ElfSymOffset {
        /// The symbol's value (virtual address)
        ///
        /// ```text
        /// ❯ readelf -Ws libart.so | c++filt | grep -i DeleteLocalRef
        ///    Num:    Value          Size Type Bind   Vis        Ndx Name
        ///   1208: 0000000000601300    26 FUNC GLOBAL PROTECTED  14  art::JNIEnvExt::DeleteLocalRef(_jobject*)
        /// ```
        /// Symbol `art::JNIEnvExt::DeleteLocalRef(_jobject*)` in `libart.so` at virtual address `0x601300`
        st_value: u64,
        /// The section's memory address
        ///
        /// ```text
        /// ❯ readelf -S --wide libart.so
        /// There are 29 section headers, starting at offset 0x89be68:
        ///
        /// Section Headers:
        ///   [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        ///   [14] .text             PROGBITS        000000000035ff00 15ff00 5df958 00  AX  0   0 128
        /// ```
        /// ELF `.text` section in `libart.so` starts at **virtual address** `0x35ff00`
        sh_addr: u64,
        /// The section's file offset
        ///
        /// ELF `.text` section in `libart.so` starts at **file** offset `0x15ff00`. See `sh_addr`
        sh_offset: u64,
    },
}

impl<'a> From<&'a str> for UProbeAttachLocation<'a> {
    fn from(s: &'a str) -> Self {
        Self::Symbol(s)
    }
}

impl From<u64> for UProbeAttachLocation<'static> {
    fn from(offset: u64) -> Self {
        Self::AbsoluteOffset(offset)
    }
}

/// Describes a single attachment point along with its optional cookie.
pub struct UProbeAttachPoint<'a> {
    /// The actual target location.
    pub location: UProbeAttachLocation<'a>,
    /// Optional cookie available via `bpf_get_attach_cookie()`.
    pub cookie: Option<u64>,
}

impl<'a, L: Into<UProbeAttachLocation<'a>>> From<L> for UProbeAttachPoint<'a> {
    fn from(location: L) -> Self {
        Self {
            location: location.into(),
            cookie: None,
        }
    }
}

impl UProbe {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::KProbe;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Returns [`ProbeKind::Entry`] if the program is a `uprobe`, or
    /// [`ProbeKind::Return`] if the program is a `uretprobe`.
    pub const fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// Attaches the program.
    ///
    /// Attaches the uprobe to the function `fn_name` defined in the `target`.
    /// If the attach point specifies an offset, it is added to the address of
    /// the target function. If `pid` is not `None`, the program executes only
    /// when the target function is executed by the given `pid`.
    ///
    /// The `target` argument can be an absolute path to a binary or library, or
    /// a library name (eg: `"libc"`).
    ///
    /// If the program is an `uprobe`, it is attached to the *start* address of
    /// the target function.  Instead if the program is a `uretprobe`, it is
    /// attached to the return address of the target function.
    ///
    /// The returned value can be used to detach, see [`UProbe::detach`].
    ///
    /// The cookie is supported since kernel 5.15, and it is made available to
    /// the eBPF program via the `bpf_get_attach_cookie()` helper. The `point`
    /// argument may be just a location (no cookie) or a [`UProbeAttachPoint`],
    /// only the latter sets the cookie explicitly.
    pub fn attach<'a, T: AsRef<Path>, Point: Into<UProbeAttachPoint<'a>>>(
        &mut self,
        point: Point,
        target: T,
        pid: Option<u32>,
    ) -> Result<UProbeLinkId, ProgramError> {
        let UProbeAttachPoint { location, cookie } = point.into();
        let proc_map = pid.map(ProcMap::new).transpose()?;
        let path = resolve_attach_path(target.as_ref(), proc_map.as_ref())?;
        let (symbol, offset) = match location {
            UProbeAttachLocation::Symbol(s) => (Some(s), 0),
            UProbeAttachLocation::SymbolOffset(s, offset) => (Some(s), offset),
            UProbeAttachLocation::AbsoluteOffset(offset) => (None, offset),
            UProbeAttachLocation::ElfSymOffset {
                st_value,
                sh_addr,
                sh_offset,
            } => (None, st_value - sh_addr + sh_offset),
        };
        let offset = if let Some(symbol) = symbol {
            let symbol_offset =
                resolve_symbol(path, symbol).map_err(|error| UProbeError::SymbolError {
                    symbol: symbol.to_string(),
                    error: Box::new(error),
                })?;
            symbol_offset + offset
        } else {
            offset
        };

        let Self { data, kind } = self;
        let path = path.as_os_str();
        attach::<Self, _>(data, *kind, path, offset, pid, cookie)
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

impl Probe for UProbe {
    const PMU: &'static str = "uprobe";

    type Error = UProbeError;

    fn file_error(filename: PathBuf, io_error: io::Error) -> Self::Error {
        UProbeError::FileError { filename, io_error }
    }

    fn write_offset<W: Write>(w: &mut W, _: ProbeKind, offset: u64) -> fmt::Result {
        write!(w, ":{offset:#x}")
    }
}

fn resolve_attach_path<'a, 'b, 'c, T>(
    target: &'a Path,
    proc_map: Option<&'b ProcMap<T>>,
) -> Result<&'c Path, UProbeError>
where
    'a: 'c,
    'b: 'c,
    T: AsRef<[u8]>,
{
    proc_map
        .and_then(|proc_map| {
            proc_map
                .find_library_path_by_name(target)
                .map_err(|source| {
                    let ProcMap { pid, data: _ } = proc_map;
                    let pid = *pid;
                    UProbeError::ProcMap { pid, source }
                })
                .transpose()
        })
        .or_else(|| target.is_absolute().then(|| Ok(target)))
        .or_else(|| {
            LD_SO_CACHE
                .as_ref()
                .map_err(|io_error| UProbeError::InvalidLdSoCache { io_error })
                .map(|cache| cache.resolve(target))
                .transpose()
        })
        .unwrap_or_else(|| {
            Err(UProbeError::InvalidTarget {
                path: target.to_owned(),
            })
        })
}

define_link_wrapper!(
    UProbeLink,
    UProbeLinkId,
    PerfLinkInner,
    PerfLinkIdInner,
    UProbe,
);

impl_try_into_fdlink!(UProbeLink, PerfLinkInner);

impl TryFrom<FdLink> for UProbeLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_TRACING as u32) {
            return Ok(Self::new(PerfLinkInner::Fd(fd_link)));
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
        io_error: &'static io::Error,
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
        pid: u32,
        /// The [`ProcMapError`] that caused the error.
        #[source]
        source: ProcMapError,
    },
}

/// Error reading from /proc/pid/maps.
#[derive(Debug, Error)]
pub enum ProcMapError {
    /// Unable to read /proc/pid/maps.
    #[error(transparent)]
    ReadFile(#[from] io::Error),

    /// Error parsing a line of /proc/pid/maps.
    #[error("could not parse {}", line.display())]
    ParseLine {
        /// The line that could not be parsed.
        line: OsString,
    },
}

/// A entry that has been parsed from /proc/`pid`/maps.
///
/// This contains information about a mapped portion of memory
/// for the process, ranging from address to `address_end`.
#[cfg_attr(test, derive(Debug, PartialEq))]
struct ProcMapEntry<'a> {
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    address: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    address_end: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    perms: &'a OsStr,
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    offset: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    dev: &'a OsStr,
    #[cfg_attr(not(test), expect(dead_code, reason = "parsed but not exposed"))]
    inode: u32,
    path: Option<&'a OsStr>,
}

/// Split a byte slice on ASCII whitespace up to `n` times.
///
/// The last item yielded contains the remainder of the slice and may itself
/// contain whitespace.
fn split_ascii_whitespace_n(s: &[u8], mut n: usize) -> impl Iterator<Item = &[u8]> {
    let mut s = s.trim_ascii_end();

    std::iter::from_fn(move || {
        if n == 0 {
            None
        } else {
            s = s.trim_ascii_start();

            n -= 1;
            Some(if n == 0 {
                s
            } else if let Some(i) = s.iter().position(u8::is_ascii_whitespace) {
                let (next, rest) = s.split_at(i);
                s = rest;
                next
            } else {
                n = 0;
                s
            })
        }
    })
}

impl<'a> ProcMapEntry<'a> {
    fn parse(line: &'a [u8]) -> Result<Self, ProcMapError> {
        use std::os::unix::ffi::OsStrExt as _;

        let err = || ProcMapError::ParseLine {
            line: OsString::from_vec(line.to_vec()),
        };

        let mut parts =
            // address, perms, offset, dev, inode, path = 6.
            split_ascii_whitespace_n(line, 6)
            .filter(|part| !part.is_empty());

        let mut next = || parts.next().ok_or_else(err);

        let (start, end) = {
            let addr = next()?;
            let mut addr_parts = addr.split(|b| *b == b'-');
            let mut next = || {
                addr_parts
                    .next()
                    .ok_or(())
                    .and_then(|part| {
                        let s =
                            std::str::from_utf8(part).map_err(|std::str::Utf8Error { .. }| ())?;
                        let n = u64::from_str_radix(s, 16)
                            .map_err(|std::num::ParseIntError { .. }| ())?;
                        Ok(n)
                    })
                    .map_err(|()| err())
            };
            let start = next()?;
            let end = next()?;
            if let Some(_part) = addr_parts.next() {
                return Err(err());
            }
            (start, end)
        };

        let perms = next()?;
        let perms = OsStr::from_bytes(perms);
        let offset = next()?;
        let offset = std::str::from_utf8(offset).map_err(|std::str::Utf8Error { .. }| err())?;
        let offset =
            u64::from_str_radix(offset, 16).map_err(|std::num::ParseIntError { .. }| err())?;
        let dev = next()?;
        let dev = OsStr::from_bytes(dev);
        let inode = next()?;
        let inode = std::str::from_utf8(inode).map_err(|std::str::Utf8Error { .. }| err())?;
        let inode = inode
            .parse()
            .map_err(|std::num::ParseIntError { .. }| err())?;

        let path = parts.next().map(OsStr::from_bytes);

        if let Some(_part) = parts.next() {
            return Err(err());
        }

        Ok(Self {
            address: start,
            address_end: end,
            perms,
            offset,
            dev,
            inode,
            path,
        })
    }
}

/// The memory maps of a process.
///
/// This is read from /proc/`pid`/maps.
///
/// The information here may be used to resolve addresses to paths.
struct ProcMap<T> {
    pid: u32,
    data: T,
}

impl ProcMap<Vec<u8>> {
    fn new(pid: u32) -> Result<Self, UProbeError> {
        let filename = PathBuf::from(format!("/proc/{pid}/maps"));
        let data = fs::read(&filename)
            .map_err(|io_error| UProbeError::FileError { filename, io_error })?;
        Ok(Self { pid, data })
    }
}

impl<T: AsRef<[u8]>> ProcMap<T> {
    fn libs(&self) -> impl Iterator<Item = Result<ProcMapEntry<'_>, ProcMapError>> {
        let Self { pid: _, data } = self;

        // /proc/<pid>/maps ends with '\n', so split() yields a trailing empty slice without this.
        data.as_ref()
            .trim_ascii()
            .split(|&b| b == b'\n')
            .map(ProcMapEntry::parse)
    }

    // Find the full path of a library by its name.
    //
    // This isn't part of the public API since it's really only useful for
    // attaching uprobes.
    fn find_library_path_by_name(&self, lib: &Path) -> Result<Option<&Path>, ProcMapError> {
        let lib = lib.as_os_str();
        let lib = lib.strip_suffix(OsStr::new(".so")).unwrap_or(lib);

        for entry in self.libs() {
            let ProcMapEntry {
                address: _,
                address_end: _,
                perms: _,
                offset: _,
                dev: _,
                inode: _,
                path,
            } = entry?;
            if let Some(path) = path {
                let path = Path::new(path);
                if let Some(filename) = path.file_name() {
                    if let Some(suffix) = filename.strip_prefix(lib) {
                        if suffix.is_empty()
                            || suffix.starts_with(OsStr::new(".so"))
                            || suffix.starts_with(OsStr::new("-"))
                        {
                            return Ok(Some(path));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
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
            let mut buf = [0u8; size_of::<u32>()];
            cursor.read_exact(&mut buf)?;

            Ok(u32::from_ne_bytes(buf))
        };

        let read_i32 = |cursor: &mut Cursor<_>| -> Result<i32, io::Error> {
            let mut buf = [0u8; size_of::<i32>()];
            cursor.read_exact(&mut buf)?;

            Ok(i32::from_ne_bytes(buf))
        };

        // Check for new format
        let mut buf = [0u8; LD_SO_CACHE_HEADER_NEW.len()];
        cursor.read_exact(&mut buf)?;
        let header = std::str::from_utf8(&buf).map_err(|std::str::Utf8Error { .. }| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid ld.so.cache header")
        })?;

        let new_format = header == LD_SO_CACHE_HEADER_NEW;

        // Check for old format
        if !new_format {
            cursor.set_position(0);
            let mut buf = [0u8; LD_SO_CACHE_HEADER_OLD.len()];
            cursor.read_exact(&mut buf)?;
            let header = std::str::from_utf8(&buf).map_err(|std::str::Utf8Error { .. }| {
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
            cursor.consume(6 * size_of::<u32>());
        }

        let offset = if new_format {
            0
        } else {
            cursor.position() as usize + num_entries as usize * 12
        };

        let entries = std::iter::repeat_with(|| {
            let flags = read_i32(&mut cursor)?;
            let k_pos = read_u32(&mut cursor)? as usize;
            let v_pos = read_u32(&mut cursor)? as usize;

            if new_format {
                cursor.consume(12);
            }

            let read_str = |pos| {
                use std::os::unix::ffi::OsStrExt as _;
                OsStr::from_bytes(
                    unsafe { CStr::from_ptr(cursor.get_ref()[offset + pos..].as_ptr().cast()) }
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
        .take(num_entries as usize)
        .collect::<Result<_, _>>()?;

        Ok(Self { entries })
    }

    fn resolve(&self, lib: &Path) -> Option<&Path> {
        let Self { entries } = self;

        let lib = lib.as_os_str();
        let lib = lib.strip_suffix(OsStr::new(".so")).unwrap_or(lib);

        entries
            .iter()
            .find_map(|CacheEntry { key, value, _flags }| {
                let suffix = key.strip_prefix(lib)?;
                suffix
                    .starts_with(OsStr::new(".so"))
                    .then_some(Path::new(value.as_os_str()))
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

    #[error("failed to access debuglink file `{0}`: `{1}`")]
    DebuglinkAccessError(PathBuf, io::Error),

    #[error("symbol `{0}` not found, mismatched build IDs in main and debug files")]
    BuildIdMismatch(String),
}

fn construct_debuglink_path<'a>(filename: &'a [u8], main_path: &Path) -> Cow<'a, Path> {
    let filename_str = OsStr::from_bytes(filename);
    let debuglink_path = Path::new(filename_str);

    if debuglink_path.is_relative() {
        // If the debug path is relative, resolve it against the parent of the main path
        main_path.parent().map_or_else(
            || debuglink_path.into(), // Use original if no parent
            |parent| parent.join(debuglink_path).into(),
        )
    } else {
        // If the path is not relative, just use original
        debuglink_path.into()
    }
}

fn verify_build_ids<'a>(
    main_obj: &'a object::File<'a>,
    debug_obj: &'a object::File<'a>,
    symbol_name: &str,
) -> Result<(), ResolveSymbolError> {
    let main_build_id = main_obj.build_id().ok().flatten();
    let debug_build_id = debug_obj.build_id().ok().flatten();

    match (debug_build_id, main_build_id) {
        (Some(debug_build_id), Some(main_build_id)) => {
            // Only perform a comparison if both build IDs are present
            if debug_build_id != main_build_id {
                return Err(ResolveSymbolError::BuildIdMismatch(symbol_name.to_owned()));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn find_debug_path_in_object<'a>(
    obj: &object::File<'a>,
    main_path: &Path,
    symbol: &str,
) -> Result<Cow<'a, Path>, ResolveSymbolError> {
    match obj.gnu_debuglink() {
        Ok(Some((filename, _))) => Ok(construct_debuglink_path(filename, main_path)),
        Ok(None) => Err(ResolveSymbolError::Unknown(symbol.to_string())),
        Err(err) => Err(ResolveSymbolError::Object(err)),
    }
}

fn find_symbol_in_object<'a>(obj: &'a object::File<'a>, symbol: &str) -> Option<Symbol<'a, 'a>> {
    obj.dynamic_symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().is_ok_and(|name| name == symbol))
}

fn resolve_symbol(path: &Path, symbol: &str) -> Result<u64, ResolveSymbolError> {
    let data = MMap::map_copy_read_only(path)?;
    let obj = object::read::File::parse(data.as_ref())?;

    if let Some(sym) = find_symbol_in_object(&obj, symbol) {
        symbol_translated_address(&obj, sym, symbol)
    } else {
        // Only search in the debug object if the symbol was not found in the main object
        let debug_path = find_debug_path_in_object(&obj, path, symbol)?;
        let debug_data = MMap::map_copy_read_only(&debug_path)
            .map_err(|e| ResolveSymbolError::DebuglinkAccessError(debug_path.into_owned(), e))?;
        let debug_obj = object::read::File::parse(debug_data.as_ref())?;

        verify_build_ids(&obj, &debug_obj, symbol)?;

        let sym = find_symbol_in_object(&debug_obj, symbol)
            .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))?;

        symbol_translated_address(&debug_obj, sym, symbol)
    }
}

fn symbol_translated_address(
    obj: &object::File<'_>,
    sym: Symbol<'_, '_>,
    symbol_name: &str,
) -> Result<u64, ResolveSymbolError> {
    let needs_addr_translation = matches!(
        obj.kind(),
        object::ObjectKind::Dynamic | object::ObjectKind::Executable
    );
    if needs_addr_translation {
        let index = sym
            .section_index()
            .ok_or_else(|| ResolveSymbolError::NotInSection(symbol_name.to_string()))?;
        let section = obj.section_by_index(index)?;
        let (offset, _size) = section.file_range().ok_or_else(|| {
            ResolveSymbolError::SectionFileRangeNone(
                symbol_name.to_string(),
                section.name().map(str::to_owned),
            )
        })?;
        Ok(sym.address() - section.address() + offset)
    } else {
        Ok(sym.address())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use object::{Architecture, BinaryFormat, Endianness, write::SectionKind};
    use test_case::test_case;

    use super::*;

    // Only run this test on with libc dynamically linked so that it can
    // exercise resolving the path to libc via the current process's memory map.
    #[test]
    #[cfg_attr(
        any(miri, not(target_os = "linux"), target_feature = "crt-static"),
        ignore = "requires dynamic linkage of libc"
    )]
    fn test_resolve_attach_path() {
        // Look up the current process's pid.
        let pid = std::process::id();
        let proc_map = ProcMap::new(pid).expect("failed to get proc map");

        // Now let's resolve the path to libc. It should exist in the current process's memory map and
        // then in the ld.so.cache.
        assert_matches!(
            resolve_attach_path("libc".as_ref(), Some(&proc_map)),
            Ok(path) => {
                // Make sure we got a path that contains libc.
                assert_matches!(
                    path.to_str(),
                    Some(path) if path.contains("libc"), "path: {}", path.display()
                );
            }
        );

        // If we pass an absolute path that doesn't match anything in /proc/<pid>/maps, we should fall
        // back to the provided path instead of erroring out. Using a synthetic absolute path keeps the
        // test hermetic.
        let synthetic_absolute = Path::new("/tmp/.aya-test-resolve-attach-absolute");
        assert_matches!(
            resolve_attach_path(synthetic_absolute, Some(&proc_map)),
            Ok(path) => {
                assert_eq!(path, synthetic_absolute, "path: {}", path.display());
            }
        );
    }

    #[test]
    fn test_relative_path_with_parent() {
        let filename = b"debug_info";
        let main_path = Path::new("/usr/lib/main_binary");
        let expected = Path::new("/usr/lib/debug_info");

        let result = construct_debuglink_path(filename, main_path);
        assert_eq!(
            result, expected,
            "The debug path should resolve relative to the main path's parent"
        );
    }

    #[test]
    fn test_relative_path_without_parent() {
        let filename = b"debug_info";
        let main_path = Path::new("main_binary");
        let expected = Path::new("debug_info");

        let result = construct_debuglink_path(filename, main_path);
        assert_eq!(
            result, expected,
            "The debug path should be the original path as there is no parent"
        );
    }

    #[test]
    fn test_absolute_path() {
        let filename = b"/absolute/path/to/debug_info";
        let main_path = Path::new("/usr/lib/main_binary");
        let expected = Path::new("/absolute/path/to/debug_info");

        let result = construct_debuglink_path(filename, main_path);
        assert_eq!(
            result, expected,
            "The debug path should be the same as the input absolute path"
        );
    }

    #[expect(
        clippy::little_endian_bytes,
        reason = "ELF debuglink fields are encoded as little-endian"
    )]
    fn create_elf_with_debuglink(
        debug_filename: &[u8],
        crc: u32,
    ) -> Result<Vec<u8>, object::write::Error> {
        let mut obj =
            object::write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

        let section_name = b".gnu_debuglink";

        let section_id = obj.add_section(vec![], section_name.to_vec(), SectionKind::Note);

        let mut debuglink_data = Vec::new();

        debuglink_data.extend_from_slice(debug_filename);
        debuglink_data.push(0); // Null terminator

        while debuglink_data.len() % 4 != 0 {
            debuglink_data.push(0);
        }

        debuglink_data.extend(&crc.to_le_bytes());

        obj.append_section_data(section_id, &debuglink_data, 4 /* align */);

        obj.write()
    }

    #[expect(
        clippy::little_endian_bytes,
        reason = "ELF note headers are encoded as little-endian"
    )]
    fn create_elf_with_build_id(build_id: &[u8]) -> Result<Vec<u8>, object::write::Error> {
        let mut obj =
            object::write::Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);

        let section_name = b".note.gnu.build-id";

        let section_id = obj.add_section(vec![], section_name.to_vec(), SectionKind::Note);

        let mut note_data = Vec::new();
        let build_id_name = b"GNU";

        note_data.extend(&(build_id_name.len() as u32 + 1).to_le_bytes());
        note_data.extend(&(build_id.len() as u32).to_le_bytes());
        note_data.extend(&3u32.to_le_bytes());

        note_data.extend_from_slice(build_id_name);
        note_data.push(0); // Null terminator
        note_data.extend_from_slice(build_id);

        obj.append_section_data(section_id, &note_data, 4 /* align */);

        obj.write()
    }

    fn aligned_slice(vec: &mut Vec<u8>) -> &mut [u8] {
        let alignment = 8;

        let original_size = vec.len();
        let total_size = original_size + alignment - 1;

        if vec.capacity() < total_size {
            vec.reserve(total_size - vec.capacity());
        }

        if vec.len() < total_size {
            vec.resize(total_size, 0);
        }

        let ptr = vec.as_ptr() as usize;

        let aligned_ptr = ptr.next_multiple_of(alignment);

        let offset = aligned_ptr - ptr;

        if offset > 0 {
            let tmp = vec.len();
            vec.copy_within(0..tmp - offset, offset);
        }

        &mut vec[offset..offset + original_size]
    }

    #[test]
    fn test_find_debug_path_success() {
        let debug_filepath = b"main.debug";
        let mut main_bytes = create_elf_with_debuglink(debug_filepath, 0x123 /* fake CRC */)
            .expect("got main_bytes");
        let align_bytes = aligned_slice(&mut main_bytes);
        let main_obj = object::File::parse(&*align_bytes).expect("got main obj");

        let main_path = Path::new("/path/to/main");

        assert_matches!(
            find_debug_path_in_object(&main_obj, main_path, "symbol"),
            Ok(path) => {
                assert_eq!(&*path, "/path/to/main.debug", "path: {}", path.display());
            }
        );
    }

    #[test]
    fn test_verify_build_ids_same() {
        let build_id = b"test_build_id";
        let mut main_bytes = create_elf_with_build_id(build_id).expect("got main_bytes");
        let align_bytes = aligned_slice(&mut main_bytes);
        let main_obj = object::File::parse(&*align_bytes).expect("got main obj");
        let debug_build_id = b"test_build_id";
        let mut debug_bytes = create_elf_with_build_id(debug_build_id).expect("got debug bytes");
        let align_bytes = aligned_slice(&mut debug_bytes);
        let debug_obj = object::File::parse(&*align_bytes).expect("got debug obj");

        assert_matches!(
            verify_build_ids(&main_obj, &debug_obj, "symbol_name"),
            Ok(())
        );
    }

    #[test]
    fn test_verify_build_ids_different() {
        let build_id = b"main_build_id";
        let mut main_bytes = create_elf_with_build_id(build_id).expect("got main_bytes");
        let align_bytes = aligned_slice(&mut main_bytes);
        let main_obj = object::File::parse(&*align_bytes).expect("got main obj");
        let debug_build_id = b"debug_build_id";
        let mut debug_bytes = create_elf_with_build_id(debug_build_id).expect("got debug bytes");
        let align_bytes = aligned_slice(&mut debug_bytes);
        let debug_obj = object::File::parse(&*align_bytes).expect("got debug obj");

        assert_matches!(
            verify_build_ids(&main_obj, &debug_obj, "symbol_name"),
            Err(ResolveSymbolError::BuildIdMismatch(symbol_name)) if symbol_name == "symbol_name"
        );
    }

    #[derive(Debug, Clone, Copy)]
    struct ExpectedProcMapEntry {
        address: u64,
        address_end: u64,
        perms: &'static str,
        offset: u64,
        dev: &'static str,
        inode: u32,
        path: Option<&'static str>,
    }

    #[test_case(
        b"7ffd6fbea000-7ffd6fbec000  r-xp  00000000  00:00  0  [vdso]",
        ExpectedProcMapEntry {
            address: 0x7ffd6fbea000,
            address_end: 0x7ffd6fbec000,
            perms: "r-xp",
            offset: 0,
            dev: "00:00",
            inode: 0,
            path: Some("[vdso]"),
        };
        "bracketed_name"
    )]
    #[test_case(
        b"7f1bca83a000-7f1bca83c000  rw-p  00036000  fd:01  2895508  /usr/lib64/ld-linux-x86-64.so.2",
        ExpectedProcMapEntry {
            address: 0x7f1bca83a000,
            address_end: 0x7f1bca83c000,
            perms: "rw-p",
            offset: 0x00036000,
            dev: "fd:01",
            inode: 2895508,
            path: Some("/usr/lib64/ld-linux-x86-64.so.2"),
        };
        "absolute_path"
    )]
    #[test_case(
        b"7f1bca5f9000-7f1bca601000  rw-p  00000000  00:00  0",
        ExpectedProcMapEntry {
            address: 0x7f1bca5f9000,
            address_end: 0x7f1bca601000,
            perms: "rw-p",
            offset: 0,
            dev: "00:00",
            inode: 0,
            path: None,
        };
        "no_path"
    )]
    #[test_case(
        b"7f1bca5f9000-7f1bca601000  rw-p  00000000  00:00  0  deadbeef",
        ExpectedProcMapEntry {
            address: 0x7f1bca5f9000,
            address_end: 0x7f1bca601000,
            perms: "rw-p",
            offset: 0,
            dev: "00:00",
            inode: 0,
            path: Some("deadbeef"),
        };
        "relative_path_token"
    )]
    #[test_case(
        b"7f1bca83a000-7f1bca83c000  rw-p  00036000  fd:01  2895508  /usr/lib/libc.so.6 (deleted)",
        ExpectedProcMapEntry {
            address: 0x7f1bca83a000,
            address_end: 0x7f1bca83c000,
            perms: "rw-p",
            offset: 0x00036000,
            dev: "fd:01",
            inode: 2895508,
            path: Some("/usr/lib/libc.so.6 (deleted)"),
        };
        "deleted_suffix_in_path"
    )]
    // The path field is the remainder of the line. It may contain whitespace and arbitrary tokens.
    #[test_case(
        b"71064dc000-71064df000 ---p 00000000 00:00 0  [page size compat] extra",
        ExpectedProcMapEntry {
            address: 0x71064dc000,
            address_end: 0x71064df000,
            perms: "---p",
            offset: 0,
            dev: "00:00",
            inode: 0,
            path: Some("[page size compat] extra"),
        };
        "path_remainder_with_spaces"
    )]
    #[test_case(
        b"724a0000-72aab000 rw-p 00000000 00:00 0 [anon:dalvik-zygote space] (deleted) extra",
        ExpectedProcMapEntry {
            address: 0x724a0000,
            address_end: 0x72aab000,
            perms: "rw-p",
            offset: 0,
            dev: "00:00",
            inode: 0,
            path: Some("[anon:dalvik-zygote space] (deleted) extra"),
        };
        "bracketed_name_with_spaces"
    )]
    #[test_case(
        b"5ba3b000-5da3b000 r--s 00000000 00:01 1033 /memfd:jit-zygote-cache (deleted)",
        ExpectedProcMapEntry {
            address: 0x5ba3b000,
            address_end: 0x5da3b000,
            perms: "r--s",
            offset: 0,
            dev: "00:01",
            inode: 1033,
            path: Some("/memfd:jit-zygote-cache (deleted)"),
        };
        "memfd_deleted"
    )]
    #[test_case(
        b"6cd539c000-6cd559c000 rw-s 00000000 00:01 7215 /dev/ashmem/CursorWindow: /data/user/0/package/databases/kitefly.db (deleted)",
        ExpectedProcMapEntry {
            address: 0x6cd539c000,
            address_end: 0x6cd559c000,
            perms: "rw-s",
            offset: 0,
            dev: "00:01",
            inode: 7215,
            path: Some("/dev/ashmem/CursorWindow: /data/user/0/package/databases/kitefly.db (deleted)"),
        };
        "ashmem_with_spaces"
    )]
    fn test_parse_proc_map_entry_ok(line: &'static [u8], expected: ExpectedProcMapEntry) {
        use std::ffi::OsStr;

        let ExpectedProcMapEntry {
            address,
            address_end,
            perms,
            offset,
            dev,
            inode,
            path,
        } = expected;

        assert_matches!(ProcMapEntry::parse(line), Ok(entry) if entry == ProcMapEntry {
            address,
            address_end,
            perms: OsStr::new(perms),
            offset,
            dev: OsStr::new(dev),
            inode,
            path: path.map(OsStr::new),
        });
    }

    #[test_case(b"zzzz-7ffd6fbea000  r-xp  00000000  00:00  0  [vdso]"; "bad_address")]
    #[test_case(b"7f1bca5f9000-7f1bca601000  r-xp  zzzz  00:00  0  [vdso]"; "bad_offset")]
    #[test_case(b"7f1bca5f9000-7f1bca601000  r-xp  00000000  00:00  zzzz  [vdso]"; "bad_inode")]
    #[test_case(b"7f1bca5f90007ffd6fbea000  r-xp  00000000  00:00  0  [vdso]"; "bad_address_range")]
    #[test_case(b"7f1bca5f9000-7f1bca601000  r-xp  00000000"; "missing_fields")]
    #[test_case(b"7f1bca5f9000-7f1bca601000-deadbeef  rw-p  00000000  00:00  0"; "bad_address_delimiter")]
    fn test_parse_proc_map_entry_err(line: &'static [u8]) {
        assert_matches!(
            ProcMapEntry::parse(line),
            Err(ProcMapError::ParseLine { line: _ })
        );
    }

    #[test]
    fn test_proc_map_find_lib_by_name() {
        let proc_map_libs = ProcMap {
            pid: 0xdead,
            data: b"
7fc4a9800000-7fc4a98ad000	r--p	00000000	00:24	18147308	/usr/lib64/libcrypto.so.3.0.9
",
        };

        assert_matches!(
            proc_map_libs.find_library_path_by_name(Path::new("libcrypto.so.3.0.9")),
            Ok(Some(path)) => {
                assert_eq!(path, "/usr/lib64/libcrypto.so.3.0.9", "path: {}", path.display());
            }
        );
    }

    #[test]
    fn test_proc_map_find_lib_by_partial_name() {
        let proc_map_libs = ProcMap {
            pid: 0xdead,
            data: b"
7fc4a9800000-7fc4a98ad000	r--p	00000000	00:24	18147308	/usr/lib64/libcrypto.so.3.0.9
",
        };

        assert_matches!(
            proc_map_libs.find_library_path_by_name(Path::new("libcrypto")),
            Ok(Some(path)) => {
                assert_eq!(path, "/usr/lib64/libcrypto.so.3.0.9", "path: {}", path.display());
            }
        );
    }

    #[test]
    fn test_proc_map_with_multiple_lib_entries() {
        let proc_map_libs = ProcMap {
            pid: 0xdead,
            data: b"
7f372868000-7f3722869000	r--p	00000000	00:24	18097875	/usr/lib64/ld-linux-x86-64.so.2
7f3722869000-7f372288f000	r-xp	00001000	00:24	18097875	/usr/lib64/ld-linux-x86-64.so.2
7f372288f000-7f3722899000	r--p	00027000	00:24	18097875	/usr/lib64/ld-linux-x86-64.so.2
7f3722899000-7f372289b000	r--p	00030000	00:24	18097875	/usr/lib64/ld-linux-x86-64.so.2
7f372289b000-7f372289d000	rw-p	00032000	00:24	18097875	/usr/lib64/ld-linux-x86-64.so.2
",
        };

        assert_matches!(
            proc_map_libs.find_library_path_by_name(Path::new("ld-linux-x86-64.so.2")),
            Ok(Some(path)) => {
                assert_eq!(path, "/usr/lib64/ld-linux-x86-64.so.2", "path: {}", path.display());
            }
        );
    }
}
