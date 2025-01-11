//! User space probes.
use std::{
    borrow::Cow,
    error::Error,
    ffi::{c_char, CStr, OsStr, OsString},
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    os::{fd::AsFd as _, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    sync::LazyLock,
};

use libc::pid_t;
use object::{Object, ObjectSection, ObjectSymbol, Symbol};
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
    /// The offset in the target object file, in bytes.
    AbsoluteOffset(u64),
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
    /// function. If `pid` is not `None`, the program executes only when the
    /// target function is executed by the given `pid`.
    ///
    /// The `target` argument can be an absolute path to a binary or library, or
    /// a library name (eg: `"libc"`).
    ///
    /// If the program is an `uprobe`, it is attached to the *start* address of
    /// the target function.  Instead if the program is a `uretprobe`, it is
    /// attached to the return address of the target function.
    ///
    /// The returned value can be used to detach, see [UProbe::detach].
    ///
    /// The cookie is supported since kernel 5.15, and it is made available to
    /// the eBPF program via the `bpf_get_attach_cookie()` helper.
    pub fn attach<'loc, T: AsRef<Path>, Loc: Into<UProbeAttachLocation<'loc>>>(
        &mut self,
        location: Loc,
        target: T,
        pid: Option<pid_t>,
        cookie: Option<u64>,
    ) -> Result<UProbeLinkId, ProgramError> {
        let path = resolve_attach_path(target.as_ref(), pid)?;
        let (symbol, offset) = match location.into() {
            UProbeAttachLocation::Symbol(s) => (Some(s), 0),
            UProbeAttachLocation::SymbolOffset(s, offset) => (Some(s), offset),
            UProbeAttachLocation::AbsoluteOffset(offset) => (None, offset),
        };
        let offset = if let Some(symbol) = symbol {
            let symbol_offset =
                resolve_symbol(&path, symbol).map_err(|error| UProbeError::SymbolError {
                    symbol: symbol.to_string(),
                    error: Box::new(error),
                })?;
            symbol_offset + offset
        } else {
            offset
        };

        let path = path.as_os_str();
        attach(&mut self.data, self.kind, path, offset, pid, cookie)
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
            .map_err(|io_error| UProbeError::InvalidLdSoCache { io_error })
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
    PerfLinkIdInner,
    UProbe,
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
        io_error: &'static io::Error,
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
            let path = line.split(|b| b.is_ascii_whitespace()).next_back()?;
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

    #[error("failed to access debuglink file `{0}`: `{1}`")]
    DebuglinkAccessError(String, io::Error),

    #[error("symbol `{0}` not found, mismatched build IDs in main and debug files")]
    BuildIdMismatch(String),
}

fn construct_debuglink_path(
    filename: &[u8],
    main_path: &Path,
) -> Result<PathBuf, ResolveSymbolError> {
    let filename_str = OsStr::from_bytes(filename);
    let debuglink_path = Path::new(filename_str);

    let resolved_path = if debuglink_path.is_relative() {
        // If the debug path is relative, resolve it against the parent of the main path
        main_path.parent().map_or_else(
            || PathBuf::from(debuglink_path), // Use original if no parent
            |parent| parent.join(debuglink_path),
        )
    } else {
        // If the path is not relative, just use original
        PathBuf::from(debuglink_path)
    };

    Ok(resolved_path)
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
    obj: &'a object::File<'a>,
    main_path: &Path,
    symbol: &str,
) -> Result<PathBuf, ResolveSymbolError> {
    match obj.gnu_debuglink() {
        Ok(Some((filename, _))) => construct_debuglink_path(filename, main_path),
        Ok(None) => Err(ResolveSymbolError::Unknown(symbol.to_string())),
        Err(err) => Err(ResolveSymbolError::Object(err)),
    }
}

fn find_symbol_in_object<'a>(obj: &'a object::File<'a>, symbol: &str) -> Option<Symbol<'a, 'a>> {
    obj.dynamic_symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().map(|name| name == symbol).unwrap_or(false))
}

fn resolve_symbol(path: &Path, symbol: &str) -> Result<u64, ResolveSymbolError> {
    let data = fs::read(path)?;
    let obj = object::read::File::parse(&*data)?;

    let mut debug_data = Vec::default();
    let mut debug_obj_keeper = None;

    let sym = find_symbol_in_object(&obj, symbol).map_or_else(
        || {
            // Only search in the debug object if the symbol was not found in the main object
            let debug_path = find_debug_path_in_object(&obj, path, symbol)?;
            debug_data = fs::read(&debug_path).map_err(|e| {
                ResolveSymbolError::DebuglinkAccessError(
                    debug_path
                        .to_str()
                        .unwrap_or("Debuglink path missing")
                        .to_string(),
                    e,
                )
            })?;
            let debug_obj = object::read::File::parse(&*debug_data)?;

            verify_build_ids(&obj, &debug_obj, symbol)?;

            debug_obj_keeper = Some(debug_obj);
            find_symbol_in_object(debug_obj_keeper.as_ref().unwrap(), symbol)
                .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))
        },
        Ok,
    )?;

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

#[cfg(test)]
mod tests {

    use object::{write::SectionKind, Architecture, BinaryFormat, Endianness};

    use super::*;

    #[test]
    fn test_relative_path_with_parent() {
        let filename = b"debug_info";
        let main_path = Path::new("/usr/lib/main_binary");
        let expected = Path::new("/usr/lib/debug_info");

        let result = construct_debuglink_path(filename, main_path).unwrap();
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

        let result = construct_debuglink_path(filename, main_path).unwrap();
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

        let result = construct_debuglink_path(filename, main_path).unwrap();
        assert_eq!(
            result, expected,
            "The debug path should be the same as the input absolute path"
        );
    }

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

        let aligned_ptr = (ptr + alignment - 1) & !(alignment - 1);

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
        let result = find_debug_path_in_object(&main_obj, main_path, "symbol");

        assert_eq!(result.unwrap(), Path::new("/path/to/main.debug"));
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

        assert!(verify_build_ids(&main_obj, &debug_obj, "symbol_name").is_ok());
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

        assert!(matches!(
            verify_build_ids(&main_obj, &debug_obj, "symbol_name"),
            Err(ResolveSymbolError::BuildIdMismatch(_))
        ));
    }
}
