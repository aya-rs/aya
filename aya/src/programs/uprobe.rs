//! User space probes.
use libc::pid_t;
use object::{Object, ObjectSymbol};
use std::{
    collections::HashMap,
    error::Error,
    ffi::CStr,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    os::raw::c_char,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_KPROBE,
    programs::{
        define_link_wrapper, load_program,
        perf_attach::{PerfLink, PerfLinkId},
        probe::{attach, ProbeKind},
        ProgramData, ProgramError,
    },
};

const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

lazy_static! {
    static ref LD_SO_CACHE: Result<LdSoCache, Arc<io::Error>> =
        LdSoCache::load(LD_SO_CACHE_FILE).map_err(Arc::new);
}
const LD_SO_CACHE_HEADER: &str = "glibc-ld.so.cache1.1";

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
        let target = target.as_ref();
        let target_str = &*target.as_os_str().to_string_lossy();

        let mut path = if let Some(pid) = pid {
            let proc_map_libs =
                ProcMap::new(pid).map_err(|e| UProbeError::ProcMapError { pid, source: e })?;
            proc_map_libs
                .find_by_name(target_str)
                .map_err(|io_error| UProbeError::FileError {
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
                let cache =
                    LD_SO_CACHE
                        .as_ref()
                        .map_err(|error| UProbeError::InvalidLdSoCache {
                            io_error: error.clone(),
                        })?;
                cache.resolve(target_str)
            }
            .map(String::from)
        };

        let path = path.ok_or(UProbeError::InvalidTarget {
            path: target.to_owned(),
        })?;

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
}

define_link_wrapper!(
    /// The link used by [UProbe] programs.
    UProbeLink,
    /// The type returned by [UProbe::attach]. Can be passed to [UProbe::detach].
    UProbeLinkId,
    PerfLink,
    PerfLinkId
);

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

        let mut buf = [0u8; LD_SO_CACHE_HEADER.len()];
        cursor.read_exact(&mut buf)?;
        let header = std::str::from_utf8(&buf).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid ld.so.cache header")
        })?;
        if header != LD_SO_CACHE_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ld.so.cache header",
            ));
        }

        let num_entries = read_u32(&mut cursor)?;
        let _str_tab_len = read_u32(&mut cursor)?;
        cursor.consume(5 * mem::size_of::<u32>());

        let mut entries = Vec::new();
        for _ in 0..num_entries {
            let flags = read_i32(&mut cursor)?;
            let k_pos = read_u32(&mut cursor)? as usize;
            let v_pos = read_u32(&mut cursor)? as usize;
            cursor.consume(12);
            let key =
                unsafe { CStr::from_ptr(cursor.get_ref()[k_pos..].as_ptr() as *const c_char) }
                    .to_string_lossy()
                    .into_owned();
            let value =
                unsafe { CStr::from_ptr(cursor.get_ref()[v_pos..].as_ptr() as *const c_char) }
                    .to_string_lossy()
                    .into_owned();
            entries.push(CacheEntry {
                key,
                value,
                _flags: flags,
            });
        }

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
}

fn resolve_symbol(path: &str, symbol: &str) -> Result<u64, ResolveSymbolError> {
    let data = fs::read(path)?;
    let obj = object::read::File::parse(&*data)?;

    obj.dynamic_symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().map(|name| name == symbol).unwrap_or(false))
        .map(|s| s.address())
        .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))
}

/// Error reading from /proc/pid/maps
#[derive(Debug, Error)]
pub enum ProcMapError {
    /// An [`io::Error`]
    #[error(transparent)]
    IoError(io::Error),

    /// Error parsing a line of /proc/pid/maps
    #[error("proc map entry parse error")]
    ParseError,
}

pub(crate) struct ProcMap {
    _entries: Vec<ProcMapEntry>,
    paths: HashMap<String, String>,
}

impl ProcMap {
    fn new(pid: pid_t) -> Result<Self, ProcMapError> {
        let maps_file = format!("/proc/{}/maps", pid);
        let data = fs::read_to_string(maps_file).map_err(ProcMapError::IoError)?;
        let mut entries = vec![];
        let mut paths = HashMap::new();
        for line in data.lines() {
            let entry = ProcMapEntry::parse(line)?;
            if let Some(path) = &entry.path {
                let p = PathBuf::from(path);
                let key = p.file_name().unwrap().to_string_lossy().into_owned();
                let value = p.to_string_lossy().to_string();
                paths.insert(key, value);
            }
            entries.push(entry);
        }
        Ok(ProcMap {
            _entries: entries,
            paths,
        })
    }

    fn find_by_name(&self, lib: &str) -> Result<Option<String>, io::Error> {
        let ret = if lib.contains(".so") {
            self.paths.iter().find(|(k, _)| k.as_str().starts_with(lib))
        } else {
            let lib = lib.to_string();
            let lib1 = lib.clone() + ".so";
            let lib2 = lib + "-";
            self.paths
                .iter()
                .find(|(k, _)| k.starts_with(&lib1) || k.starts_with(&lib2))
        };

        Ok(ret.map(|(_, v)| v.clone()))
    }
}

pub(crate) struct ProcMapEntry {
    _address: u64,
    _address_end: u64,
    _perms: String,
    _offset: u64,
    _dev: String,
    _inode: u32,
    path: Option<String>,
}

impl ProcMapEntry {
    fn parse(line: &str) -> Result<Self, ProcMapError> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(ProcMapError::ParseError);
        }
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        let address =
            u64::from_str_radix(addr_parts[0], 16).map_err(|_| ProcMapError::ParseError)?;
        let address_end =
            u64::from_str_radix(addr_parts[1], 16).map_err(|_| ProcMapError::ParseError)?;
        let perms = parts[1];
        let offset = u64::from_str_radix(parts[2], 16).map_err(|_| ProcMapError::ParseError)?;
        let dev = parts[3];
        let inode = parts[4].parse().map_err(|_| ProcMapError::ParseError)?;
        let path = if parts.len() == 6 {
            if parts[5].starts_with('/') {
                Some(parts[5].to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(ProcMapEntry {
            _address: address,
            _address_end: address_end,
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

    #[test]
    fn test_parse_proc_map_entry_from_str_1() {
        let s = "7ffd6fbea000-7ffd6fbec000 r-xp 00000000 00:00 0                          [vdso]";
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
    fn test_parse_proc_map_entry_from_str_2() {
        let s = "7f1bca83a000-7f1bca83c000 rw-p 00036000 fd:01 2895508                    /usr/lib64/ld-linux-x86-64.so.2";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        assert_eq!(proc_map._address, 0x7f1bca83a000);
        assert_eq!(proc_map._address_end, 0x7f1bca83c000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map._offset, 0x00036000);
        assert_eq!(proc_map._dev, "fd:01");
        assert_eq!(proc_map._inode, 2895508);
        assert_eq!(
            proc_map.path,
            Some("/usr/lib64/ld-linux-x86-64.so.2".to_string())
        );
    }

    #[test]
    fn test_parse_proc_map_entry_from_str_3() {
        let s = "7f1bca5f9000-7f1bca601000 rw-p 00000000 00:00 0";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        assert_eq!(proc_map._address, 0x7f1bca5f9000);
        assert_eq!(proc_map._address_end, 0x7f1bca601000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map._offset, 0x0);
        assert_eq!(proc_map._dev, "00:00");
        assert_eq!(proc_map._inode, 0);
        assert_eq!(proc_map.path, None);
    }
}
