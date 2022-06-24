//! Common functions shared between multiple eBPF program types.
use libc::pid_t;
use object::{Object, ObjectSymbol};
use std::{
    collections::HashMap,
    ffi::CStr,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    os::{raw::c_char, unix::prelude::RawFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

use crate::{
    programs::{FdLink, Link, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// Attaches the program to a raw tracepoint.
pub(crate) fn attach_raw_tracepoint<T: Link + From<FdLink>>(
    program_data: &mut ProgramData<T>,
    tp_name: Option<&CStr>,
) -> Result<T::Id, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;

    let pfd = bpf_raw_tracepoint_open(tp_name, prog_fd).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "bpf_raw_tracepoint_open".to_owned(),
            io_error,
        }
    })? as RawFd;

    program_data.links.insert(FdLink::new(pfd).into())
}

pub(crate) const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

lazy_static! {
    pub(crate) static ref LD_SO_CACHE: Result<LdSoCache, Arc<io::Error>> =
        LdSoCache::load(LD_SO_CACHE_FILE).map_err(Arc::new);
}
const LD_SO_CACHE_HEADER: &str = "glibc-ld.so.cache1.1";
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
pub(crate) enum ResolveSymbolError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("error parsing ELF")]
    Object(#[from] object::Error),

    #[error("unknown symbol `{0}`")]
    Unknown(String),
}

pub(crate) fn resolve_symbol(path: &str, symbol: &str) -> Result<u64, ResolveSymbolError> {
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
    entries: Vec<ProcMapEntry>,
    paths: HashMap<String, String>,
}

impl ProcMap {
    pub(crate) fn new(pid: pid_t) -> Result<Self, ProcMapError> {
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
        Ok(ProcMap { entries, paths })
    }

    pub(crate) fn find_by_name(&self, lib: &str) -> Result<Option<String>, io::Error> {
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

    pub(crate) fn find_by_offset(&self, offset: u64) -> Option<&ProcMapEntry> {
        for e in &self.entries {
            if e.offset <= offset && offset < e.offset + (e.address_end - e.address) {
                return Some(e);
            }
        }
        None
    }
}

pub(crate) struct ProcMapEntry {
    pub address: u64,
    pub address_end: u64,
    _perms: String,
    pub offset: u64,
    _dev: String,
    _inode: u32,
    pub path: Option<String>,
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
            address,
            address_end,
            _perms: perms.to_string(),
            offset,
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
        assert_eq!(proc_map.address, 0x7ffd6fbea000);
        assert_eq!(proc_map.address_end, 0x7ffd6fbec000);
        assert_eq!(proc_map._perms, "r-xp");
        assert_eq!(proc_map.offset, 0x0);
        assert_eq!(proc_map._dev, "00:00");
        assert_eq!(proc_map._inode, 0);
        assert_eq!(proc_map.path, None);
    }

    #[test]
    fn test_parse_proc_map_entry_from_str_2() {
        let s = "7f1bca83a000-7f1bca83c000 rw-p 00036000 fd:01 2895508                    /usr/lib64/ld-linux-x86-64.so.2";
        let proc_map = ProcMapEntry::parse(s).unwrap();
        assert_eq!(proc_map.address, 0x7f1bca83a000);
        assert_eq!(proc_map.address_end, 0x7f1bca83c000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map.offset, 0x00036000);
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
        assert_eq!(proc_map.address, 0x7f1bca5f9000);
        assert_eq!(proc_map.address_end, 0x7f1bca601000);
        assert_eq!(proc_map._perms, "rw-p");
        assert_eq!(proc_map.offset, 0x0);
        assert_eq!(proc_map._dev, "00:00");
        assert_eq!(proc_map._inode, 0);
        assert_eq!(proc_map.path, None);
    }
}
