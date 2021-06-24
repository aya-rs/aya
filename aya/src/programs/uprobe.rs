//! User space probes.
use std::{
    error::Error,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
};

use libc::pid_t;
use object::{Object, ObjectSymbol};
use thiserror::Error;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_KPROBE,
    programs::{
        LinkRef,
        load_program,
        probe::{attach, ProbeKind}, ProgramData, ProgramError,
    },
};

const LD_SO_CACHE_FILE: &str = "/etc/ld.so.cache";

lazy_static! {
    static ref LD_SO_CACHE: Result<LdSoCache, Arc<io::Error>> =
        LdSoCache::load(LD_SO_CACHE_FILE).map_err(Arc::new);
}
const LD_SO_CACHE_HEADER: &str = "glibc-ld.so.cache1.1";
const LD_SO_CACHE_HEADER_OLD: &str = "ld.so-1.7.0";

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
    pub(crate) data: ProgramData,
    pub(crate) kind: ProbeKind,
}

impl UProbe {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
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
    /// function.  Instead if the program is a `kretprobe`, it is attached to the return address of
    /// the target function.
    ///
    pub fn attach<T: AsRef<Path>>(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: T,
        pid: Option<pid_t>,
    ) -> Result<LinkRef, ProgramError> {
        let target = target.as_ref();
        let target_str = &*target.as_os_str().to_string_lossy();

        let mut path = if let Some(pid) = pid {
            find_lib_in_proc_maps(pid, &target_str).map_err(|io_error| UProbeError::FileError {
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
}

/// The type returned when attaching an [`UProbe`] fails.
#[derive(Debug, Error)]
pub enum UProbeError {
    /// There was an error parsing `/etc/ld.so.cache`.
    #[error("error reading `{}` file", LD_SO_CACHE_FILE)]
    InvalidLdSoCache {
        #[source]
        io_error: Arc<io::Error>,
    },

    /// The target program could not be found.
    #[error("could not resolve uprobe target `{path}`")]
    InvalidTarget { path: PathBuf },

    /// There was an error resolving the target symbol.
    #[error("error resolving symbol")]
    SymbolError {
        symbol: String,
        #[source]
        error: Box<dyn Error + Send + Sync>,
    },

    /// There was an error accessing `filename`.
    #[error("`{filename}`")]
    FileError {
        filename: String,
        #[source]
        io_error: io::Error,
    },
}

fn proc_maps_libs(pid: pid_t) -> Result<Vec<(String, String)>, io::Error> {
    let maps_file = format!("/proc/{}/maps", pid);
    let data = fs::read_to_string(maps_file)?;

    Ok(data
        .lines()
        .filter_map(|line| {
            let line = line.split_whitespace().last()?;
            if line.starts_with('/') {
                let path = PathBuf::from(line);
                let key = path.file_name().unwrap().to_string_lossy().into_owned();
                Some((key, path.to_string_lossy().to_string()))
            } else {
                None
            }
        })
        .collect())
}

fn find_lib_in_proc_maps(pid: pid_t, lib: &str) -> Result<Option<String>, io::Error> {
    let libs = proc_maps_libs(pid)?;

    let ret = if lib.contains(".so") {
        libs.iter().find(|(k, _)| k.as_str().starts_with(lib))
    } else {
        let lib = lib.to_string();
        let lib1 = lib.clone() + ".so";
        let lib2 = lib + "-";
        libs.iter()
            .find(|(k, _)| k.starts_with(&lib1) || k.starts_with(&lib2))
    };

    Ok(ret.map(|(_, v)| v.clone()))
}

#[derive(Debug)]
pub(crate) struct CacheEntry {
    lib_name: String,
    path: String,
    flags: i32,
}

#[derive(Debug)]
pub(crate) struct LdSoCache {
    entries: Vec<CacheEntry>,
}

#[allow(unused)]
#[derive(Copy, Clone, Debug)]
pub enum TargetEndian {
    Native,
    Big,
    Little,
}

impl LdSoCache {
    pub fn load<T: AsRef<Path>>(path: T) -> Result<Self, io::Error> {
        let data = fs::read(path)?;
        Self::parse(&data, TargetEndian::Native)
    }

    fn parse(data: &[u8], endianness: TargetEndian) -> Result<Self, io::Error> {
        let mut cursor = Cursor::new(data);

        let read_u32 = |cursor: &mut Cursor<_>| -> Result<u32, io::Error> {
            let mut buf = [0u8; mem::size_of::<u32>()];
            cursor.read_exact(&mut buf)?;

            Ok(match endianness {
                TargetEndian::Native => u32::from_ne_bytes(buf),
                TargetEndian::Big => u32::from_be_bytes(buf),
                TargetEndian::Little => u32::from_le_bytes(buf),
            })
        };

        let read_i32 = |cursor: &mut Cursor<_>| -> Result<i32, io::Error> {
            let mut buf = [0u8; mem::size_of::<i32>()];
            cursor.read_exact(&mut buf)?;
            Ok(match endianness {
                TargetEndian::Native => i32::from_ne_bytes(buf),
                TargetEndian::Big => i32::from_be_bytes(buf),
                TargetEndian::Little => i32::from_le_bytes(buf),
            })
        };

        let mut buf = [0u8; LD_SO_CACHE_HEADER.len()];
        let mut buf_old = [0u8; LD_SO_CACHE_HEADER_OLD.len()];
        cursor.read_exact(&mut buf)?;
        cursor.set_position(0);
        cursor.read_exact(&mut buf_old)?;
        let header = std::str::from_utf8(&buf).or(
            std::str::from_utf8(&buf_old).or(
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid ld.so.cache header",
                ))
            )
        )?;
        let mut is_old: bool = false;
        match header {
            LD_SO_CACHE_HEADER => {
                // we have to reset the position since we found the new header
                cursor.set_position(LD_SO_CACHE_HEADER.len() as u64);
            }
            LD_SO_CACHE_HEADER_OLD => {
                is_old = true;
                // add a padding corresponding to LD_SO_CACHE_HEADER_OLD
                // size 11 + 1 to align on 12 bytes or 3*4 bounds
                cursor.consume(1)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid ld.so.cache header",
                ));
            }
        }

        let num_entries: u32 = read_u32(&mut cursor)?;
        let mut string_table_offset: usize = 0;
        if !is_old {
            let _str_tab_len = read_u32(&mut cursor)?;
            // those are as of glibc 2.33 (flags u8, empty 3xu8, extension_offset u32, unused 3xu32)
            cursor.consume(5 * mem::size_of::<u32>());
        } else {
            // only 3 u32 were present in the old entries
            string_table_offset = cursor.position() as usize + num_entries as usize * mem::size_of::<u32>() * 3;
        }

        let mut entries = Vec::new();
        for _ in 0..num_entries {
            let flags = read_i32(&mut cursor)?;
            let k_pos = read_u32(&mut cursor)? as usize;
            let v_pos = read_u32(&mut cursor)? as usize;
            if !is_old {
                // those are as of glibc 2.33 (os_version u32, hwcap u64)
                cursor.consume(mem::size_of::<u32>() + mem::size_of::<u64>());
            }
            let key = Self::str_from_u8_nul_utf8(&cursor.get_ref()[k_pos + string_table_offset..]).map_err(|e| io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid ut8 string : {}", e),
            ))?.to_owned();
            let value = Self::str_from_u8_nul_utf8(&cursor.get_ref()[v_pos + string_table_offset..]).map_err(|e| io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid ut8 string : {}", e),
            ))?.to_owned();
            entries.push(CacheEntry { lib_name: key, path: value, flags });
        }

        Ok(LdSoCache { entries })
    }

    pub fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
        let nul_range_end = utf8_src
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(utf8_src.len()); // default to length if no `\0` present
        ::std::str::from_utf8(&utf8_src[0..nul_range_end])
    }

    pub fn resolve(&self, lib: &str) -> Option<&str> {
        let lib = if !lib.contains(".so") {
            lib.to_string() + ".so"
        } else {
            lib.to_string()
        };
        self.entries
            .iter()
            .find(|entry| entry.lib_name.starts_with(&lib))
            .map(|entry| entry.path.as_str())
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
    let obj = object::read::File::parse(&data)?;

    obj.dynamic_symbols()
        .chain(obj.symbols())
        .find(|sym| sym.name().map(|name| name == symbol).unwrap_or(false))
        .map(|s| s.address())
        .ok_or_else(|| ResolveSymbolError::Unknown(symbol.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_endian_old_format_s390x() {
        let data = include_bytes!("../../tests/fixtures/ld.so.cache_s390x_old");
        let cache = LdSoCache::parse(data, TargetEndian::Big);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.entries.len(), 188);
        let strings: &str = include_str!("../../tests/fixtures/s390x.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_new_format_mips() {
        let data = include_bytes!("../../tests/fixtures/ld.so.cache_mips");
        let cache = LdSoCache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.entries.len(), 2407);
        let strings: &str = include_str!("../../tests/fixtures/mips.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_new_format_debian_x86_64() {
        let data = include_bytes!("../../tests/fixtures/ld.so.cache_debian");
        let cache = LdSoCache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.entries.len(), 81);
        let strings: &str = include_str!("../../tests/fixtures/debian.strings");
        test_entries(strings, cache);
    }

    #[test]
    fn test_little_endian_old_format_debian_x86_64() {
        let data = include_bytes!("../../tests/fixtures/ld.so.cache_debian_old");
        let cache = LdSoCache::parse(data, TargetEndian::Little);
        assert!(cache.is_ok());
        let cache = cache.unwrap();
        assert_eq!(cache.entries.len(), 148);
        let strings: &str = include_str!("../../tests/fixtures/debian_old.strings");
        test_entries(strings, cache);
    }

    fn test_entries(strings: &str, cache: LdSoCache) {
        for string in strings.split_terminator("\n") {
            let (lib_name, path) = string.split_once(" ").unwrap();
            assert!(cache.entries.iter().any(|x| x.lib_name == lib_name), "lib name : {} was not inside the entries", lib_name);
            let found_paths: Vec<&CacheEntry> = cache.entries.iter().filter(|e| e.lib_name == lib_name).collect();
            assert!(!found_paths.is_empty(), "Path was not found for lib name : {}", lib_name);
            assert!(found_paths.iter().any(|e| e.path == path), "lib path : {} was not correct, got {:?}", path, found_paths);
        }
    }
}