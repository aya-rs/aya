use libc::pid_t;
use object::{Object, ObjectSymbol};
use std::{
    ffi::CStr,
    fs,
    io::{self, BufRead, Cursor, Read},
    mem,
    os::raw::c_char,
    path::{Path, PathBuf},
};
use thiserror::Error;

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_KPROBE,
    programs::{load_program, perf_attach, Link, ProgramData, ProgramError},
    syscalls::perf_event_open_probe,
};

lazy_static! {
    static ref LD_SO_CACHE: Result<LdSoCache, io::Error> = LdSoCache::load("/etc/ld.so.cache");
}
const LD_SO_CACHE_HEADER: &str = "glibc-ld.so.cache1.1";

#[derive(Debug)]
pub struct KProbe {
    pub(crate) data: ProgramData,
}

#[derive(Debug)]
pub struct UProbe {
    pub(crate) data: ProgramData,
}

impl KProbe {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    pub fn attach(
        &mut self,
        fn_name: &str,
        offset: u64,
        pid: Option<pid_t>,
    ) -> Result<impl Link, ProgramError> {
        attach(&mut self.data, ProbeKind::KProbe, fn_name, offset, pid)
    }
}

impl UProbe {
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_KPROBE, &mut self.data)
    }

    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    pub fn attach<T: AsRef<Path>>(
        &mut self,
        fn_name: Option<&str>,
        offset: u64,
        target: T,
        pid: Option<pid_t>,
    ) -> Result<impl Link, ProgramError> {
        let target = target.as_ref();
        let target_str = &*target.as_os_str().to_string_lossy();

        let mut path = if let Some(pid) = pid {
            find_lib_in_proc_maps(pid, &target_str).map_err(|io_error| ProgramError::Other {
                message: format!("error parsing /proc/{}/maps: {}", pid, io_error),
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
                        .map_err(|io_error| ProgramError::InvalidLdSoCache {
                            error_kind: io_error.kind(),
                        })?;
                cache.resolve(target_str)
            }
            .map(String::from)
        };

        let path = path.ok_or(ProgramError::InvalidUprobeTarget {
            path: target.to_owned(),
        })?;

        let sym_offset = if let Some(fn_name) = fn_name {
            resolve_symbol(&path, fn_name).map_err(|error| ProgramError::UprobeSymbolError {
                symbol: fn_name.to_string(),
                error: error.to_string(),
            })?
        } else {
            0
        };

        attach(
            &mut self.data,
            ProbeKind::UProbe,
            &path,
            sym_offset + offset,
            pid,
        )
    }
}

enum ProbeKind {
    KProbe,
    KRetProbe,
    UProbe,
    URetProbe,
}

fn attach(
    program_data: &mut ProgramData,
    kind: ProbeKind,
    name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<impl Link, ProgramError> {
    use ProbeKind::*;

    let perf_ty = read_sys_fs_perf_type(match kind {
        KProbe | KRetProbe => "kprobe",
        UProbe | URetProbe => "uprobe",
    })?;
    let ret_bit = match kind {
        KRetProbe => Some(read_sys_fs_perf_ret_probe("kprobe")?),
        URetProbe => Some(read_sys_fs_perf_ret_probe("uprobe")?),
        _ => None,
    };

    let fd = perf_event_open_probe(perf_ty, ret_bit, name, offset, pid)
        .map_err(|(_code, io_error)| ProgramError::PerfEventOpenFailed { io_error })?
        as i32;

    perf_attach(program_data, fd)
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
    key: String,
    value: String,
    flags: i32,
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
        let header = std::str::from_utf8(&buf).or(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ld.so.cache header",
        )))?;
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
            entries.push(CacheEntry { key, value, flags });
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
    #[error("io error {0}")]
    Io(#[from] io::Error),

    #[error("error parsing ELF {0}")]
    Object(#[from] object::Error),

    #[error("unknown symbol {0}")]
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

pub fn read_sys_fs_perf_type(pmu: &str) -> Result<u32, ProgramError> {
    let file = format!("/sys/bus/event_source/devices/{}/type", pmu);

    let perf_ty = fs::read_to_string(&file).map_err(|e| ProgramError::Other {
        message: format!("error parsing {}: {}", file, e),
    })?;
    let perf_ty = perf_ty
        .trim()
        .parse::<u32>()
        .map_err(|e| ProgramError::Other {
            message: format!("error parsing {}: {}", file, e),
        })?;

    Ok(perf_ty)
}

pub fn read_sys_fs_perf_ret_probe(pmu: &str) -> Result<u32, ProgramError> {
    let file = format!("/sys/bus/event_source/devices/{}/format/retprobe", pmu);

    let data = fs::read_to_string(&file).map_err(|e| ProgramError::Other {
        message: format!("error parsing {}: {}", file, e),
    })?;

    let mut parts = data.trim().splitn(2, ":").skip(1);
    let config = parts.next().ok_or(ProgramError::Other {
        message: format!("error parsing {}: `{}'", file, data),
    })?;
    config.parse::<u32>().map_err(|e| ProgramError::Other {
        message: format!("error parsing {}: {}", file, e),
    })
}
