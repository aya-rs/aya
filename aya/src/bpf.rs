use std::{
    collections::HashMap,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{
    generated::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    maps::{Map, MapError, MapLock, MapRef, MapRefMut},
    obj::{
        btf::{Btf, BtfError},
        Object, ParseError, ProgramKind,
    },
    programs::{
        probe::ProbeKind, KProbe, Program, ProgramData, ProgramError, SocketFilter, TracePoint,
        UProbe, Xdp,
    },
    sys::bpf_map_update_elem_ptr,
    util::{possible_cpus, POSSIBLE_CPUS},
};

pub(crate) const BPF_OBJ_NAME_LEN: usize = 16;

/* FIXME: these are arch dependent */
pub(crate) const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 9216;
pub(crate) const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 9217;
pub(crate) const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 1074013192;

pub unsafe trait Pod: Copy + 'static {}

macro_rules! unsafe_impl_pod {
    ($($struct_name:ident),+ $(,)?) => {
        $(
            unsafe impl Pod for $struct_name { }
        )+
    }
}

unsafe_impl_pod!(i8, u8, i16, u16, i32, u32, i64, u64);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct bpf_map_def {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
}

#[derive(Debug)]
pub struct Bpf {
    maps: HashMap<String, MapLock>,
    programs: HashMap<String, Program>,
}

impl Bpf {
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Bpf, BpfError> {
        let path = path.as_ref();
        Bpf::load(
            &fs::read(path).map_err(|error| BpfError::FileError {
                path: path.to_owned(),
                error,
            })?,
            Some(Btf::from_sys_fs()?),
        )
    }

    pub fn load(data: &[u8], target_btf: Option<Btf>) -> Result<Bpf, BpfError> {
        let mut obj = Object::parse(data)?;

        if let Some(btf) = target_btf {
            obj.relocate_btf(btf)?;
        }

        let mut maps = Vec::new();
        for (_, mut obj) in obj.maps.drain() {
            if obj.def.map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 && obj.def.max_entries == 0
            {
                obj.def.max_entries = *possible_cpus()
                    .map_err(|error| BpfError::FileError {
                        path: PathBuf::from(POSSIBLE_CPUS),
                        error,
                    })?
                    .last()
                    .unwrap_or(&0);
            }
            let mut map = Map { obj, fd: None };
            let fd = map.create()?;
            if !map.obj.data.is_empty() && map.obj.name != ".bss" {
                bpf_map_update_elem_ptr(fd, &0 as *const _, map.obj.data.as_ptr(), 0)
                    .map_err(|(code, io_error)| MapError::UpdateElementError { code, io_error })?;
            }
            maps.push(map);
        }

        obj.relocate_maps(maps.as_slice())?;
        obj.relocate_calls()?;

        let programs = obj
            .programs
            .drain()
            .map(|(name, obj)| {
                let kind = obj.kind;
                let data = ProgramData {
                    obj,
                    name: name.clone(),
                    fd: None,
                    links: Vec::new(),
                };
                let program = match kind {
                    ProgramKind::KProbe => Program::KProbe(KProbe {
                        data,
                        kind: ProbeKind::KProbe,
                    }),
                    ProgramKind::KRetProbe => Program::KProbe(KProbe {
                        data,
                        kind: ProbeKind::KRetProbe,
                    }),
                    ProgramKind::UProbe => Program::UProbe(UProbe {
                        data,
                        kind: ProbeKind::UProbe,
                    }),
                    ProgramKind::URetProbe => Program::UProbe(UProbe {
                        data,
                        kind: ProbeKind::URetProbe,
                    }),
                    ProgramKind::TracePoint => Program::TracePoint(TracePoint { data }),
                    ProgramKind::SocketFilter => Program::SocketFilter(SocketFilter { data }),
                    ProgramKind::Xdp => Program::Xdp(Xdp { data }),
                };

                (name, program)
            })
            .collect();

        Ok(Bpf {
            maps: maps
                .drain(..)
                .map(|map| (map.obj.name.clone(), MapLock::new(map)))
                .collect(),
            programs,
        })
    }

    pub fn map(&self, name: &str) -> Result<MapRef, MapError> {
        self.maps
            .get(name)
            .ok_or_else(|| MapError::NotFound {
                name: name.to_owned(),
            })
            .and_then(|lock| {
                lock.try_read().map_err(|_| MapError::BorrowError {
                    name: name.to_owned(),
                })
            })
    }

    pub fn map_mut(&self, name: &str) -> Result<MapRefMut, MapError> {
        self.maps
            .get(name)
            .ok_or_else(|| MapError::NotFound {
                name: name.to_owned(),
            })
            .and_then(|lock| {
                lock.try_write().map_err(|_| MapError::BorrowError {
                    name: name.to_owned(),
                })
            })
    }

    pub fn maps<'a>(&'a self) -> impl Iterator<Item = (&'a str, Result<MapRef, MapError>)> + 'a {
        let ret = self.maps.iter().map(|(name, lock)| {
            (
                name.as_str(),
                lock.try_read()
                    .map_err(|_| MapError::BorrowError { name: name.clone() }),
            )
        });
        ret
    }

    pub fn program(&self, name: &str) -> Result<&Program, ProgramError> {
        self.programs
            .get(name)
            .ok_or_else(|| ProgramError::NotFound {
                name: name.to_owned(),
            })
    }

    pub fn program_mut(&mut self, name: &str) -> Result<&mut Program, ProgramError> {
        self.programs
            .get_mut(name)
            .ok_or_else(|| ProgramError::NotFound {
                name: name.to_owned(),
            })
    }

    pub fn programs(&self) -> impl Iterator<Item = &Program> {
        self.programs.values()
    }
}

#[derive(Debug, Error)]
pub enum BpfError {
    #[error("error loading {path}")]
    FileError {
        path: PathBuf,
        #[source]
        error: io::Error,
    },

    #[error("error parsing BPF object")]
    ParseError(#[from] ParseError),

    #[error("BTF error")]
    BtfError(#[from] BtfError),

    #[error("error relocating `{function}`: {error}")]
    RelocationError {
        function: String,
        error: Box<dyn Error + Send + Sync>,
    },

    #[error("map error: {0}")]
    MapError(#[from] MapError),

    #[error("program error: {0}")]
    ProgramError(#[from] ProgramError),
}
