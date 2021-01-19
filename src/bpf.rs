use std::collections::HashMap;

use thiserror::Error;

use crate::{
    generated::bpf_insn,
    maps::{Map, MapError},
    obj::{relocate, Object, ParseError, RelocationError},
    programs::{KProbe, Program, ProgramData, ProgramError, SocketFilter, TracePoint, UProbe, Xdp},
    syscalls::bpf_map_update_elem_ptr,
};

unsafe impl object::Pod for bpf_insn {}

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

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct bpf_map_def {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
}

unsafe impl object::Pod for bpf_map_def {}

#[derive(Debug)]
pub struct Bpf {
    maps: HashMap<String, Map>,
    programs: HashMap<String, Program>,
}

impl Bpf {
    pub fn load(data: &[u8]) -> Result<Bpf, BpfError> {
        let mut obj = Object::parse(data)?;

        let mut maps = Vec::new();
        for (_, obj) in obj.maps.drain() {
            let mut map = Map { obj, fd: None };
            let fd = map.create()?;
            if !map.obj.data.is_empty() && map.obj.name != ".bss" {
                bpf_map_update_elem_ptr(fd, &0 as *const _, map.obj.data.as_ptr(), 0)
                    .map_err(|(code, io_error)| MapError::UpdateElementFailed { code, io_error })?;
            }
            maps.push(map);
        }

        relocate(&mut obj, maps.as_slice())?;

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
                    crate::obj::ProgramKind::KProbe => Program::KProbe(KProbe { data }),
                    crate::obj::ProgramKind::UProbe => Program::UProbe(UProbe { data }),
                    crate::obj::ProgramKind::TracePoint => Program::TracePoint(TracePoint { data }),
                    crate::obj::ProgramKind::Xdp => Program::Xdp(Xdp { data }),
                };

                (name, program)
            })
            .collect();

        Ok(Bpf {
            maps: maps
                .drain(..)
                .map(|map| (map.obj.name.clone(), map))
                .collect(),
            programs,
        })
    }

    pub fn map(&self, name: &str) -> Option<&Map> {
        self.maps.get(name)
    }

    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.maps.get_mut(name)
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.programs.get(name)
    }

    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.get_mut(name)
    }

    pub fn kprobe(&self, name: &str) -> Option<&KProbe> {
        match self.programs.get(name) {
            Some(Program::KProbe(kprobe)) => Some(kprobe),
            _ => None,
        }
    }

    pub fn kprobe_mut(&mut self, name: &str) -> Option<&mut KProbe> {
        match self.programs.get_mut(name) {
            Some(Program::KProbe(kprobe)) => Some(kprobe),
            _ => None,
        }
    }

    pub fn uprobe(&self, name: &str) -> Option<&UProbe> {
        match self.programs.get(name) {
            Some(Program::UProbe(uprobe)) => Some(uprobe),
            _ => None,
        }
    }

    pub fn uprobe_mut(&mut self, name: &str) -> Option<&mut UProbe> {
        match self.programs.get_mut(name) {
            Some(Program::UProbe(uprobe)) => Some(uprobe),
            _ => None,
        }
    }

    pub fn trace_point(&self, name: &str) -> Option<&TracePoint> {
        match self.programs.get(name) {
            Some(Program::TracePoint(trace_point)) => Some(trace_point),
            _ => None,
        }
    }

    pub fn trace_point_mut(&mut self, name: &str) -> Option<&mut TracePoint> {
        match self.programs.get_mut(name) {
            Some(Program::TracePoint(trace_point)) => Some(trace_point),
            _ => None,
        }
    }

    pub fn socket_filter(&self, name: &str) -> Option<&SocketFilter> {
        match self.programs.get(name) {
            Some(Program::SocketFilter(socket_filter)) => Some(socket_filter),
            _ => None,
        }
    }

    pub fn socket_filter_mut(&mut self, name: &str) -> Option<&mut SocketFilter> {
        match self.programs.get_mut(name) {
            Some(Program::SocketFilter(socket_filter)) => Some(socket_filter),
            _ => None,
        }
    }

    pub fn xdp(&self, name: &str) -> Option<&Xdp> {
        match self.programs.get(name) {
            Some(Program::Xdp(xdp)) => Some(xdp),
            _ => None,
        }
    }

    pub fn xdp_mut(&mut self, name: &str) -> Option<&mut Xdp> {
        match self.programs.get_mut(name) {
            Some(Program::Xdp(xdp)) => Some(xdp),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum BpfError {
    #[error("error parsing BPF object: {0}")]
    ParseError(#[from] ParseError),
    #[error("error relocating BPF object: {0}")]
    RelocationError(#[from] RelocationError),
    #[error("map error: {0}")]
    MapError(#[from] MapError),
    #[error("program error: {0}")]
    ProgramError(#[from] ProgramError),
}
