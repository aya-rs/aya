use std::{
    collections::HashMap,
    error::Error,
    fs, io,
    os::raw::c_int,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{
    generated::{
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY, AYA_PERF_EVENT_IOC_DISABLE,
        AYA_PERF_EVENT_IOC_ENABLE, AYA_PERF_EVENT_IOC_SET_BPF,
    },
    maps::{Map, MapError, MapLock, MapRef, MapRefMut},
    obj::{
        btf::{Btf, BtfError},
        Object, ParseError, ProgramSection,
    },
    programs::{
        CgroupSkb, CgroupSkbAttachType, KProbe, LircMode2, ProbeKind, Program, ProgramData,
        ProgramError, SchedClassifier, SkMsg, SkSkb, SkSkbKind, SockOps, SocketFilter, TracePoint,
        UProbe, Xdp,
    },
    sys::bpf_map_update_elem_ptr,
    util::{possible_cpus, POSSIBLE_CPUS},
};

pub(crate) const BPF_OBJ_NAME_LEN: usize = 16;

pub(crate) const PERF_EVENT_IOC_ENABLE: c_int = AYA_PERF_EVENT_IOC_ENABLE;
pub(crate) const PERF_EVENT_IOC_DISABLE: c_int = AYA_PERF_EVENT_IOC_DISABLE;
pub(crate) const PERF_EVENT_IOC_SET_BPF: c_int = AYA_PERF_EVENT_IOC_SET_BPF;

/// Marker trait for types that can safely be converted to and from byte slices.
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
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub(crate) struct bpf_map_def {
    // minimum features required by old BPF programs
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    // optional features
    pub(crate) id: u32,
    pub(crate) pinning: u32,
}

/// The main entry point into the library, used to work with eBPF programs and maps.
#[derive(Debug)]
pub struct Bpf {
    maps: HashMap<String, MapLock>,
    programs: HashMap<String, Program>,
}

impl Bpf {
    /// Loads eBPF bytecode from a file.
    ///
    /// Parses the given object code file and initializes the [maps](crate::maps) defined in it. If
    /// the kernel supports [BTF](Btf) debug info, it is automatically loaded from
    /// `/sys/kernel/btf/vmlinux`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::Bpf;
    ///
    /// let bpf = Bpf::load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Bpf, BpfError> {
        let path = path.as_ref();
        Bpf::load(
            &fs::read(path).map_err(|error| BpfError::FileError {
                path: path.to_owned(),
                error,
            })?,
            Btf::from_sys_fs().ok(),
        )
    }

    /// Load eBPF bytecode.
    ///
    /// Parses the object code contained in `data` and initializes the [maps](crate::maps) defined
    /// in it. If `target_btf` is not `None` and `data` includes BTF debug info, [BTF](Btf) relocations
    /// are applied as well.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::{Bpf, Btf};
    /// use std::fs;
    ///
    /// let data = fs::read("file.o").unwrap();
    /// // load the BTF data from /sys/kernel/btf/vmlinux
    /// let bpf = Bpf::load(&data, Some(Btf::from_sys_fs()?));
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn load(data: &[u8], target_btf: Option<Btf>) -> Result<Bpf, BpfError> {
        let mut obj = Object::parse(data)?;

        if let Some(btf) = target_btf {
            obj.relocate_btf(btf)?;
        }

        let mut maps = Vec::new();
        for (_, mut obj) in obj.maps.drain() {
            if obj.def.map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 && obj.def.max_entries == 0
            {
                obj.def.max_entries = possible_cpus()
                    .map_err(|error| BpfError::FileError {
                        path: PathBuf::from(POSSIBLE_CPUS),
                        error,
                    })?
                    .len() as u32;
            }
            let mut map = Map { obj, fd: None };
            let fd = map.create()?;
            if !map.obj.data.is_empty() && map.obj.name != ".bss" {
                bpf_map_update_elem_ptr(fd, &0 as *const _, map.obj.data.as_mut_ptr(), 0).map_err(
                    |(code, io_error)| MapError::SyscallError {
                        call: "bpf_map_update_elem".to_owned(),
                        code,
                        io_error,
                    },
                )?;
            }
            maps.push(map);
        }

        obj.relocate_maps(maps.as_slice())?;
        obj.relocate_calls()?;

        let programs = obj
            .programs
            .drain()
            .map(|(name, obj)| {
                let section = obj.section.clone();
                let data = ProgramData {
                    obj,
                    name: name.clone(),
                    fd: None,
                    links: Vec::new(),
                };
                let program = match section {
                    ProgramSection::KProbe { .. } => Program::KProbe(KProbe {
                        data,
                        kind: ProbeKind::KProbe,
                    }),
                    ProgramSection::KRetProbe { .. } => Program::KProbe(KProbe {
                        data,
                        kind: ProbeKind::KRetProbe,
                    }),
                    ProgramSection::UProbe { .. } => Program::UProbe(UProbe {
                        data,
                        kind: ProbeKind::UProbe,
                    }),
                    ProgramSection::URetProbe { .. } => Program::UProbe(UProbe {
                        data,
                        kind: ProbeKind::URetProbe,
                    }),
                    ProgramSection::TracePoint { .. } => Program::TracePoint(TracePoint { data }),
                    ProgramSection::SocketFilter { .. } => {
                        Program::SocketFilter(SocketFilter { data })
                    }
                    ProgramSection::Xdp { .. } => Program::Xdp(Xdp { data }),
                    ProgramSection::SkMsg { .. } => Program::SkMsg(SkMsg { data }),
                    ProgramSection::SkSkbStreamParser { .. } => Program::SkSkb(SkSkb {
                        data,
                        kind: SkSkbKind::StreamParser,
                    }),
                    ProgramSection::SkSkbStreamVerdict { .. } => Program::SkSkb(SkSkb {
                        data,
                        kind: SkSkbKind::StreamVerdict,
                    }),
                    ProgramSection::SockOps { .. } => Program::SockOps(SockOps { data }),
                    ProgramSection::SchedClassifier { .. } => {
                        Program::SchedClassifier(SchedClassifier { data })
                    }
                    ProgramSection::CgroupSkbIngress { .. } => Program::CgroupSkb(CgroupSkb {
                        data,
                        expected_attach_type: Some(CgroupSkbAttachType::Ingress),
                    }),
                    ProgramSection::CgroupSkbEgress { .. } => Program::CgroupSkb(CgroupSkb {
                        data,
                        expected_attach_type: Some(CgroupSkbAttachType::Egress),
                    }),
                    ProgramSection::LircMode2 { .. } => Program::LircMode2(LircMode2 { data }),
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

    /// Returns a reference to the map with the given name.
    ///
    /// The returned type is mostly opaque. In order to do anything useful with it you need to
    /// convert it to a [typed map](crate::maps).
    ///
    /// For more details and examples on maps and their usage, see the [maps module
    /// documentation][crate::maps].
    ///
    /// # Errors
    ///
    /// Returns [`MapError::MapNotFound`] if the map does not exist. If the map is already borrowed
    /// mutably with [map_mut](Self::map_mut) then [`MapError::BorrowError`] is returned.
    pub fn map(&self, name: &str) -> Result<MapRef, MapError> {
        self.maps
            .get(name)
            .ok_or_else(|| MapError::MapNotFound {
                name: name.to_owned(),
            })
            .and_then(|lock| {
                lock.try_read().map_err(|_| MapError::BorrowError {
                    name: name.to_owned(),
                })
            })
    }

    /// Returns a mutable reference to the map with the given name.
    ///
    /// The returned type is mostly opaque. In order to do anything useful with it you need to
    /// convert it to a [typed map](crate::maps).
    ///
    /// For more details and examples on maps and their usage, see the [maps module
    /// documentation][crate::maps].
    ///
    /// # Errors
    ///
    /// Returns [`MapError::MapNotFound`] if the map does not exist. If the map is already borrowed
    /// mutably with [map_mut](Self::map_mut) then [`MapError::BorrowError`] is returned.
    pub fn map_mut(&self, name: &str) -> Result<MapRefMut, MapError> {
        self.maps
            .get(name)
            .ok_or_else(|| MapError::MapNotFound {
                name: name.to_owned(),
            })
            .and_then(|lock| {
                lock.try_write().map_err(|_| MapError::BorrowError {
                    name: name.to_owned(),
                })
            })
    }

    /// An iterator over all the maps.
    ///
    /// # Examples
    /// ```no_run
    /// # let mut bpf = aya::Bpf::load(&[], None)?;
    /// for (name, map) in bpf.maps() {
    ///     println!(
    ///         "found map `{}` of type `{:?}`",
    ///         name,
    ///         map?.map_type().unwrap()
    ///     );
    /// }
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn maps(&self) -> impl Iterator<Item = (&str, Result<MapRef, MapError>)> {
        let ret = self.maps.iter().map(|(name, lock)| {
            (
                name.as_str(),
                lock.try_read()
                    .map_err(|_| MapError::BorrowError { name: name.clone() }),
            )
        });
        ret
    }

    /// Returns a reference to the program with the given name.
    ///
    /// You can use this to inspect a program and its properties. To load and attach a program, use
    /// [program_mut](Self::program_mut) instead.
    ///
    /// For more details on programs and their usage, see the [programs module
    /// documentation](crate::programs).
    ///
    /// # Errors
    ///
    /// Returns [`ProgramError::NotFound`] if the program does not exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let bpf = aya::Bpf::load(&[], None)?;
    /// let program = bpf.program("SSL_read")?;
    /// println!("program SSL_read is of type {:?}", program.prog_type());
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn program(&self, name: &str) -> Result<&Program, ProgramError> {
        self.programs
            .get(name)
            .ok_or_else(|| ProgramError::NotFound {
                name: name.to_owned(),
            })
    }

    /// Returns a mutable reference to the program with the given name.
    ///
    /// Used to get a program before loading and attaching it. For more details on programs and
    /// their usage, see the [programs module documentation](crate::programs).
    ///
    /// # Errors
    ///
    /// Returns [`ProgramError::NotFound`] if the program does not exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut bpf = aya::Bpf::load(&[], None)?;
    /// use aya::programs::UProbe;
    /// use std::convert::TryInto;
    ///
    /// let program: &mut UProbe = bpf.program_mut("SSL_read")?.try_into()?;
    /// program.load()?;
    /// program.attach(Some("SSL_read"), 0, "libssl", None)?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn program_mut(&mut self, name: &str) -> Result<&mut Program, ProgramError> {
        self.programs
            .get_mut(name)
            .ok_or_else(|| ProgramError::NotFound {
                name: name.to_owned(),
            })
    }

    /// An iterator over all the programs.
    ///
    /// # Examples
    /// ```no_run
    /// # let mut bpf = aya::Bpf::load(&[], None)?;
    /// for program in bpf.programs() {
    ///     println!(
    ///         "found program `{}` of type `{:?}`",
    ///         program.name(),
    ///         program.prog_type()
    ///     );
    /// }
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn programs(&self) -> impl Iterator<Item = &Program> {
        self.programs.values()
    }
}

/// The error type returned by [`Bpf::load_file`] and [`Bpf::load`].
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

    #[error("error relocating `{function}`")]
    RelocationError {
        function: String,
        #[source]
        error: Box<dyn Error + Send + Sync>,
    },

    #[error("map error")]
    MapError(#[from] MapError),

    #[error("program error")]
    ProgramError(#[from] ProgramError),
}
