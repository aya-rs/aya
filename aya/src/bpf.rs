use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    ffi::CString,
    fs, io,
    os::{raw::c_int, unix::io::RawFd},
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
        BtfTracePoint, CgroupSkb, CgroupSkbAttachType, FEntry, FExit, KProbe, LircMode2, Lsm,
        PerfEvent, ProbeKind, Program, ProgramData, ProgramError, RawTracePoint, SchedClassifier,
        SkMsg, SkSkb, SkSkbKind, SockOps, SocketFilter, TracePoint, UProbe, Xdp,
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

unsafe_impl_pod!(i8, u8, i16, u16, i32, u32, i64, u64, u128, i128);

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
    pub(crate) pinning: PinningType,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum PinningType {
    None = 0,
    #[allow(dead_code)] // ByName is constructed from the BPF side
    ByName = 1,
}

impl Default for PinningType {
    fn default() -> Self {
        PinningType::None
    }
}

/// Builder style API for advanced loading of eBPF programs.
///
/// Loading eBPF code involves a few steps, including loading maps and applying
/// relocations. You can use `BpfLoader` to customize some of the loading
/// options.
///
/// # Examples
///
/// ```no_run
/// use aya::{BpfLoader, Btf};
/// use std::fs;
///
/// let bpf = BpfLoader::new()
///     // load the BTF data from /sys/kernel/btf/vmlinux
///     .btf(Btf::from_sys_fs().ok().as_ref())
///     // load pinned maps from /sys/fs/bpf/my-program
///     .map_pin_path("/sys/fs/bpf/my-program")
///     // finally load the code
///     .load_file("file.o")?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
pub struct BpfLoader<'a> {
    btf: Option<Cow<'a, Btf>>,
    map_pin_path: Option<PathBuf>,
}

impl<'a> BpfLoader<'a> {
    /// Creates a new loader instance.
    pub fn new() -> BpfLoader<'a> {
        BpfLoader {
            btf: Btf::from_sys_fs().ok().map(Cow::Owned),
            map_pin_path: None,
        }
    }

    /// Sets the target [BTF](Btf) info.
    ///
    /// The loader defaults to loading `BTF` info using [Btf::from_sys_fs].
    /// Use this method if you want to load `BTF` from a custom location or
    /// pass `None` to disable `BTF` relocations entirely.
    /// # Example
    ///
    /// ```no_run
    /// use aya::{BpfLoader, Btf, Endianness};
    ///
    /// let bpf = BpfLoader::new()
    ///     // load the BTF data from a custom location
    ///     .btf(Btf::parse_file("/custom_btf_file", Endianness::default()).ok().as_ref())
    ///     .load_file("file.o")?;
    ///
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn btf(&mut self, btf: Option<&'a Btf>) -> &mut BpfLoader<'a> {
        self.btf = btf.map(Cow::Borrowed);
        self
    }

    /// Sets the base directory path for pinned maps.
    ///
    /// Pinned maps will be loaded from `path/MAP_NAME`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new()
    ///     .map_pin_path("/sys/fs/bpf/my-program")
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn map_pin_path<P: AsRef<Path>>(&mut self, path: P) -> &mut BpfLoader<'a> {
        self.map_pin_path = Some(path.as_ref().to_owned());
        self
    }

    /// Loads eBPF bytecode from a file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new().load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Bpf, BpfError> {
        let path = path.as_ref();
        self.load(&fs::read(path).map_err(|error| BpfError::FileError {
            path: path.to_owned(),
            error,
        })?)
    }

    /// Loads eBPF bytecode from a buffer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    /// use std::fs;
    ///
    /// let data = fs::read("file.o").unwrap();
    /// let bpf = BpfLoader::new().load(&data)?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn load(&mut self, data: &[u8]) -> Result<Bpf, BpfError> {
        let mut obj = Object::parse(data)?;

        if let Some(btf) = &self.btf {
            obj.relocate_btf(btf)?;
        }

        let mut maps = HashMap::new();
        for (name, mut obj) in obj.maps.drain() {
            if obj.def.map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 && obj.def.max_entries == 0
            {
                obj.def.max_entries = possible_cpus()
                    .map_err(|error| BpfError::FileError {
                        path: PathBuf::from(POSSIBLE_CPUS),
                        error,
                    })?
                    .len() as u32;
            }
            let mut map = Map {
                obj,
                fd: None,
                pinned: false,
            };
            let fd = match map.obj.def.pinning {
                PinningType::ByName => {
                    let path = match &self.map_pin_path {
                        Some(p) => p,
                        None => return Err(BpfError::NoPinPath),
                    };
                    // try to open map in case it's already pinned
                    match map.from_pinned(&name, path) {
                        Ok(fd) => {
                            map.pinned = true;
                            fd as RawFd
                        }
                        Err(_) => {
                            let fd = map.create(&name)?;
                            map.pin(&name, path)?;
                            fd
                        }
                    }
                }
                PinningType::None => map.create(&name)?,
            };
            if !map.obj.data.is_empty() && name != ".bss" {
                bpf_map_update_elem_ptr(fd, &0 as *const _, map.obj.data.as_mut_ptr(), 0).map_err(
                    |(code, io_error)| MapError::SyscallError {
                        call: "bpf_map_update_elem".to_owned(),
                        code,
                        io_error,
                    },
                )?;
            }
            maps.insert(name, map);
        }

        obj.relocate_maps(maps.iter().map(|(name, map)| (name.as_str(), map)))?;
        obj.relocate_calls()?;

        let programs = obj
            .programs
            .drain()
            .map(|(name, obj)| {
                let data = ProgramData {
                    obj,
                    fd: None,
                    links: Vec::new(),
                    expected_attach_type: None,
                    attach_btf_obj_fd: None,
                    attach_btf_id: None,
                };
                let program = match &data.obj.section {
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
                        Program::SchedClassifier(SchedClassifier {
                            data,
                            name: unsafe {
                                CString::from_vec_unchecked(Vec::from(name.clone()))
                                    .into_boxed_c_str()
                            },
                        })
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
                    ProgramSection::PerfEvent { .. } => Program::PerfEvent(PerfEvent { data }),
                    ProgramSection::RawTracePoint { .. } => {
                        Program::RawTracePoint(RawTracePoint { data })
                    }
                    ProgramSection::Lsm { .. } => Program::Lsm(Lsm { data }),
                    ProgramSection::BtfTracePoint { .. } => {
                        Program::BtfTracePoint(BtfTracePoint { data })
                    }
                    ProgramSection::FEntry { .. } => Program::FEntry(FEntry { data }),
                    ProgramSection::FExit { .. } => Program::FExit(FExit { data }),
                };

                (name, program)
            })
            .collect();
        let maps = maps
            .drain()
            .map(|(name, map)| (name, MapLock::new(map)))
            .collect();
        Ok(Bpf { maps, programs })
    }
}

impl<'a> Default for BpfLoader<'a> {
    fn default() -> Self {
        BpfLoader::new()
    }
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
    /// For more loading options, see [BpfLoader].
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
        BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .load_file(path)
    }

    /// Loads eBPF bytecode from a buffer.
    ///
    /// Parses the object code contained in `data` and initializes the
    /// [maps](crate::maps) defined in it. If the kernel supports [BTF](Btf)
    /// debug info, it is automatically loaded from `/sys/kernel/btf/vmlinux`.
    ///
    /// For more loading options, see [BpfLoader].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::{Bpf, Btf};
    /// use std::fs;
    ///
    /// let data = fs::read("file.o").unwrap();
    /// // load the BTF data from /sys/kernel/btf/vmlinux
    /// let bpf = Bpf::load(&data)?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn load(data: &[u8]) -> Result<Bpf, BpfError> {
        BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .load(data)
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
    /// # let mut bpf = aya::Bpf::load(&[])?;
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
    /// # Examples
    ///
    /// ```no_run
    /// # let bpf = aya::Bpf::load(&[])?;
    /// let program = bpf.program("SSL_read").unwrap();
    /// println!("program SSL_read is of type {:?}", program.prog_type());
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn program(&self, name: &str) -> Option<&Program> {
        self.programs.get(name)
    }

    /// Returns a mutable reference to the program with the given name.
    ///
    /// Used to get a program before loading and attaching it. For more details on programs and
    /// their usage, see the [programs module documentation](crate::programs).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// use aya::programs::UProbe;
    /// use std::convert::TryInto;
    ///
    /// let program: &mut UProbe = bpf.program_mut("SSL_read").unwrap().try_into()?;
    /// program.load()?;
    /// program.attach(Some("SSL_read"), 0, "libssl", None)?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.get_mut(name)
    }

    /// An iterator over all the programs.
    ///
    /// # Examples
    /// ```no_run
    /// # let bpf = aya::Bpf::load(&[])?;
    /// for (name, program) in bpf.programs() {
    ///     println!(
    ///         "found program `{}` of type `{:?}`",
    ///         name,
    ///         program.prog_type()
    ///     );
    /// }
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn programs(&self) -> impl Iterator<Item = (&str, &Program)> {
        self.programs.iter().map(|(s, p)| (s.as_str(), p))
    }

    /// An iterator mutably referencing all of the programs.
    ///
    /// # Examples
    /// ```no_run
    /// # use std::path::Path;
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// # let pin_path = Path::new("/tmp/pin_path");
    /// for (_, program) in bpf.programs_mut() {
    ///     program.pin(pin_path)?;
    /// }
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn programs_mut(&mut self) -> impl Iterator<Item = (&str, &mut Program)> {
        self.programs.iter_mut().map(|(s, p)| (s.as_str(), p))
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

    #[error("pinning requested but no path provided")]
    NoPinPath,

    #[error("unexpected pinning type {name}")]
    UnexpectedPinningType { name: u32 },

    #[error("invalid path `{error}`")]
    InvalidPath { error: String },

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
