use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::CString,
    fs, io,
    os::{raw::c_int, unix::io::RawFd},
    path::{Path, PathBuf},
};

use aya_obj::{
    btf::{BtfFeatures, BtfRelocationError},
    generated::{BPF_F_SLEEPABLE, BPF_F_XDP_HAS_FRAGS},
    relocation::BpfRelocationError,
    BpfSectionKind, Features,
};
use log::{debug, warn};
use thiserror::Error;

use crate::{
    generated::{
        bpf_map_type, bpf_map_type::*, AYA_PERF_EVENT_IOC_DISABLE, AYA_PERF_EVENT_IOC_ENABLE,
        AYA_PERF_EVENT_IOC_SET_BPF,
    },
    maps::{Map, MapData, MapError},
    obj::{
        btf::{Btf, BtfError},
        Object, ParseError, ProgramSection,
    },
    programs::{
        BtfTracePoint, CgroupDevice, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr,
        CgroupSockopt, CgroupSysctl, Extension, FEntry, FExit, KProbe, LircMode2, Lsm, PerfEvent,
        ProbeKind, Program, ProgramData, ProgramError, RawTracePoint, SchedClassifier, SkLookup,
        SkMsg, SkSkb, SkSkbKind, SockOps, SocketFilter, TracePoint, UProbe, Xdp,
    },
    sys::{
        bpf_load_btf, bpf_map_freeze, bpf_map_update_elem_ptr, is_bpf_cookie_supported,
        is_bpf_global_data_supported, is_btf_datasec_supported, is_btf_decl_tag_supported,
        is_btf_float_supported, is_btf_func_global_supported, is_btf_func_supported,
        is_btf_supported, is_btf_type_tag_supported, is_perf_link_supported,
        is_probe_read_kernel_supported, is_prog_name_supported, retry_with_verifier_logs,
    },
    util::{bytes_of, bytes_of_slice, page_size, possible_cpus, POSSIBLE_CPUS},
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

// It only makes sense that an array of POD types is itself POD
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

pub use aya_obj::maps::{bpf_map_def, PinningType};

lazy_static! {
    pub(crate) static ref FEATURES: Features = detect_features();
}

fn detect_features() -> Features {
    let btf = if is_btf_supported() {
        Some(BtfFeatures::new(
            is_btf_func_supported(),
            is_btf_func_global_supported(),
            is_btf_datasec_supported(),
            is_btf_float_supported(),
            is_btf_decl_tag_supported(),
            is_btf_type_tag_supported(),
        ))
    } else {
        None
    };
    let f = Features::new(
        is_prog_name_supported(),
        is_probe_read_kernel_supported(),
        is_perf_link_supported(),
        is_bpf_global_data_supported(),
        is_bpf_cookie_supported(),
        btf,
    );
    debug!("BPF Feature Detection: {:#?}", f);
    f
}

/// Returns a reference to the detected BPF features.
pub fn features() -> &'static Features {
    &FEATURES
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
    globals: HashMap<&'a str, (&'a [u8], bool)>,
    max_entries: HashMap<&'a str, u32>,
    extensions: HashSet<&'a str>,
    verifier_log_level: VerifierLogLevel,
    allow_unsupported_maps: bool,
}

bitflags! {
    /// Used to set the verifier log level flags in [BpfLoader](BpfLoader::verifier_log_level()).
    #[derive(Clone, Copy, Debug)]
    pub struct VerifierLogLevel: u32 {
        /// Sets no verifier logging.
        const DISABLE = 0;
        /// Enables debug verifier logging.
        const DEBUG = 1;
        /// Enables verbose verifier logging.
        const VERBOSE = 2 | Self::DEBUG.bits();
        /// Enables verifier stats.
        const STATS = 4;
    }
}

impl Default for VerifierLogLevel {
    fn default() -> Self {
        Self::DEBUG | Self::STATS
    }
}

impl<'a> BpfLoader<'a> {
    /// Creates a new loader instance.
    pub fn new() -> BpfLoader<'a> {
        BpfLoader {
            btf: Btf::from_sys_fs().ok().map(Cow::Owned),
            map_pin_path: None,
            globals: HashMap::new(),
            max_entries: HashMap::new(),
            extensions: HashSet::new(),
            verifier_log_level: VerifierLogLevel::default(),
            allow_unsupported_maps: false,
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

    /// Allows programs containing unsupported maps to be loaded.
    ///
    /// By default programs containing unsupported maps will fail to load. This
    /// method can be used to configure the loader so that unsupported maps will
    /// be loaded, but won't be accessible from userspace. Can be useful when
    /// using unsupported maps that are only accessed from eBPF code and don't
    /// require any userspace interaction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new()
    ///     .allow_unsupported_maps()
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn allow_unsupported_maps(&mut self) -> &mut BpfLoader<'a> {
        self.allow_unsupported_maps = true;
        self
    }

    /// Sets the base directory path for pinned maps.
    ///
    /// Pinned maps will be loaded from `path/MAP_NAME`.
    /// The caller is responsible for ensuring the directory exists.
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

    /// Sets the value of a global variable.
    ///
    /// If the `must_exist` argument is `true`, [`BpfLoader::load`] will fail with [`ParseError::SymbolNotFound`] if the loaded object code does not contain the variable.
    ///
    /// From Rust eBPF, a global variable can be defined as follows:
    ///
    /// ```no_run
    /// #[no_mangle]
    /// static VERSION: i32 = 0;
    /// ```
    ///
    /// Then it can be accessed using `core::ptr::read_volatile`:
    ///
    /// ```no_run
    /// # #[no_mangle]
    /// # static VERSION: i32 = 0;
    /// # unsafe fn try_test() {
    /// let version = core::ptr::read_volatile(&VERSION);
    /// # }
    /// ```
    ///
    /// The type of a global variable must be `Pod` (plain old data), for instance `u8`, `u32` and
    /// all other primitive types. You may use custom types as well, but you must ensure that those
    /// types are `#[repr(C)]` and only contain other `Pod` types.
    ///
    /// From C eBPF, you would annotate a global variable as `volatile const`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new()
    ///     .set_global("VERSION", &2, true)
    ///     .set_global("PIDS", &[1234u16, 5678], true)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn set_global<T: Into<GlobalData<'a>>>(
        &mut self,
        name: &'a str,
        value: T,
        must_exist: bool,
    ) -> &mut BpfLoader<'a> {
        self.globals.insert(name, (value.into().bytes, must_exist));
        self
    }

    /// Set the max_entries for specified map.
    ///
    /// Overwrite the value of max_entries of the map that matches
    /// the provided name before the map is created.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new()
    ///     .set_max_entries("map", 64)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn set_max_entries(&mut self, name: &'a str, size: u32) -> &mut BpfLoader<'a> {
        self.max_entries.insert(name, size);
        self
    }

    /// Treat the provided program as an [`Extension`]
    ///
    /// When attempting to load the program with the provided `name`
    /// the program type is forced to be ] [`Extension`] and is not
    /// inferred from the ELF section name.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::BpfLoader;
    ///
    /// let bpf = BpfLoader::new()
    ///     .extension("myfunc")
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn extension(&mut self, name: &'a str) -> &mut BpfLoader<'a> {
        self.extensions.insert(name);
        self
    }

    /// Sets BPF verifier log level.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::{BpfLoader, VerifierLogLevel};
    ///
    /// let bpf = BpfLoader::new()
    ///     .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    ///
    pub fn verifier_log_level(&mut self, level: VerifierLogLevel) -> &mut BpfLoader<'a> {
        self.verifier_log_level = level;
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
        let Self {
            btf,
            map_pin_path,
            globals,
            max_entries,
            extensions,
            verifier_log_level,
            allow_unsupported_maps,
        } = self;
        let mut obj = Object::parse(data)?;
        obj.patch_map_data(globals.clone())?;

        let btf_fd = if let Some(features) = &FEATURES.btf() {
            if let Some(btf) = obj.fixup_and_sanitize_btf(features)? {
                match load_btf(btf.to_bytes(), *verifier_log_level) {
                    Ok(btf_fd) => Some(btf_fd),
                    // Only report an error here if the BTF is truely needed, otherwise proceed without.
                    Err(err) => {
                        for program in obj.programs.values() {
                            match program.section {
                                ProgramSection::Extension { .. }
                                | ProgramSection::FEntry { .. }
                                | ProgramSection::FExit { .. }
                                | ProgramSection::Lsm { .. }
                                | ProgramSection::BtfTracePoint { .. } => {
                                    return Err(BpfError::BtfError(err))
                                }
                                ProgramSection::KRetProbe { .. }
                                | ProgramSection::KProbe { .. }
                                | ProgramSection::UProbe { .. }
                                | ProgramSection::URetProbe { .. }
                                | ProgramSection::TracePoint { .. }
                                | ProgramSection::SocketFilter { .. }
                                | ProgramSection::Xdp { .. }
                                | ProgramSection::SkMsg { .. }
                                | ProgramSection::SkSkbStreamParser { .. }
                                | ProgramSection::SkSkbStreamVerdict { .. }
                                | ProgramSection::SockOps { .. }
                                | ProgramSection::SchedClassifier { .. }
                                | ProgramSection::CgroupSkb { .. }
                                | ProgramSection::CgroupSkbIngress { .. }
                                | ProgramSection::CgroupSkbEgress { .. }
                                | ProgramSection::CgroupSockAddr { .. }
                                | ProgramSection::CgroupSysctl { .. }
                                | ProgramSection::CgroupSockopt { .. }
                                | ProgramSection::LircMode2 { .. }
                                | ProgramSection::PerfEvent { .. }
                                | ProgramSection::RawTracePoint { .. }
                                | ProgramSection::SkLookup { .. }
                                | ProgramSection::CgroupSock { .. }
                                | ProgramSection::CgroupDevice { .. } => {}
                            }
                        }

                        warn!("Object BTF couldn't be loaded in the kernel: {err}");

                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(btf) = &btf {
            obj.relocate_btf(btf)?;
        }
        let mut maps = HashMap::new();
        for (name, mut obj) in obj.maps.drain() {
            if let (false, BpfSectionKind::Bss | BpfSectionKind::Data | BpfSectionKind::Rodata) =
                (FEATURES.bpf_global_data(), obj.section_kind())
            {
                continue;
            }
            let num_cpus = || -> Result<u32, BpfError> {
                Ok(possible_cpus()
                    .map_err(|error| BpfError::FileError {
                        path: PathBuf::from(POSSIBLE_CPUS),
                        error,
                    })?
                    .len() as u32)
            };
            let map_type: bpf_map_type = obj.map_type().try_into().map_err(MapError::from)?;
            if let Some(max_entries) = max_entries_override(
                map_type,
                max_entries.get(name.as_str()).copied(),
                || obj.max_entries(),
                num_cpus,
                || page_size() as u32,
            )? {
                obj.set_max_entries(max_entries)
            }
            let mut map = MapData {
                obj,
                fd: None,
                pinned: false,
                btf_fd,
            };
            let fd = match map.obj.pinning() {
                PinningType::ByName => {
                    let path = match &map_pin_path {
                        Some(p) => p,
                        None => return Err(BpfError::NoPinPath),
                    };
                    // try to open map in case it's already pinned
                    match map.open_pinned(&name, path) {
                        Ok(fd) => {
                            map.pinned = true;
                            fd as RawFd
                        }
                        Err(_) => {
                            let fd = map.create(&name)?;
                            map.pin(&name, path).map_err(|error| MapError::PinError {
                                name: Some(name.to_string()),
                                error,
                            })?;
                            fd
                        }
                    }
                }
                PinningType::None => map.create(&name)?,
            };
            if !map.obj.data().is_empty() && map.obj.section_kind() != BpfSectionKind::Bss {
                bpf_map_update_elem_ptr(fd, &0 as *const _, map.obj.data_mut().as_mut_ptr(), 0)
                    .map_err(|(_, io_error)| MapError::SyscallError {
                        call: "bpf_map_update_elem",
                        io_error,
                    })?;
            }
            if map.obj.section_kind() == BpfSectionKind::Rodata {
                bpf_map_freeze(fd).map_err(|(_, io_error)| MapError::SyscallError {
                    call: "bpf_map_freeze",
                    io_error,
                })?;
            }
            maps.insert(name, map);
        }

        let text_sections = obj
            .functions
            .keys()
            .map(|(section_index, _)| *section_index)
            .collect();

        obj.relocate_maps(
            maps.iter()
                .map(|(s, data)| (s.as_str(), data.fd, &data.obj)),
            &text_sections,
        )?;
        obj.relocate_calls(&text_sections)?;
        obj.sanitize_functions(&FEATURES);

        let programs = obj
            .programs
            .drain()
            .map(|(name, prog_obj)| {
                let function_obj = obj.functions.get(&prog_obj.function_key()).unwrap().clone();

                let prog_name = if FEATURES.bpf_name() {
                    Some(name.clone())
                } else {
                    None
                };
                let section = prog_obj.section.clone();
                let obj = (prog_obj, function_obj);

                let program = if extensions.contains(name.as_str()) {
                    Program::Extension(Extension {
                        data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                    })
                } else {
                    match &section {
                        ProgramSection::KProbe { .. } => Program::KProbe(KProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::KProbe,
                        }),
                        ProgramSection::KRetProbe { .. } => Program::KProbe(KProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::KRetProbe,
                        }),
                        ProgramSection::UProbe { .. } => Program::UProbe(UProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::UProbe,
                        }),
                        ProgramSection::URetProbe { .. } => Program::UProbe(UProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::URetProbe,
                        }),
                        ProgramSection::TracePoint { .. } => Program::TracePoint(TracePoint {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SocketFilter { .. } => {
                            Program::SocketFilter(SocketFilter {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                        ProgramSection::Xdp { frags, .. } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *frags {
                                data.flags = BPF_F_XDP_HAS_FRAGS;
                            }
                            Program::Xdp(Xdp { data })
                        }
                        ProgramSection::SkMsg { .. } => Program::SkMsg(SkMsg {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::CgroupSysctl { .. } => {
                            Program::CgroupSysctl(CgroupSysctl {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                        ProgramSection::CgroupSockopt { attach_type, .. } => {
                            Program::CgroupSockopt(CgroupSockopt {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::SkSkbStreamParser { .. } => Program::SkSkb(SkSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: SkSkbKind::StreamParser,
                        }),
                        ProgramSection::SkSkbStreamVerdict { .. } => Program::SkSkb(SkSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: SkSkbKind::StreamVerdict,
                        }),
                        ProgramSection::SockOps { .. } => Program::SockOps(SockOps {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SchedClassifier { .. } => {
                            Program::SchedClassifier(SchedClassifier {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                name: unsafe {
                                    CString::from_vec_unchecked(Vec::from(name.clone()))
                                        .into_boxed_c_str()
                                },
                            })
                        }
                        ProgramSection::CgroupSkb { .. } => Program::CgroupSkb(CgroupSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            expected_attach_type: None,
                        }),
                        ProgramSection::CgroupSkbIngress { .. } => Program::CgroupSkb(CgroupSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            expected_attach_type: Some(CgroupSkbAttachType::Ingress),
                        }),
                        ProgramSection::CgroupSkbEgress { .. } => Program::CgroupSkb(CgroupSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            expected_attach_type: Some(CgroupSkbAttachType::Egress),
                        }),
                        ProgramSection::CgroupSockAddr { attach_type, .. } => {
                            Program::CgroupSockAddr(CgroupSockAddr {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::LircMode2 { .. } => Program::LircMode2(LircMode2 {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::PerfEvent { .. } => Program::PerfEvent(PerfEvent {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::RawTracePoint { .. } => {
                            Program::RawTracePoint(RawTracePoint {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                        ProgramSection::Lsm { sleepable, .. } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::Lsm(Lsm { data })
                        }
                        ProgramSection::BtfTracePoint { .. } => {
                            Program::BtfTracePoint(BtfTracePoint {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                        ProgramSection::FEntry { .. } => Program::FEntry(FEntry {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::FExit { .. } => Program::FExit(FExit {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::Extension { .. } => Program::Extension(Extension {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SkLookup { .. } => Program::SkLookup(SkLookup {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::CgroupSock { attach_type, .. } => {
                            Program::CgroupSock(CgroupSock {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::CgroupDevice { .. } => {
                            Program::CgroupDevice(CgroupDevice {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                    }
                };
                (name, program)
            })
            .collect();
        let maps = maps
            .drain()
            .map(parse_map)
            .collect::<Result<HashMap<String, Map>, BpfError>>()?;

        if !*allow_unsupported_maps {
            maps.iter().try_for_each(|(_, x)| match x {
                Map::Unsupported(map) => Err(BpfError::MapError(MapError::Unsupported {
                    map_type: map.obj.map_type(),
                })),
                _ => Ok(()),
            })?;
        };

        Ok(Bpf { maps, programs })
    }
}

fn parse_map(data: (String, MapData)) -> Result<(String, Map), BpfError> {
    let (name, map) = data;
    let map_type = bpf_map_type::try_from(map.obj.map_type()).map_err(MapError::from)?;
    let map = match map_type {
        BPF_MAP_TYPE_ARRAY => Map::Array(map),
        BPF_MAP_TYPE_PERCPU_ARRAY => Map::PerCpuArray(map),
        BPF_MAP_TYPE_PROG_ARRAY => Map::ProgramArray(map),
        BPF_MAP_TYPE_HASH => Map::HashMap(map),
        BPF_MAP_TYPE_LRU_HASH => Map::LruHashMap(map),
        BPF_MAP_TYPE_PERCPU_HASH => Map::PerCpuHashMap(map),
        BPF_MAP_TYPE_LRU_PERCPU_HASH => Map::PerCpuLruHashMap(map),
        BPF_MAP_TYPE_PERF_EVENT_ARRAY => Map::PerfEventArray(map),
        BPF_MAP_TYPE_RINGBUF => Map::RingBuf(map),
        BPF_MAP_TYPE_SOCKHASH => Map::SockHash(map),
        BPF_MAP_TYPE_SOCKMAP => Map::SockMap(map),
        BPF_MAP_TYPE_BLOOM_FILTER => Map::BloomFilter(map),
        BPF_MAP_TYPE_LPM_TRIE => Map::LpmTrie(map),
        BPF_MAP_TYPE_STACK => Map::Stack(map),
        BPF_MAP_TYPE_STACK_TRACE => Map::StackTraceMap(map),
        BPF_MAP_TYPE_QUEUE => Map::Queue(map),
        m => {
            warn!("The map {name} is of type {:#?} which is currently unsupported in Aya, use `allow_unsupported_maps()` to load it anyways", m);
            Map::Unsupported(map)
        }
    };

    Ok((name, map))
}

/// Computes the value which should be used to override the max_entries value of the map
/// based on the user-provided override and the rules for that map type.
fn max_entries_override(
    map_type: bpf_map_type,
    user_override: Option<u32>,
    current_value: impl Fn() -> u32,
    num_cpus: impl Fn() -> Result<u32, BpfError>,
    page_size: impl Fn() -> u32,
) -> Result<Option<u32>, BpfError> {
    let max_entries = || user_override.unwrap_or_else(&current_value);
    Ok(match map_type {
        BPF_MAP_TYPE_PERF_EVENT_ARRAY if max_entries() == 0 => Some(num_cpus()?),
        BPF_MAP_TYPE_RINGBUF => Some(adjust_to_page_size(max_entries(), page_size()))
            .filter(|adjusted| *adjusted != max_entries())
            .or(user_override),
        _ => user_override,
    })
}

// Adjusts the byte size of a RingBuf map to match a power-of-two multiple of the page size.
//
// This mirrors the logic used by libbpf.
// See https://github.com/libbpf/libbpf/blob/ec6f716eda43/src/libbpf.c#L2461-L2463
fn adjust_to_page_size(byte_size: u32, page_size: u32) -> u32 {
    // If the byte_size is zero, return zero and let the verifier reject the map
    // when it is loaded. This is the behavior of libbpf.
    if byte_size == 0 {
        return 0;
    }
    // TODO: Replace with primitive method when int_roundings (https://github.com/rust-lang/rust/issues/88581)
    // is stabilized.
    fn div_ceil(n: u32, rhs: u32) -> u32 {
        let d = n / rhs;
        let r = n % rhs;
        if r > 0 && rhs > 0 {
            d + 1
        } else {
            d
        }
    }
    let pages_needed = div_ceil(byte_size, page_size);
    page_size * pages_needed.next_power_of_two()
}

#[cfg(test)]
mod tests {

    use crate::generated::bpf_map_type::*;

    const PAGE_SIZE: u32 = 4096;
    const NUM_CPUS: u32 = 4;

    #[test]
    fn test_adjust_to_page_size() {
        use super::adjust_to_page_size;
        [
            (0, 0),
            (4096, 1),
            (4096, 4095),
            (4096, 4096),
            (8192, 4097),
            (8192, 8192),
            (16384, 8193),
        ]
        .into_iter()
        .for_each(|(exp, input)| assert_eq!(exp, adjust_to_page_size(input, PAGE_SIZE)))
    }

    #[test]
    fn test_max_entries_override() {
        use super::max_entries_override;
        [
            (BPF_MAP_TYPE_RINGBUF, Some(1), 1, Some(PAGE_SIZE)),
            (BPF_MAP_TYPE_RINGBUF, None, 1, Some(PAGE_SIZE)),
            (BPF_MAP_TYPE_RINGBUF, None, PAGE_SIZE, None),
            (BPF_MAP_TYPE_PERF_EVENT_ARRAY, None, 1, None),
            (BPF_MAP_TYPE_PERF_EVENT_ARRAY, Some(42), 1, Some(42)),
            (BPF_MAP_TYPE_PERF_EVENT_ARRAY, Some(0), 1, Some(NUM_CPUS)),
            (BPF_MAP_TYPE_PERF_EVENT_ARRAY, None, 0, Some(NUM_CPUS)),
            (BPF_MAP_TYPE_PERF_EVENT_ARRAY, None, 42, None),
            (BPF_MAP_TYPE_ARRAY, None, 1, None),
            (BPF_MAP_TYPE_ARRAY, Some(2), 1, Some(2)),
        ]
        .into_iter()
        .for_each(|(map_type, user_override, current_value, exp)| {
            assert_eq!(
                exp,
                max_entries_override(
                    map_type,
                    user_override,
                    || { current_value },
                    || Ok(NUM_CPUS),
                    || PAGE_SIZE
                )
                .unwrap()
            )
        })
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
    maps: HashMap<String, Map>,
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
    pub fn map(&self, name: &str) -> Option<&Map> {
        self.maps.get(name)
    }

    /// Returns a mutable reference to the map with the given name.
    ///
    /// The returned type is mostly opaque. In order to do anything useful with it you need to
    /// convert it to a [typed map](crate::maps).
    ///
    /// For more details and examples on maps and their usage, see the [maps module
    /// documentation][crate::maps].
    pub fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.maps.get_mut(name)
    }

    /// Takes ownership of a map with the given name.
    ///
    /// Use this when borrowing with [`map`](crate::Bpf::map) or [`map_mut`](crate::Bpf::map_mut)
    /// is not possible (eg when using the map from an async task). The returned
    /// map will be closed on `Drop`, therefore the caller is responsible for
    /// managing its lifetime.
    ///
    /// The returned type is mostly opaque. In order to do anything useful with it you need to
    /// convert it to a [typed map](crate::maps).
    ///
    /// For more details and examples on maps and their usage, see the [maps module
    /// documentation][crate::maps].
    pub fn take_map(&mut self, name: &str) -> Option<Map> {
        self.maps.remove(name)
    }

    /// An iterator over all the maps.
    ///
    /// # Examples
    /// ```no_run
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// for (name, map) in bpf.maps() {
    ///     println!(
    ///         "found map `{}`",
    ///         name,
    ///     );
    /// }
    /// # Ok::<(), aya::BpfError>(())
    /// ```
    pub fn maps(&self) -> impl Iterator<Item = (&str, &Map)> {
        self.maps.iter().map(|(name, map)| (name.as_str(), map))
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
    /// # #[derive(thiserror::Error, Debug)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Bpf(#[from] aya::BpfError),
    /// #     #[error(transparent)]
    /// #     Pin(#[from] aya::pin::PinError)
    /// # }
    /// # let mut bpf = aya::Bpf::load(&[])?;
    /// # let pin_path = Path::new("/tmp/pin_path");
    /// for (_, program) in bpf.programs_mut() {
    ///     program.pin(pin_path)?;
    /// }
    /// # Ok::<(), Error>(())
    /// ```
    pub fn programs_mut(&mut self) -> impl Iterator<Item = (&str, &mut Program)> {
        self.programs.iter_mut().map(|(s, p)| (s.as_str(), p))
    }
}

/// The error type returned by [`Bpf::load_file`] and [`Bpf::load`].
#[derive(Debug, Error)]
pub enum BpfError {
    /// Error loading file
    #[error("error loading {path}")]
    FileError {
        /// The file path
        path: PathBuf,
        #[source]
        /// The original io::Error
        error: io::Error,
    },

    /// Pinning requested but no path provided
    #[error("pinning requested but no path provided")]
    NoPinPath,

    /// Unexpected pinning type
    #[error("unexpected pinning type {name}")]
    UnexpectedPinningType {
        /// The value encountered
        name: u32,
    },

    /// Invalid path
    #[error("invalid path `{error}`")]
    InvalidPath {
        /// The error message
        error: String,
    },

    /// Error parsing BPF object
    #[error("error parsing BPF object: {0}")]
    ParseError(#[from] ParseError),

    /// Error parsing BTF object
    #[error("BTF error: {0}")]
    BtfError(#[from] BtfError),

    /// Error performing relocations
    #[error("error relocating function")]
    RelocationError(#[from] BpfRelocationError),

    /// Error performing relocations
    #[error("error relocating section")]
    BtfRelocationError(#[from] BtfRelocationError),

    /// No BTF parsed for object
    #[error("no BTF parsed for object")]
    NoBTF,

    #[error("map error: {0}")]
    /// A map error
    MapError(#[from] MapError),

    #[error("program error: {0}")]
    /// A program error
    ProgramError(#[from] ProgramError),
}

fn load_btf(raw_btf: Vec<u8>, verifier_log_level: VerifierLogLevel) -> Result<RawFd, BtfError> {
    let (ret, verifier_log) = retry_with_verifier_logs(10, |logger| {
        bpf_load_btf(raw_btf.as_slice(), logger, verifier_log_level)
    });
    match ret {
        Ok(fd) => Ok(fd as RawFd),
        Err((_, io_error)) => Err(BtfError::LoadError {
            io_error,
            verifier_log,
        }),
    }
}

/// Global data that can be exported to eBPF programs before they are loaded.
///
/// Valid global data includes `Pod` types and slices of `Pod` types. See also
/// [BpfLoader::set_global].
pub struct GlobalData<'a> {
    bytes: &'a [u8],
}

impl<'a, T: Pod> From<&'a [T]> for GlobalData<'a> {
    fn from(s: &'a [T]) -> Self {
        GlobalData {
            bytes: bytes_of_slice(s),
        }
    }
}

impl<'a, T: Pod> From<&'a T> for GlobalData<'a> {
    fn from(v: &'a T) -> Self {
        GlobalData {
            // Safety: v is Pod
            bytes: unsafe { bytes_of(v) },
        }
    }
}
