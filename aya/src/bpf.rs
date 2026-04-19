use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs, io,
    os::fd::{AsFd as _, AsRawFd as _},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};
#[cfg(feature = "flate2")]
use std::{fs::File, io::Read as _};

use aya_obj::{
    EbpfSectionKind, Features, Object, ParseError, ProgramSection,
    btf::{Btf, BtfError, BtfFeatures, BtfRelocationError},
    generated::{BPF_F_SLEEPABLE, BPF_F_XDP_HAS_FRAGS, bpf_map_type},
    relocation::EbpfRelocationError,
};
#[cfg(feature = "flate2")]
use flate2::read::GzDecoder;
use log::{debug, warn};
use thiserror::Error;

use crate::{
    maps::{Map, MapData, MapError},
    programs::{
        BtfTracePoint, CgroupDevice, CgroupSkb, CgroupSock, CgroupSockAddr, CgroupSockopt,
        CgroupSysctl, Extension, FEntry, FExit, FlowDissector, Iter, KProbe, LircMode2, Lsm,
        LsmCgroup, PerfEvent, ProbeKind, Program, ProgramData, ProgramError, RawTracePoint,
        SchedClassifier, SkLookup, SkMsg, SkReuseport, SkSkb, SockOps, SocketFilter, TracePoint,
        UProbe, Xdp,
    },
    sys::{
        bpf_load_btf, is_bpf_cookie_supported, is_bpf_global_data_supported,
        is_bpf_syscall_wrapper_supported, is_btf_datasec_supported, is_btf_datasec_zero_supported,
        is_btf_decl_tag_supported, is_btf_enum64_supported, is_btf_float_supported,
        is_btf_func_global_supported, is_btf_func_supported, is_btf_supported,
        is_btf_type_tag_supported, is_perf_link_supported, is_probe_read_kernel_supported,
        is_prog_id_supported, is_prog_name_supported, retry_with_verifier_logs,
    },
    util::{KernelVersion, bytes_of, bytes_of_slice, nr_cpus, page_size},
};

/// Marker trait for types that can safely be converted to and from byte slices.
///
/// # Safety
///
/// This trait is unsafe because it allows for the conversion of types to and
/// from byte slices.
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

pub use aya_obj::maps::{PinningType, bpf_map_def};

pub(crate) static FEATURES: LazyLock<Features> = LazyLock::new(detect_features);

/// Kernel configuration data for eBPF extern variables.
///
/// This type holds kernel configuration values that can be used to patch extern variables
/// in eBPF programs. It includes both kernel version information and CONFIG_* values from
/// the kernel configuration.
///
/// # Examples
///
/// ```no_run
/// use aya::{EbpfLoader, KConfig};
///
/// // Load kconfig from the system
/// let kconfig = KConfig::current()?;
/// let mut loader = EbpfLoader::new();
/// let bpf = loader.kconfig(Some(kconfig)).load_file("file.o")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct KConfig {
    data: HashMap<String, Vec<u8>>,
}

/// The error type returned by [`KConfig::parse`].
#[derive(Debug, Error)]
pub enum KConfigError {
    /// No kernel config file could be found on the system.
    #[error("kernel config not found at /boot/config-<release> or /proc/config.gz")]
    NotFound,

    /// A kernel config file could be found, but could not be read.
    #[error("failed to read kernel config {path}: {error}")]
    Read {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O or decode error.
        error: io::Error,
    },

    /// The provided kernel config contains a malformed line.
    #[error("malformed kernel config line: {line}")]
    MalformedLine {
        /// The malformed line.
        line: String,
    },

    /// The provided kernel config is not valid UTF-8.
    #[error("kernel config is not valid UTF-8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

impl KConfig {
    fn with_raw_config(raw_config: Option<&str>) -> Result<Self, KConfigError> {
        Ok(Self {
            data: compute_kconfig_definition(&FEATURES, raw_config)?,
        })
    }

    /// Creates a new `KConfig` by reading kernel configuration from the system.
    ///
    /// This will attempt to read `/boot/config-<release>` first, then `/proc/config.gz` when
    /// gzip support is enabled, and populate the configuration with kernel version and feature
    /// detection information.
    pub fn current() -> Result<Self, KConfigError> {
        let raw_config = read_kconfig()?;
        Self::with_raw_config(Some(&raw_config))
    }

    /// Creates a new `KConfig` from kernel configuration data provided by the caller.
    ///
    /// The provided bytes should contain the textual contents of a kernel config file.
    /// This still populates the synthetic libbpf-compatible externs from local feature
    /// detection and kernel version discovery.
    pub fn parse(data: &[u8]) -> Result<Self, KConfigError> {
        Self::with_raw_config(Some(std::str::from_utf8(data)?))
    }

    /// Returns a reference to the underlying configuration data.
    pub(crate) const fn as_map(&self) -> &HashMap<String, Vec<u8>> {
        &self.data
    }
}

#[derive(Debug)]
enum KConfigMode {
    Auto,
    Disabled,
    Explicit(KConfig),
}

fn resolve_kconfig(
    mode: &KConfigMode,
    requires_real_kconfig: bool,
    load_current: impl FnOnce() -> Result<KConfig, KConfigError>,
) -> Result<Option<KConfig>, KConfigError> {
    match mode {
        KConfigMode::Auto => {
            if requires_real_kconfig {
                return load_current().map(Some);
            }
            Ok(Some(KConfig::with_raw_config(None)?))
        }
        KConfigMode::Disabled => Ok(None),
        KConfigMode::Explicit(kconfig) => Ok(Some(kconfig.clone())),
    }
}

fn detect_features() -> Features {
    let btf = is_btf_supported().then(|| {
        BtfFeatures::new(
            is_btf_func_supported(),
            is_btf_func_global_supported(),
            is_btf_datasec_supported(),
            is_btf_datasec_zero_supported(),
            is_btf_float_supported(),
            is_btf_decl_tag_supported(),
            is_btf_type_tag_supported(),
            is_btf_enum64_supported(),
        )
    });
    let f = Features::new(
        is_prog_name_supported(),
        is_probe_read_kernel_supported(),
        is_perf_link_supported(),
        is_bpf_global_data_supported(),
        is_bpf_cookie_supported(),
        is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_CPUMAP),
        is_prog_id_supported(bpf_map_type::BPF_MAP_TYPE_DEVMAP),
        is_bpf_syscall_wrapper_supported(),
        btf,
    );
    debug!("BPF Feature Detection: {f:#?}");
    f
}

/// Returns a reference to the detected BPF features.
pub fn features() -> &'static Features {
    &FEATURES
}

fn compute_kconfig_definition(
    features: &Features,
    raw_config: Option<&str>,
) -> Result<HashMap<String, Vec<u8>>, KConfigError> {
    let mut result = HashMap::new();

    if let Ok(version_code) = KernelVersion::current().map(KernelVersion::code) {
        result.insert(
            "LINUX_KERNEL_VERSION".to_string(),
            version_code.to_ne_bytes().to_vec(),
        );
    }

    // Mirror libbpf's virtual __kconfig externs, see
    // https://github.com/libbpf/libbpf/blob/libbpf-1.6.2/src/libbpf.c#L8465-L8468
    result.insert(
        "LINUX_HAS_BPF_COOKIE".to_string(),
        u64::from(features.bpf_cookie()).to_ne_bytes().to_vec(),
    );
    result.insert(
        "LINUX_HAS_SYSCALL_WRAPPER".to_string(),
        u64::from(features.bpf_syscall_wrapper())
            .to_ne_bytes()
            .to_vec(),
    );

    if let Some(raw_config) = raw_config {
        parse_kconfig_values(raw_config, &mut result)?;
    }

    Ok(result)
}

fn parse_kconfig_values(
    raw_config: &str,
    result: &mut HashMap<String, Vec<u8>>,
) -> Result<(), KConfigError> {
    for line in raw_config.lines() {
        if !line.starts_with("CONFIG_") {
            continue;
        }

        let Some((key, raw_value)) = line.split_once('=') else {
            return Err(KConfigError::MalformedLine {
                line: line.to_owned(),
            });
        };

        let value = match raw_value {
            "n" | "y" | "m" => raw_value.as_bytes().to_vec(),
            _ if raw_value.starts_with('"') => {
                if raw_value.len() < 2 || !raw_value.ends_with('"') {
                    return Err(KConfigError::MalformedLine {
                        line: line.to_owned(),
                    });
                }

                let raw_value = &raw_value[1..raw_value.len() - 1];
                raw_value
                    .as_bytes()
                    .iter()
                    .chain(std::iter::once(&0u8))
                    .copied()
                    .collect()
            }
            _ => {
                if let Some(value) = parse_kconfig_numeric(raw_value) {
                    value.to_vec()
                } else {
                    return Err(KConfigError::MalformedLine {
                        line: line.to_owned(),
                    });
                }
            }
        };

        result.insert(key.to_string(), value);
    }

    Ok(())
}

fn parse_kconfig_numeric(raw_value: &str) -> Option<[u8; 8]> {
    if raw_value.starts_with('-') {
        return raw_value.parse::<i64>().ok().map(i64::to_ne_bytes);
    }

    if let Some(value) = raw_value
        .strip_prefix("0x")
        .or_else(|| raw_value.strip_prefix("0X"))
    {
        u64::from_str_radix(value, 16).ok().map(u64::to_ne_bytes)
    } else {
        raw_value.parse::<u64>().ok().map(u64::to_ne_bytes)
    }
}

fn read_kconfig() -> Result<String, KConfigError> {
    let release = kernel_release().ok_or(KConfigError::NotFound)?;
    let mut boot_config_name = OsString::from("config-");
    boot_config_name.push(release);
    let boot_config_path = PathBuf::from("/boot").join(boot_config_name);

    #[cfg(feature = "flate2")]
    let proc_config_path = Some(Path::new("/proc/config.gz"));
    #[cfg(not(feature = "flate2"))]
    let proc_config_path = None;

    read_kconfig_from_paths(proc_config_path, Some(&boot_config_path))
}

fn read_kconfig_from_paths(
    proc_config_path: Option<&Path>,
    boot_config_path: Option<&Path>,
) -> Result<String, KConfigError> {
    let mut read_error = None;

    if let Some(config_path) = boot_config_path {
        if config_path.exists() {
            debug!("Found kernel config at {}", config_path.to_string_lossy());
            match read_kconfig_file(config_path, false) {
                Ok(config) => return Ok(config),
                Err(err @ KConfigError::Read { .. }) => {
                    read_error.get_or_insert(err);
                }
                Err(err) => return Err(err),
            }
        }
    }

    #[cfg(not(feature = "flate2"))]
    let _: Option<&Path> = proc_config_path;

    #[cfg(feature = "flate2")]
    if let Some(config_path) = proc_config_path {
        if config_path.exists() {
            debug!("Found kernel config at {}", config_path.to_string_lossy());
            match read_kconfig_file(config_path, true) {
                Ok(config) => return Ok(config),
                Err(err @ KConfigError::Read { .. }) => {
                    read_error.get_or_insert(err);
                }
                Err(err) => return Err(err),
            }
        }
    }

    Err(read_error.unwrap_or(KConfigError::NotFound))
}

#[cfg(test)]
fn kernel_release() -> Option<OsString> {
    std::env::var_os("AYA_TEST_KERNEL_RELEASE").or_else(|| Some(OsString::from("unknown")))
}

#[cfg(not(test))]
fn kernel_release() -> Option<OsString> {
    use std::{ffi::CStr, os::unix::ffi::OsStringExt as _};

    unsafe {
        let mut v = std::mem::zeroed::<libc::utsname>();
        if libc::uname(std::ptr::from_mut(&mut v)) != 0 {
            return None;
        }

        let release = CStr::from_ptr(v.release.as_ptr());
        Some(OsString::from_vec(release.to_bytes().to_vec()))
    }
}

fn read_kconfig_file(path: &Path, gzip: bool) -> Result<String, KConfigError> {
    let res = if gzip {
        #[cfg(feature = "flate2")]
        {
            let mut output = String::new();
            File::open(path).map(GzDecoder::new).and_then(|mut file| {
                file.read_to_string(&mut output)?;
                Ok(output)
            })
        }
        #[cfg(not(feature = "flate2"))]
        {
            return Err(KConfigError::NotFound);
        }
    } else {
        fs::read_to_string(path)
    };

    let output = res.map_err(|error| KConfigError::Read {
        path: path.to_owned(),
        error,
    })?;
    KConfig::parse(output.as_bytes())?;
    Ok(output)
}

/// Builder style API for advanced loading of eBPF programs.
///
/// Loading eBPF code involves a few steps, including loading maps and applying
/// relocations. You can use `EbpfLoader` to customize some of the loading
/// options.
///
/// # Examples
///
/// ```no_run
/// use aya::{EbpfLoader, Btf};
/// use std::fs;
///
/// let bpf = EbpfLoader::new()
///     // load the BTF data from /sys/kernel/btf/vmlinux
///     .btf(Btf::from_sys_fs().ok().as_ref())
///     // load pinned maps from /sys/fs/bpf/my-program
///     .default_map_pin_directory("/sys/fs/bpf/my-program")
///     // finally load the code
///     .load_file("file.o")?;
/// # Ok::<(), aya::EbpfError>(())
/// ```
#[derive(Debug)]
pub struct EbpfLoader<'a> {
    btf: Option<Cow<'a, Btf>>,
    default_map_pin_directory: Option<PathBuf>,
    globals: HashMap<&'a str, (&'a [u8], bool)>,
    // Max entries overrides the max_entries field of the map that matches the provided name
    // before the map is created.
    max_entries: HashMap<&'a str, u32>,
    // Map pin path overrides the pin path of the map that matches the provided name before
    // it is created.
    map_pin_path_by_name: HashMap<&'a str, Cow<'a, Path>>,

    extensions: HashSet<&'a str>,
    verifier_log_level: VerifierLogLevel,
    allow_unsupported_maps: bool,
    kconfig: KConfigMode,
}

/// Builder style API for advanced loading of eBPF programs.
#[deprecated(since = "0.13.0", note = "use `EbpfLoader` instead")]
pub type BpfLoader<'a> = EbpfLoader<'a>;

bitflags::bitflags! {
    /// Used to set the verifier log level flags in [EbpfLoader](EbpfLoader::verifier_log_level()).
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

impl<'a> EbpfLoader<'a> {
    /// Creates a new loader instance.
    pub fn new() -> Self {
        Self {
            btf: Btf::from_sys_fs().ok().map(Cow::Owned),
            default_map_pin_directory: None,
            globals: HashMap::new(),
            max_entries: HashMap::new(),
            map_pin_path_by_name: HashMap::new(),
            extensions: HashSet::new(),
            verifier_log_level: VerifierLogLevel::default(),
            allow_unsupported_maps: false,
            kconfig: KConfigMode::Auto,
        }
    }

    /// Sets the kernel configuration data for extern variables.
    ///
    /// This allows you to provide kernel configuration values that will be used to patch
    /// extern variables in eBPF programs. If not set, the loader will use
    /// [`KConfig::current`]. Pass `None` to disable kconfig patching.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::{EbpfLoader, KConfig};
    ///
    /// let kconfig = KConfig::current()?;
    /// let mut loader = EbpfLoader::new();
    /// let bpf = loader.kconfig(Some(kconfig)).load_file("file.o")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn kconfig(&mut self, kconfig: Option<KConfig>) -> &mut Self {
        self.kconfig = match kconfig {
            Some(kconfig) => KConfigMode::Explicit(kconfig),
            None => KConfigMode::Disabled,
        };
        self
    }

    /// Sets the target [BTF](Btf) info.
    ///
    /// The loader defaults to loading `BTF` info using [`Btf::from_sys_fs`].
    /// Use this method if you want to load `BTF` from a custom location or
    /// pass `None` to disable `BTF` relocations entirely.
    /// # Example
    ///
    /// ```no_run
    /// use aya::{EbpfLoader, Btf, Endianness};
    ///
    /// let bpf = EbpfLoader::new()
    ///     // load the BTF data from a custom location
    ///     .btf(Btf::parse_file("/custom_btf_file", Endianness::default()).ok().as_ref())
    ///     .load_file("file.o")?;
    ///
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn btf(&mut self, btf: Option<&'a Btf>) -> &mut Self {
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
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new()
    ///     .allow_unsupported_maps()
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub const fn allow_unsupported_maps(&mut self) -> &mut Self {
        self.allow_unsupported_maps = true;
        self
    }

    /// Sets the base directory path for pinned maps.
    ///
    /// Pinned maps will be loaded from `path/MAP_NAME`.
    /// The caller is responsible for ensuring the directory exists.
    ///
    /// Note that if a path is provided for a specific map via [`EbpfLoader::map_pin_path`],
    /// it will take precedence over this path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new()
    ///     .default_map_pin_directory("/sys/fs/bpf/my-program")
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub fn default_map_pin_directory<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.default_map_pin_directory = Some(path.as_ref().to_owned());
        self
    }

    /// Override the value of a global variable.
    ///
    /// If the `must_exist` argument is `true`, [`EbpfLoader::load`] will fail with [`ParseError::SymbolNotFound`] if the loaded object code does not contain the variable.
    ///
    /// From Rust eBPF, a global variable can be defined using `Global` - please refer to the `aya-ebpf` documentation.
    ///
    /// The type of a global variable must be `Pod` (plain old data), for instance `u8`, `u32` and
    /// all other primitive types. You may use custom types as well, but you must ensure that those
    /// types are `#[repr(C)]` and only contain other `Pod` types.
    ///
    /// The type used here and in the eBPF must be the same (or have a compatible layout).
    ///
    /// From C eBPF, you would annotate a global variable as `volatile const`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new()
    ///     .override_global("VERSION", &2, true)
    ///     .override_global("PIDS", &[1234u16, 5678], true)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub fn override_global<T: Into<GlobalData<'a>>>(
        &mut self,
        name: &'a str,
        value: T,
        must_exist: bool,
    ) -> &mut Self {
        self.globals.insert(name, (value.into().bytes, must_exist));
        self
    }

    /// Override the value of a global variable.
    #[deprecated(since = "0.13.2", note = "please use `override_global` instead")]
    pub fn set_global<T: Into<GlobalData<'a>>>(
        &mut self,
        name: &'a str,
        value: T,
        must_exist: bool,
    ) -> &mut Self {
        self.override_global(name, value, must_exist)
    }

    /// Set the `max_entries` for specified map.
    ///
    /// Overwrite the value of `max_entries` of the map that matches
    /// the provided name before the map is created.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new()
    ///     .map_max_entries("map", 64)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub fn map_max_entries(&mut self, name: &'a str, size: u32) -> &mut Self {
        self.max_entries.insert(name, size);
        self
    }

    /// Set the `max_entries` for specified map.
    #[deprecated(since = "0.13.2", note = "please use `map_max_entries` instead")]
    pub fn set_max_entries(&mut self, name: &'a str, size: u32) -> &mut Self {
        self.map_max_entries(name, size)
    }

    /// Set the pin path for the map that matches the provided name.
    ///
    /// Note that this is an absolute path to the pinned map; it is not a prefix
    /// to be combined with the map name, and it is not relative to the
    /// configured base directory for pinned maps.
    ///
    /// Each call to this function with the same name overwrites the path to the
    /// pinned map; last one wins.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    ///
    /// # let mut loader = aya::EbpfLoader::new();
    /// # let pin_path = Path::new("/sys/fs/bpf/my-pinned-map");
    /// let bpf = loader
    ///     .map_pin_path("map", pin_path)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub fn map_pin_path<P: Into<Cow<'a, Path>>>(&mut self, name: &'a str, path: P) -> &mut Self {
        self.map_pin_path_by_name.insert(name, path.into());
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
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new()
    ///     .extension("myfunc")
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub fn extension(&mut self, name: &'a str) -> &mut Self {
        self.extensions.insert(name);
        self
    }

    /// Sets BPF verifier log level.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya::{EbpfLoader, VerifierLogLevel};
    ///
    /// let bpf = EbpfLoader::new()
    ///     .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
    ///     .load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    ///
    pub const fn verifier_log_level(&mut self, level: VerifierLogLevel) -> &mut Self {
        self.verifier_log_level = level;
        self
    }

    /// Loads eBPF bytecode from a file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::EbpfLoader;
    ///
    /// let bpf = EbpfLoader::new().load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<Ebpf, EbpfError> {
        let path = path.as_ref();
        self.load(&fs::read(path).map_err(|error| EbpfError::FileError {
            path: path.to_owned(),
            error,
        })?)
    }

    /// Loads eBPF bytecode from a buffer.
    ///
    /// The buffer needs to be 4-bytes aligned. If you are bundling the bytecode statically
    /// into your binary, it is recommended that you do so using
    /// [`include_bytes_aligned`](crate::include_bytes_aligned).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::EbpfLoader;
    /// use std::fs;
    ///
    /// let data = fs::read("file.o").unwrap();
    /// let bpf = EbpfLoader::new().load(&data)?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn load(&mut self, data: &[u8]) -> Result<Ebpf, EbpfError> {
        let Self {
            btf,
            default_map_pin_directory,
            globals,
            max_entries,
            extensions,
            verifier_log_level,
            allow_unsupported_maps,
            map_pin_path_by_name,
            kconfig,
        } = self;
        let mut obj = Object::parse(data)?;
        obj.patch_map_data(globals.clone())?;
        let requires_real_kconfig = obj.has_config_kconfig_externs()?;
        let kconfig = resolve_kconfig(kconfig, requires_real_kconfig, KConfig::current)
            .map_err(EbpfError::KConfigError)?;
        if let Some(kconfig) = kconfig.as_ref() {
            obj.prepare_kconfig_section(kconfig.as_map())?;
        }

        let btf_fd = if let Some(features) = &FEATURES.btf() {
            if let Some(btf) = obj.fixup_and_sanitize_btf(features)? {
                match load_btf(btf.to_bytes(), *verifier_log_level) {
                    Ok(btf_fd) => Some(Arc::new(btf_fd)),
                    // Only report an error here if the BTF is truly needed, otherwise proceed without.
                    Err(err) => {
                        for program in obj.programs.values() {
                            match program.section {
                                ProgramSection::Extension
                                | ProgramSection::FEntry { sleepable: _ }
                                | ProgramSection::FExit { sleepable: _ }
                                | ProgramSection::Lsm { sleepable: _ }
                                | ProgramSection::LsmCgroup
                                | ProgramSection::BtfTracePoint
                                | ProgramSection::Iter { sleepable: _ } => {
                                    return Err(EbpfError::BtfError(err));
                                }
                                ProgramSection::KRetProbe
                                | ProgramSection::KProbe
                                | ProgramSection::UProbe { sleepable: _ }
                                | ProgramSection::URetProbe { sleepable: _ }
                                | ProgramSection::TracePoint
                                | ProgramSection::SocketFilter
                                | ProgramSection::Xdp {
                                    frags: _,
                                    attach_type: _,
                                }
                                | ProgramSection::SkMsg
                                | ProgramSection::SkSkbStream { kind: _ }
                                | ProgramSection::SockOps
                                | ProgramSection::SchedClassifier
                                | ProgramSection::CgroupSkb { attach_type: _ }
                                | ProgramSection::CgroupSockAddr { attach_type: _ }
                                | ProgramSection::CgroupSysctl
                                | ProgramSection::CgroupSockopt { attach_type: _ }
                                | ProgramSection::LircMode2
                                | ProgramSection::PerfEvent
                                | ProgramSection::RawTracePoint
                                | ProgramSection::SkLookup
                                | ProgramSection::SkReuseport { attach_type: _ }
                                | ProgramSection::FlowDissector
                                | ProgramSection::CgroupSock { attach_type: _ }
                                | ProgramSection::CgroupDevice => {}
                            }
                        }

                        if obj.has_btf_relocations() {
                            return Err(EbpfError::BtfError(err));
                        }

                        warn!("object BTF couldn't be loaded in the kernel: {err}");

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
            if let (false, EbpfSectionKind::Bss | EbpfSectionKind::Data | EbpfSectionKind::Rodata) =
                (FEATURES.bpf_global_data(), obj.section_kind())
            {
                continue;
            }
            let num_cpus = || {
                Ok(nr_cpus().map_err(|(path, error)| EbpfError::FileError {
                    path: PathBuf::from(path),
                    error,
                })? as u32)
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
            if let Some(value_size) = value_size_override(map_type) {
                obj.set_value_size(value_size)
            }
            let btf_fd = btf_fd.as_deref().map(|fd| fd.as_fd());
            let mut map = if let Some(pin_path) = map_pin_path_by_name.get(name.as_str()) {
                MapData::create_pinned_by_name(pin_path, obj, &name, btf_fd)?
            } else {
                match obj.pinning() {
                    PinningType::None => MapData::create(obj, &name, btf_fd)?,
                    PinningType::ByName => {
                        // pin maps in /sys/fs/bpf by default to align with libbpf
                        // behavior https://github.com/libbpf/libbpf/blob/v1.2.2/src/libbpf.c#L2161.
                        let path = default_map_pin_directory
                            .as_deref()
                            .unwrap_or_else(|| Path::new("/sys/fs/bpf"));
                        let path = path.join(&name);

                        MapData::create_pinned_by_name(path, obj, &name, btf_fd)?
                    }
                }
            };
            map.finalize()?;
            maps.insert(name, map);
        }

        let text_sections = obj
            .functions
            .keys()
            .map(|(section_index, _)| *section_index)
            .collect();

        obj.relocate_maps(
            maps.iter()
                .map(|(s, data)| (s.as_str(), data.fd().as_fd().as_raw_fd(), data.obj())),
            &text_sections,
        )?;
        obj.relocate_calls(&text_sections)?;
        obj.sanitize_functions(&FEATURES);

        let programs = obj
            .programs
            .drain()
            .map(|(name, prog_obj)| {
                let function_obj = obj.functions[&prog_obj.function_key()].clone();

                let prog_name = FEATURES.bpf_name().then(|| name.clone().into());
                let section = prog_obj.section.clone();
                let obj = (prog_obj, function_obj);

                let btf_fd = btf_fd.as_ref().map(Arc::clone);
                let program = if extensions.contains(name.as_str()) {
                    Program::Extension(Extension {
                        data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                    })
                } else {
                    match &section {
                        ProgramSection::KProbe => Program::KProbe(KProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::Entry,
                        }),
                        ProgramSection::KRetProbe => Program::KProbe(KProbe {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: ProbeKind::Return,
                        }),
                        ProgramSection::UProbe { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::UProbe(UProbe {
                                data,
                                kind: ProbeKind::Entry,
                            })
                        }
                        ProgramSection::URetProbe { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::UProbe(UProbe {
                                data,
                                kind: ProbeKind::Return,
                            })
                        }
                        ProgramSection::TracePoint => Program::TracePoint(TracePoint {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SocketFilter => Program::SocketFilter(SocketFilter {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::Xdp {
                            frags, attach_type, ..
                        } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *frags {
                                data.flags = BPF_F_XDP_HAS_FRAGS;
                            }
                            Program::Xdp(Xdp {
                                data,
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::SkMsg => Program::SkMsg(SkMsg {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::CgroupSysctl => Program::CgroupSysctl(CgroupSysctl {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::CgroupSockopt { attach_type, .. } => {
                            Program::CgroupSockopt(CgroupSockopt {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::SkSkbStream { kind } => Program::SkSkb(SkSkb {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            kind: *kind,
                        }),
                        ProgramSection::SockOps => Program::SockOps(SockOps {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SchedClassifier => {
                            Program::SchedClassifier(SchedClassifier {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                            })
                        }
                        ProgramSection::CgroupSkb { attach_type } => {
                            Program::CgroupSkb(CgroupSkb {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::CgroupSockAddr { attach_type, .. } => {
                            Program::CgroupSockAddr(CgroupSockAddr {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::LircMode2 => Program::LircMode2(LircMode2 {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::PerfEvent => Program::PerfEvent(PerfEvent {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::RawTracePoint => Program::RawTracePoint(RawTracePoint {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::Lsm { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::Lsm(Lsm { data })
                        }
                        ProgramSection::LsmCgroup => Program::LsmCgroup(LsmCgroup {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::BtfTracePoint => Program::BtfTracePoint(BtfTracePoint {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::FEntry { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::FEntry(FEntry { data })
                        }
                        ProgramSection::FExit { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::FExit(FExit { data })
                        }
                        ProgramSection::FlowDissector => Program::FlowDissector(FlowDissector {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::Extension => Program::Extension(Extension {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SkLookup => Program::SkLookup(SkLookup {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::SkReuseport { attach_type } => {
                            Program::SkReuseport(SkReuseport {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::CgroupSock { attach_type, .. } => {
                            Program::CgroupSock(CgroupSock {
                                data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                                attach_type: *attach_type,
                            })
                        }
                        ProgramSection::CgroupDevice => Program::CgroupDevice(CgroupDevice {
                            data: ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level),
                        }),
                        ProgramSection::Iter { sleepable } => {
                            let mut data =
                                ProgramData::new(prog_name, obj, btf_fd, *verifier_log_level);
                            if *sleepable {
                                data.flags = BPF_F_SLEEPABLE;
                            }
                            Program::Iter(Iter { data })
                        }
                    }
                };
                (name, program)
            })
            .collect();
        let maps = maps
            .drain()
            .map(|data| parse_map(data, *allow_unsupported_maps))
            .collect::<Result<HashMap<String, Map>, EbpfError>>()?;

        Ok(Ebpf { maps, programs })
    }
}

fn parse_map(
    data: (String, MapData),
    allow_unsupported_maps: bool,
) -> Result<(String, Map), EbpfError> {
    let (name, map) = data;
    let map_type = bpf_map_type::try_from(map.obj().map_type()).map_err(MapError::from)?;
    let map = match map_type {
        bpf_map_type::BPF_MAP_TYPE_ARRAY => Map::Array(map),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY => Map::PerCpuArray(map),
        bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY => Map::ProgramArray(map),
        bpf_map_type::BPF_MAP_TYPE_HASH => Map::HashMap(map),
        bpf_map_type::BPF_MAP_TYPE_LRU_HASH => Map::LruHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH => Map::PerCpuHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH => Map::PerCpuLruHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => Map::PerfEventArray(map),
        bpf_map_type::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY => Map::ReusePortSockArray(map),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF => Map::RingBuf(map),
        bpf_map_type::BPF_MAP_TYPE_SOCKHASH => Map::SockHash(map),
        bpf_map_type::BPF_MAP_TYPE_SOCKMAP => Map::SockMap(map),
        bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER => Map::BloomFilter(map),
        bpf_map_type::BPF_MAP_TYPE_LPM_TRIE => Map::LpmTrie(map),
        bpf_map_type::BPF_MAP_TYPE_STACK => Map::Stack(map),
        bpf_map_type::BPF_MAP_TYPE_STACK_TRACE => Map::StackTraceMap(map),
        bpf_map_type::BPF_MAP_TYPE_QUEUE => Map::Queue(map),
        bpf_map_type::BPF_MAP_TYPE_CPUMAP => Map::CpuMap(map),
        bpf_map_type::BPF_MAP_TYPE_DEVMAP => Map::DevMap(map),
        bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH => Map::DevMapHash(map),
        bpf_map_type::BPF_MAP_TYPE_XSKMAP => Map::XskMap(map),
        bpf_map_type::BPF_MAP_TYPE_SK_STORAGE => Map::SkStorage(map),
        m_type => {
            if allow_unsupported_maps {
                Map::Unsupported(map)
            } else {
                return Err(EbpfError::MapError(MapError::Unsupported {
                    name,
                    map_type: m_type,
                }));
            }
        }
    };

    Ok((name, map))
}

/// Computes the value which should be used to override the `max_entries` value of the map
/// based on the user-provided override and the rules for that map type.
fn max_entries_override(
    map_type: bpf_map_type,
    user_override: Option<u32>,
    current_value: impl Fn() -> u32,
    num_cpus: impl Fn() -> Result<u32, EbpfError>,
    page_size: impl Fn() -> u32,
) -> Result<Option<u32>, EbpfError> {
    let max_entries = || user_override.unwrap_or_else(&current_value);
    Ok(match map_type {
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY if max_entries() == 0 => Some(num_cpus()?),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF => Some(adjust_to_page_size(max_entries(), page_size()))
            .filter(|adjusted| *adjusted != max_entries())
            .or(user_override),
        _ => user_override,
    })
}

/// Computes the value which should be used to override the `value_size` value of the map
/// based on the rules for that map type.
fn value_size_override(map_type: bpf_map_type) -> Option<u32> {
    match map_type {
        bpf_map_type::BPF_MAP_TYPE_CPUMAP => Some(if FEATURES.cpumap_prog_id() { 8 } else { 4 }),
        bpf_map_type::BPF_MAP_TYPE_DEVMAP | bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH => {
            Some(if FEATURES.devmap_prog_id() { 8 } else { 4 })
        }
        bpf_map_type::BPF_MAP_TYPE_RINGBUF => Some(0),
        _ => None,
    }
}

// Adjusts the byte size of a RingBuf map to match a power-of-two multiple of the page size.
//
// This mirrors the logic used by libbpf.
// See https://github.com/libbpf/libbpf/blob/ec6f716eda43/src/libbpf.c#L2461-L2463
const fn adjust_to_page_size(byte_size: u32, page_size: u32) -> u32 {
    // If the byte_size is zero, return zero and let the verifier reject the map
    // when it is loaded. This is the behavior of libbpf.
    if byte_size == 0 {
        return 0;
    }
    // TODO: Replace with primitive method when int_roundings (https://github.com/rust-lang/rust/issues/88581)
    // is stabilized.
    const fn div_ceil(n: u32, rhs: u32) -> u32 {
        let d = n / rhs;
        let r = n % rhs;
        if r > 0 && rhs > 0 { d + 1 } else { d }
    }
    let pages_needed = div_ceil(byte_size, page_size);
    page_size * pages_needed.next_power_of_two()
}

#[cfg(test)]
mod tests {
    use aya_obj::generated::bpf_map_type::*;

    const PAGE_SIZE: u32 = 4096;
    const NUM_CPUS: u32 = 4;

    #[test]
    fn test_adjust_to_page_size() {
        use super::adjust_to_page_size;
        for (exp, input) in [
            (0, 0),
            (4096, 1),
            (4096, 4095),
            (4096, 4096),
            (8192, 4097),
            (8192, 8192),
            (16384, 8193),
        ] {
            assert_eq!(exp, adjust_to_page_size(input, PAGE_SIZE));
        }
    }

    #[test]
    fn test_max_entries_override() {
        use super::max_entries_override;
        for (map_type, user_override, current_value, exp) in [
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
        ] {
            assert_eq!(
                exp,
                max_entries_override(
                    map_type,
                    user_override,
                    || current_value,
                    || Ok(NUM_CPUS),
                    || PAGE_SIZE,
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn test_resolve_kconfig_auto_uses_current() {
        let kconfig = super::KConfig::parse(b"CONFIG_TEST=1").unwrap();

        let resolved =
            super::resolve_kconfig(&super::KConfigMode::Auto, true, || Ok(kconfig.clone()))
                .unwrap();

        assert_eq!(resolved.unwrap().as_map(), kconfig.as_map());
    }

    #[test]
    fn test_resolve_kconfig_auto_uses_virtuals_only_when_real_kconfig_is_not_required() {
        let resolved = super::resolve_kconfig(&super::KConfigMode::Auto, false, || {
            Err(super::KConfigError::NotFound)
        })
        .unwrap();

        let resolved = resolved.unwrap();
        let map = resolved.as_map();
        assert!(map.contains_key("LINUX_KERNEL_VERSION"));
        assert!(map.contains_key("LINUX_HAS_BPF_COOKIE"));
        assert!(map.contains_key("LINUX_HAS_SYSCALL_WRAPPER"));
        assert!(!map.contains_key("CONFIG_TEST"));
    }

    #[test]
    fn test_resolve_kconfig_disabled_skips_current() {
        let resolved = super::resolve_kconfig(&super::KConfigMode::Disabled, true, || {
            panic!("current kernel config should not be loaded")
        })
        .unwrap();

        assert!(resolved.is_none());
    }

    #[test]
    fn test_resolve_kconfig_explicit_skips_current() {
        let kconfig = super::KConfig::parse(b"CONFIG_TEST=1").unwrap();

        let resolved =
            super::resolve_kconfig(&super::KConfigMode::Explicit(kconfig.clone()), true, || {
                panic!("current kernel config should not be loaded")
            })
            .unwrap();

        assert_eq!(resolved.unwrap().as_map(), kconfig.as_map());
    }

    #[test]
    fn test_resolve_kconfig_auto_propagates_errors_when_config_is_needed() {
        let err = super::resolve_kconfig(&super::KConfigMode::Auto, true, || {
            Err(super::KConfigError::NotFound)
        })
        .unwrap_err();

        assert!(matches!(err, super::KConfigError::NotFound));
    }

    #[test]
    #[cfg(feature = "flate2")]
    #[cfg_attr(
        miri,
        ignore = "tempfile uses filesystem operations blocked by Miri isolation"
    )]
    fn test_read_kconfig_prefers_boot_config_over_proc_config() {
        let tempdir = tempfile::tempdir().unwrap();
        let proc_config_path = tempdir.path().join("config.gz");
        let boot_config_path = tempdir.path().join("config");

        write_gzip_config(&proc_config_path, "CONFIG_PROC=y\n");
        std::fs::write(&boot_config_path, b"CONFIG_BOOT=y\n").unwrap();

        let config =
            super::read_kconfig_from_paths(Some(&proc_config_path), Some(&boot_config_path))
                .unwrap();

        assert_eq!(config, "CONFIG_BOOT=y\n");
    }

    #[test]
    #[cfg(feature = "flate2")]
    #[cfg_attr(
        miri,
        ignore = "tempfile uses filesystem operations blocked by Miri isolation"
    )]
    fn test_read_kconfig_falls_back_to_proc_when_boot_config_read_fails() {
        let tempdir = tempfile::tempdir().unwrap();
        let proc_config_path = tempdir.path().join("config.gz");
        let boot_config_path = tempdir.path().join("config");

        std::fs::create_dir(&boot_config_path).unwrap();
        write_gzip_config(&proc_config_path, "CONFIG_PROC=y\n");

        let config =
            super::read_kconfig_from_paths(Some(&proc_config_path), Some(&boot_config_path))
                .unwrap();

        assert_eq!(config, "CONFIG_PROC=y\n");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "tempfile uses filesystem operations blocked by Miri isolation"
    )]
    fn test_read_kconfig_returns_read_error_when_no_candidate_succeeds() {
        let tempdir = tempfile::tempdir().unwrap();
        let boot_config_path = tempdir.path().join("config");
        std::fs::create_dir(&boot_config_path).unwrap();

        let err = super::read_kconfig_from_paths(None, Some(&boot_config_path)).unwrap_err();

        assert!(matches!(err, super::KConfigError::Read { .. }));
    }

    #[test]
    fn test_parse_kconfig_ignores_commented_out_keys() {
        let kconfig =
            super::KConfig::parse(b"# CONFIG_DISABLED is not set\nCONFIG_ENABLED=y\n").unwrap();

        let map = kconfig.as_map();
        assert!(!map.contains_key("CONFIG_DISABLED"));
        assert_eq!(map["CONFIG_ENABLED"], b"y");
    }

    #[test]
    fn test_parse_kconfig_preserves_tristate_scalars() {
        let kconfig =
            super::KConfig::parse(b"CONFIG_NO=n\nCONFIG_YES=y\nCONFIG_MODULE=m\n").unwrap();

        let map = kconfig.as_map();
        assert_eq!(map["CONFIG_NO"], b"n");
        assert_eq!(map["CONFIG_YES"], b"y");
        assert_eq!(map["CONFIG_MODULE"], b"m");
    }

    #[test]
    fn test_parse_kconfig_rejects_malformed_lines() {
        let err = super::KConfig::parse(b"CONFIG_BROKEN\n").unwrap_err();
        assert!(matches!(
            err,
            super::KConfigError::MalformedLine { line } if line == "CONFIG_BROKEN"
        ));

        let err = super::KConfig::parse(b"CONFIG_BROKEN=\"unterminated\n").unwrap_err();
        assert!(matches!(
            err,
            super::KConfigError::MalformedLine { line } if line == "CONFIG_BROKEN=\"unterminated"
        ));
    }

    #[cfg(feature = "flate2")]
    fn write_gzip_config(path: &std::path::Path, contents: &str) {
        use std::io::Write as _;

        use flate2::{Compression, write::GzEncoder};

        let file = std::fs::File::create(path).unwrap();
        let mut file = GzEncoder::new(file, Compression::default());
        file.write_all(contents.as_bytes()).unwrap();
        file.finish().unwrap();
    }
}

impl Default for EbpfLoader<'_> {
    fn default() -> Self {
        EbpfLoader::new()
    }
}

/// The main entry point into the library, used to work with eBPF programs and maps.
#[derive(Debug)]
pub struct Ebpf {
    maps: HashMap<String, Map>,
    programs: HashMap<String, Program>,
}

/// The main entry point into the library, used to work with eBPF programs and maps.
#[deprecated(since = "0.13.0", note = "use `Ebpf` instead")]
pub type Bpf = Ebpf;

impl Ebpf {
    /// Loads eBPF bytecode from a file.
    ///
    /// Parses the given object code file and initializes the [maps](crate::maps) defined in it. If
    /// the kernel supports [BTF](Btf) debug info, it is automatically loaded from
    /// `/sys/kernel/btf/vmlinux`.
    ///
    /// For more loading options, see [`EbpfLoader`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::Ebpf;
    ///
    /// let bpf = Ebpf::load_file("file.o")?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self, EbpfError> {
        EbpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .load_file(path)
    }

    /// Loads eBPF bytecode from a buffer.
    ///
    /// Parses the object code contained in `data` and initializes the
    /// [maps](crate::maps) defined in it. If the kernel supports [BTF](Btf)
    /// debug info, it is automatically loaded from `/sys/kernel/btf/vmlinux`.
    ///
    /// The buffer needs to be 4-bytes aligned. If you are bundling the bytecode statically
    /// into your binary, it is recommended that you do so using
    /// [`include_bytes_aligned`](crate::include_bytes_aligned).
    ///
    /// For more loading options, see [`EbpfLoader`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya::{Ebpf, Btf};
    /// use std::fs;
    ///
    /// let data = fs::read("file.o").unwrap();
    /// // load the BTF data from /sys/kernel/btf/vmlinux
    /// let bpf = Ebpf::load(&data)?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn load(data: &[u8]) -> Result<Self, EbpfError> {
        EbpfLoader::new()
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
    /// Use this when borrowing with [`map`](crate::Ebpf::map) or [`map_mut`](crate::Ebpf::map_mut)
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
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// for (name, map) in bpf.maps() {
    ///     println!(
    ///         "found map `{}`",
    ///         name,
    ///     );
    /// }
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn maps(&self) -> impl Iterator<Item = (&str, &Map)> {
        self.maps.iter().map(|(name, map)| (name.as_str(), map))
    }

    /// A mutable iterator over all the maps.
    ///
    /// # Examples
    /// ```no_run
    /// # use std::path::Path;
    /// # #[derive(thiserror::Error, Debug)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Ebpf(#[from] aya::EbpfError),
    /// #     #[error(transparent)]
    /// #     Pin(#[from] aya::pin::PinError)
    /// # }
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// # let pin_path = Path::new("/tmp/pin_path");
    /// for (_, map) in bpf.maps_mut() {
    ///     map.pin(pin_path)?;
    /// }
    /// # Ok::<(), Error>(())
    /// ```
    pub fn maps_mut(&mut self) -> impl Iterator<Item = (&str, &mut Map)> {
        self.maps.iter_mut().map(|(name, map)| (name.as_str(), map))
    }

    /// Attempts to get mutable references to `N` maps at once.
    ///
    /// Returns an array of length `N` with the results of each query, in the same order
    /// as the requested map names. For soundness, at most one mutable reference will be
    /// returned to any map. `None` will be used if a map with the given name is missing.
    ///
    /// This method performs a check to ensure that there are no duplicate map names,
    /// which currently has a time-complexity of *O(n²)*. Be careful when passing a large
    /// number of names.
    ///
    /// # Panics
    ///
    /// Panics if any names are duplicated.
    ///
    /// # Examples
    /// ```no_run
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// match bpf.maps_disjoint_mut(["MAP1", "MAP2"]) {
    ///     [Some(m1), Some(m2)] => println!("Got MAP1 and MAP2"),
    ///     [Some(m1), None] => println!("Got only MAP1"),
    ///     [None, Some(m2)] => println!("Got only MAP2"),
    ///     [None, None] => println!("No maps"),
    /// }
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn maps_disjoint_mut<const N: usize>(&mut self, names: [&str; N]) -> [Option<&mut Map>; N] {
        self.maps.get_disjoint_mut(names)
    }

    /// Returns a reference to the program with the given name.
    ///
    /// You can use this to inspect a program and its properties. To load and attach a program, use
    /// [`program_mut`](Self::program_mut) instead.
    ///
    /// For more details on programs and their usage, see the [programs module
    /// documentation](crate::programs).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # let bpf = aya::Ebpf::load(&[])?;
    /// let program = bpf.program("SSL_read").unwrap();
    /// println!("program SSL_read is of type {:?}", program.prog_type());
    /// # Ok::<(), aya::EbpfError>(())
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
    /// # let mut bpf = aya::Ebpf::load(&[])?;
    /// use aya::programs::{uprobe::UProbeScope, UProbe};
    ///
    /// let program: &mut UProbe = bpf.program_mut("SSL_read").unwrap().try_into()?;
    /// program.load()?;
    /// program.attach("SSL_read", "libssl", UProbeScope::AllProcesses)?;
    /// # Ok::<(), aya::EbpfError>(())
    /// ```
    pub fn program_mut(&mut self, name: &str) -> Option<&mut Program> {
        self.programs.get_mut(name)
    }

    /// An iterator over all the programs.
    ///
    /// # Examples
    /// ```no_run
    /// # let bpf = aya::Ebpf::load(&[])?;
    /// for (name, program) in bpf.programs() {
    ///     println!(
    ///         "found program `{}` of type `{:?}`",
    ///         name,
    ///         program.prog_type()
    ///     );
    /// }
    /// # Ok::<(), aya::EbpfError>(())
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
    /// #     Ebpf(#[from] aya::EbpfError),
    /// #     #[error(transparent)]
    /// #     Pin(#[from] aya::pin::PinError)
    /// # }
    /// # let mut bpf = aya::Ebpf::load(&[])?;
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

/// The error type returned by [`Ebpf::load_file`] and [`Ebpf::load`].
#[derive(Debug, Error)]
pub enum EbpfError {
    /// Error loading file
    #[error("error loading {path}")]
    FileError {
        /// The file path
        path: PathBuf,
        #[source]
        /// The original [`io::Error`]
        error: io::Error,
    },

    /// Unexpected pinning type
    #[error("unexpected pinning type {name}")]
    UnexpectedPinningType {
        /// The value encountered
        name: u32,
    },

    /// Error parsing BPF object
    #[error("error parsing BPF object: {0}")]
    ParseError(#[from] ParseError),

    /// Error parsing BTF object
    #[error("BTF error: {0}")]
    BtfError(#[from] BtfError),

    /// Error reading kernel config data
    #[error("kernel config error: {0}")]
    KConfigError(KConfigError),

    /// Error performing relocations
    #[error("error relocating function")]
    RelocationError(#[from] EbpfRelocationError),

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

/// The error type returned by [`Bpf::load_file`] and [`Bpf::load`].
#[deprecated(since = "0.13.0", note = "use `EbpfError` instead")]
pub type BpfError = EbpfError;

fn load_btf(
    raw_btf: Vec<u8>,
    verifier_log_level: VerifierLogLevel,
) -> Result<crate::MockableFd, BtfError> {
    let (ret, verifier_log) = retry_with_verifier_logs(10, |logger| {
        bpf_load_btf(raw_btf.as_slice(), logger, verifier_log_level)
    });
    ret.map_err(|io_error| BtfError::LoadError {
        io_error,
        verifier_log,
    })
}

/// Global data that can be exported to eBPF programs before they are loaded.
///
/// Valid global data includes `Pod` types and slices of `Pod` types. See also
/// [`EbpfLoader::override_global`].
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
            bytes: bytes_of(v),
        }
    }
}
