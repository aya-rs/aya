//! Utility functions.
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File},
    io::{self, BufRead, BufReader},
    mem, slice,
    str::FromStr,
};

use crate::{
    generated::{TC_H_MAJ_MASK, TC_H_MIN_MASK},
    Pod,
};

use libc::{if_nametoindex, sysconf, uname, utsname, _SC_PAGESIZE};

/// Represents a kernel version, in major.minor.release version.
// Adapted from https://docs.rs/procfs/latest/procfs/sys/kernel/struct.Version.html.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd)]
pub struct KernelVersion {
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) patch: u16,
}

impl KernelVersion {
    /// Constructor.
    pub fn new(major: u8, minor: u8, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns the kernel version of the currently running kernel.
    pub fn current() -> Result<Self, String> {
        let kernel_version = Self::get_kernel_version();

        // The kernel version is clamped to 4.19.255 on kernels 4.19.222 and above.
        //
        // See https://github.com/torvalds/linux/commit/a256aac.
        const CLAMPED_KERNEL_MAJOR: u8 = 4;
        const CLAMPED_KERNEL_MINOR: u8 = 19;
        if let Ok(Self {
            major: CLAMPED_KERNEL_MAJOR,
            minor: CLAMPED_KERNEL_MINOR,
            patch: 222..,
        }) = kernel_version
        {
            return Ok(Self::new(CLAMPED_KERNEL_MAJOR, CLAMPED_KERNEL_MINOR, 255));
        }

        kernel_version
    }

    // This is ported from https://github.com/torvalds/linux/blob/3f01e9f/tools/lib/bpf/libbpf_probes.c#L21-L101.

    fn get_ubuntu_kernel_version() -> Result<Option<Self>, String> {
        const UBUNTU_KVER_FILE: &str = "/proc/version_signature";
        let s = match fs::read(UBUNTU_KVER_FILE) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(format!("failed to read {}: {}", UBUNTU_KVER_FILE, e));
            }
        };
        (|| {
            let ubuntu: String;
            let ubuntu_version: String;
            let major: u8;
            let minor: u8;
            let patch: u16;
            text_io::try_scan!(s.iter().copied() => "{} {} {}.{}.{}\n", ubuntu, ubuntu_version, major, minor, patch);
            Ok(Some(Self::new(major, minor, patch)))
        })().map_err(|e: text_io::Error| format!("failed to parse {:?}: {}", s, e))
    }

    fn get_debian_kernel_version(info: &utsname) -> Result<Option<Self>, String> {
        // Safety: man 2 uname:
        //
        // The length of the arrays in a struct utsname is unspecified (see NOTES); the fields are
        // terminated by a null byte ('\0').
        let p = unsafe { CStr::from_ptr(info.version.as_ptr()) };
        let p = p
            .to_str()
            .map_err(|e| format!("failed to parse version: {}", e))?;
        let p = match p.split_once("Debian ") {
            Some((_prefix, suffix)) => suffix,
            None => return Ok(None),
        };
        (|| {
            let major: u8;
            let minor: u8;
            let patch: u16;
            text_io::try_scan!(p.bytes() => "{}.{}.{}", major, minor, patch);
            Ok(Some(Self::new(major, minor, patch)))
        })()
        .map_err(|e: text_io::Error| format!("failed to parse {}: {}", p, e))
    }

    fn get_kernel_version() -> Result<Self, String> {
        if let Some(v) = Self::get_ubuntu_kernel_version()? {
            return Ok(v);
        }

        let mut info = unsafe { mem::zeroed::<utsname>() };
        if unsafe { uname(&mut info) } != 0 {
            return Err(format!(
                "failed to get kernel version: {}",
                io::Error::last_os_error()
            ));
        }

        if let Some(v) = Self::get_debian_kernel_version(&info)? {
            return Ok(v);
        }

        // Safety: man 2 uname:
        //
        // The length of the arrays in a struct utsname is unspecified (see NOTES); the fields are
        // terminated by a null byte ('\0').
        let p = unsafe { CStr::from_ptr(info.release.as_ptr()) };
        let p = p
            .to_str()
            .map_err(|e| format!("failed to parse release: {}", e))?;
        // Unlike sscanf, text_io::try_scan! does not stop at the first non-matching character.
        let p = match p.split_once(|c: char| c != '.' && !c.is_ascii_digit()) {
            Some((prefix, _suffix)) => prefix,
            None => p,
        };
        (|| {
            let major: u8;
            let minor: u8;
            let patch: u16;
            text_io::try_scan!(p.bytes() => "{}.{}.{}", major, minor, patch);
            Ok(Self::new(major, minor, patch))
        })()
        .map_err(|e: text_io::Error| format!("failed to parse {}: {}", p, e))
    }
}

const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";
pub(crate) const POSSIBLE_CPUS: &str = "/sys/devices/system/cpu/possible";

/// Returns the numeric IDs of the CPUs currently online.
pub fn online_cpus() -> Result<Vec<u32>, io::Error> {
    let data = fs::read_to_string(ONLINE_CPUS)?;
    parse_cpu_ranges(data.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected {ONLINE_CPUS} format"),
        )
    })
}

/// Get the number of possible cpus.
///
/// See `/sys/devices/system/cpu/possible`.
pub fn nr_cpus() -> Result<usize, io::Error> {
    Ok(possible_cpus()?.len())
}

/// Get the list of possible cpus.
///
/// See `/sys/devices/system/cpu/possible`.
pub(crate) fn possible_cpus() -> Result<Vec<u32>, io::Error> {
    let data = fs::read_to_string(POSSIBLE_CPUS)?;
    parse_cpu_ranges(data.trim()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected {POSSIBLE_CPUS} format"),
        )
    })
}

fn parse_cpu_ranges(data: &str) -> Result<Vec<u32>, ()> {
    let mut cpus = Vec::new();
    for range in data.split(',') {
        cpus.extend({
            match range
                .splitn(2, '-')
                .map(u32::from_str)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ())?
                .as_slice()
            {
                &[] | &[_, _, _, ..] => return Err(()),
                &[start] => start..=start,
                &[start, end] => start..=end,
            }
        })
    }

    Ok(cpus)
}

/// Loads kernel symbols from `/proc/kallsyms`.
///
/// The symbols can be passed to [`StackTrace::resolve`](crate::maps::stack_trace::StackTrace::resolve).
pub fn kernel_symbols() -> Result<BTreeMap<u64, String>, io::Error> {
    let mut reader = BufReader::new(File::open("/proc/kallsyms")?);
    parse_kernel_symbols(&mut reader)
}

fn parse_kernel_symbols(reader: impl BufRead) -> Result<BTreeMap<u64, String>, io::Error> {
    let mut syms = BTreeMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts = line.splitn(4, ' ').collect::<Vec<_>>();
        let addr = u64::from_str_radix(parts[0], 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, line.clone()))?;
        let name = parts[2].to_owned();
        syms.insert(addr, name);
    }

    Ok(syms)
}

/// Returns the prefix used by syscalls.
///
/// # Example
///
/// ```no_run
/// use aya::util::syscall_prefix;
/// let prefix = syscall_prefix().unwrap();
/// let syscall_fname = format!("{prefix}exec");
/// ```
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::NotFound`] if the prefix can't be guessed. Returns other [`std::io::Error`] kinds if `/proc/kallsyms` can't be opened or is somehow invalid.
pub fn syscall_prefix() -> Result<&'static str, io::Error> {
    const PREFIXES: [&str; 7] = [
        "sys_",
        "__x64_sys_",
        "__x32_compat_sys_",
        "__ia32_compat_sys_",
        "__arm64_sys_",
        "__s390x_sys_",
        "__s390_sys_",
    ];
    let ksym = kernel_symbols()?;
    for p in PREFIXES {
        let prefixed_syscall = format!("{}bpf", p);
        if ksym.values().any(|el| *el == prefixed_syscall) {
            return Ok(p);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

pub(crate) fn ifindex_from_ifname(if_name: &str) -> Result<u32, io::Error> {
    let c_str_if_name = CString::new(if_name)?;
    let c_if_name = c_str_if_name.as_ptr();
    // Safety: libc wrapper
    let if_index = unsafe { if_nametoindex(c_if_name) };
    if if_index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(if_index)
}

pub(crate) fn tc_handler_make(major: u32, minor: u32) -> u32 {
    (major & TC_H_MAJ_MASK) | (minor & TC_H_MIN_MASK)
}

/// Include bytes from a file for use in a subsequent [`crate::Bpf::load`].
///
/// This macro differs from the standard `include_bytes!` macro since it also ensures that
/// the bytes are correctly aligned to be parsed as an ELF binary. This avoid some nasty
/// compilation errors when the resulting byte array is not the correct alignment.
///
/// # Examples
/// ```ignore
/// use aya::{Bpf, include_bytes_aligned};
///
/// let mut bpf = Bpf::load(include_bytes_aligned!(
///     "/path/to/bpf.o"
/// ))?;
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[macro_export]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(align(32))]
        pub struct Aligned32;

        #[repr(C)]
        pub struct Aligned<Bytes: ?Sized> {
            pub _align: [Aligned32; 0],
            pub bytes: Bytes,
        }

        static ALIGNED: &Aligned<[u8]> = &Aligned {
            _align: [],
            bytes: *include_bytes!($path),
        };

        &ALIGNED.bytes
    }};
}

pub(crate) fn page_size() -> usize {
    // Safety: libc
    (unsafe { sysconf(_SC_PAGESIZE) }) as usize
}

// bytes_of converts a <T> to a byte slice
pub(crate) unsafe fn bytes_of<T: Pod>(val: &T) -> &[u8] {
    let size = mem::size_of::<T>();
    slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size)
}

pub(crate) fn bytes_of_slice<T: Pod>(val: &[T]) -> &[u8] {
    let size = val.len().wrapping_mul(mem::size_of::<T>());
    // Safety:
    // Any alignment is allowed.
    // The size is determined in this function.
    // The Pod trait ensures the type is valid to cast to bytes.
    unsafe { slice::from_raw_parts(val.as_ptr().cast(), size) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_online_cpus() {
        assert_eq!(parse_cpu_ranges("0").unwrap(), vec![0]);
        assert_eq!(parse_cpu_ranges("0,1").unwrap(), vec![0, 1]);
        assert_eq!(parse_cpu_ranges("0,1,2").unwrap(), vec![0, 1, 2]);
        assert_eq!(
            parse_cpu_ranges("0-7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert_eq!(
            parse_cpu_ranges("0-3,4-7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert_eq!(
            parse_cpu_ranges("0-5,6,7").unwrap(),
            (0..=7).collect::<Vec<_>>()
        );
        assert!(parse_cpu_ranges("").is_err());
        assert!(parse_cpu_ranges("0-1,2-").is_err());
        assert!(parse_cpu_ranges("foo").is_err());
    }

    #[test]
    fn test_parse_kernel_symbols() {
        let data = "0000000000002000 A irq_stack_backing_store\n\
                          0000000000006000 A cpu_tss_rw [foo bar]\n"
            .as_bytes();
        let syms = parse_kernel_symbols(&mut BufReader::new(data)).unwrap();
        assert_eq!(syms.keys().collect::<Vec<_>>(), vec![&0x2000, &0x6000]);
        assert_eq!(
            syms.get(&0x2000u64).unwrap().as_str(),
            "irq_stack_backing_store"
        );
        assert_eq!(syms.get(&0x6000u64).unwrap().as_str(), "cpu_tss_rw");
    }
}
