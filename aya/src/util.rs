//! Utility functions.
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File},
    io::{self, BufReader},
    mem, slice,
    str::FromStr,
};

use crate::generated::{TC_H_MAJ_MASK, TC_H_MIN_MASK};

use libc::{if_nameindex, if_nametoindex, sysconf, _SC_PAGESIZE};

use io::BufRead;

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

pub(crate) fn ifname_from_ifindex(if_index: u32) -> Result<String, std::io::Error> {
    let mut buffer: [libc::c_char; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];
    let name = unsafe {
        // Returns null on error
        let res = libc::if_indextoname(if_index, buffer.as_mut_ptr());

        if res.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        CStr::from_ptr(buffer.as_ptr())
    };

    Ok(name.to_string_lossy().to_string())
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
pub(crate) unsafe fn bytes_of<T>(val: &T) -> &[u8] {
    let size = mem::size_of::<T>();
    slice::from_raw_parts(slice::from_ref(val).as_ptr().cast(), size)
}

const MIN_LOG_BUF_SIZE: usize = 1024 * 10;
const MAX_LOG_BUF_SIZE: usize = (std::u32::MAX >> 8) as usize;

pub(crate) struct VerifierLog {
    buf: Vec<u8>,
}

impl VerifierLog {
    pub(crate) fn new() -> VerifierLog {
        VerifierLog { buf: Vec::new() }
    }

    pub(crate) fn buf(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    pub(crate) fn grow(&mut self) {
        let len = (self.buf.capacity() * 10).clamp(MIN_LOG_BUF_SIZE, MAX_LOG_BUF_SIZE);
        self.buf.resize(len, 0);
        self.reset();
    }

    pub(crate) fn reset(&mut self) {
        if !self.buf.is_empty() {
            self.buf[0] = 0;
        }
    }

    pub(crate) fn truncate(&mut self) {
        if self.buf.is_empty() {
            return;
        }

        let pos = self
            .buf
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.buf.len() - 1);
        self.buf[pos] = 0;
        self.buf.truncate(pos + 1);
    }

    pub(crate) fn as_c_str(&self) -> Option<&CStr> {
        if self.buf.is_empty() {
            None
        } else {
            Some(CStr::from_bytes_with_nul(&self.buf).unwrap())
        }
    }
}

#[derive(Debug, Clone)]
/// A kernel network interface.
// if_name isn't stored because it can change in the kernel and aya won't know
pub struct NetworkInterface {
    pub(crate) index: i32,
}

impl NetworkInterface {
    /// Provides a number that can be used to identify this interface on this system.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Extracts the interface name from the kernel.
    pub fn name(&self) -> Result<String, std::io::Error> {
        ifname_from_ifindex(self.index as u32)
    }

    /// Provides a [Vec] of all operating system network interfaces, including virtual ones.
    /// # Example
    ///
    /// ```
    /// let interfaces_names: Vec<String> = NetworkInterface::list()
    ///     .iter()
    ///     .map(|interface| interface.name().unwrap())
    ///     .collect();
    /// ```
    pub fn list() -> Vec<NetworkInterface> {
        let mut list = Vec::new();

        // The nameindex array is terminated by an interface with if_index == 0 and if_name == null
        let head = unsafe { libc::if_nameindex() };
        let mut curr = head;

        while let Ok(interface) = NetworkInterface::from_ifnameindex(unsafe { *curr }) {
            list.push(interface);
            curr = unsafe { curr.add(1) };
        }

        unsafe {
            libc::if_freenameindex(head);
        };

        list
    }

    // Returns Err is the interface is invalid (zeroed)
    fn from_ifnameindex(value: if_nameindex) -> Result<Self, ()> {
        if value.if_index == 0 || value.if_name.is_null() {
            return Err(());
        }

        Ok(NetworkInterface {
            index: value.if_index as i32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

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

    #[test]
    fn network_interface_list() {
        let interfaces_dir = "/sys/class/net";

        let expected: Vec<String> = std::fs::read_dir(interfaces_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();

        let interfaces = NetworkInterface::list();

        assert_eq!(expected.len(), interfaces.len());

        for interface in interfaces {
            let name = interface.name().unwrap().to_string();
            assert!(expected.contains(&name));
        }
    }

    #[test]
    fn network_interface_from_ifnameindex() {
        use libc::if_nameindex;
        use std::ptr::null_mut;

        let name = CString::new("eth0").unwrap();

        let k_interface = if_nameindex {
            if_index: 1,
            if_name: name.as_ptr() as *mut i8,
        };

        let interface = NetworkInterface::from_ifnameindex(k_interface).unwrap();

        assert_eq!(interface.index(), 1);

        let invalid_k_interface = if_nameindex {
            if_index: 0,
            if_name: null_mut(),
        };

        let res = NetworkInterface::from_ifnameindex(invalid_k_interface);
        assert_eq!(res.unwrap_err(), ());

        let invalid_k_interface = if_nameindex {
            if_index: 1,
            if_name: null_mut(),
        };

        let res = NetworkInterface::from_ifnameindex(invalid_k_interface);
        assert_eq!(res.unwrap_err(), ());
    }

    #[test]
    fn network_interface_name() {
        let interfaces_dir = "/sys/class/net";

        let first_interface_path = std::fs::read_dir(interfaces_dir)
            .expect("Failed to read sysfs interface directory")
            .next();

        if let Some(first_interface_path) = first_interface_path {
            let (name, index) = {
                let entry = first_interface_path.unwrap();
                let file_name = entry.file_name();
                let mut path = entry.path();
                path.push("ifindex");
                let index_contents = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
                let index = index_contents.trim().parse::<i32>().unwrap();
                (file_name, index)
            };

            let interface = NetworkInterface { index };

            assert_eq!(
                name.to_string_lossy().to_string(),
                interface.name().unwrap()
            );
        } else {
            panic!("no interfaces found in {interfaces_dir} to test");
        }
    }
}
