//! Utilities for resolving symbols from addresses obtained via stack traces
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use addr2line::{
    gimli::{EndianRcSlice, RunTimeEndian},
    Context,
};
use lru_cache::LruCache;
use thiserror::Error;

use crate::util::kernel_symbols;

/// The error typey returned when creating various [`SymbolResolver`]s.
#[derive(Debug, Error)]
pub enum CreateResolverError {
    /// Failed to create a kernel symbol resolver
    #[error("Error creating KernelSymbolResolver: {error}")]
    KernelSymbolResolverBuildError {
        #[source]
        /// The original io::Error
        error: io::Error,
    },
}

/// Stores all information that was resolved for a specific symbol
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// Virtual memory address of a certain function
    virtual_address: u64,
    /// Address of a function inside an object. `None` if it was not resolved
    object_address: Option<u64>,
    /// The PID of the process in user space
    /// `None` is the symbol if the address is a kernel function
    process_id: Option<u32>,
    /// The resolved function name
    function_name: Option<String>,
    /// Path to the object which defines the symbol
    object_path: Option<PathBuf>,
}

impl SymbolInfo {
    /// Creates a `SymbolInfo` instance for a kernel-space function which hasn't been resolved yet
    pub fn unresolved_kernel(address: u64) -> Self {
        Self {
            virtual_address: address,
            object_address: Some(address),
            function_name: None,
            object_path: None,
            process_id: None,
        }
    }

    /// Creates a `SymbolInfo` instance for a user-space function which hasn't been resolved yet
    pub fn unresolved_user(process_id: u32, address: u64) -> Self {
        Self {
            virtual_address: address,
            object_address: None,
            function_name: None,
            object_path: None,
            process_id: Some(process_id),
        }
    }

    /// Whether the symbol refers to a kernel-space function
    pub fn is_kernel(&self) -> bool {
        self.process_id.is_none()
    }

    /// Whether the symbol refers to a user-space function
    pub fn is_user(&self) -> bool {
        self.process_id.is_some()
    }

    /// Returns the ID of the process for which the symbol was recorded
    pub fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    /// Virtual memory address of a certain function
    pub fn virtual_address(&self) -> u64 {
        self.virtual_address
    }

    /// Address of a function inside an object. `None` if it was not resolved
    pub fn object_address(&self) -> Option<u64> {
        self.object_address
    }

    /// Path to the object which defines the symbol
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }

    /// The resolved function name
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }
}

/// Resolves a symbol based on it's address.
///
/// See [`DefaultResolver`] for exemplaric usage.
pub trait SymbolResolver {
    /// Resolves a symbol based on it's address
    fn resolve(&self, symbol: &mut SymbolInfo);
}

/// A resolver for kernel symbols
pub struct KernelSymbolResolver {
    symbols: BTreeMap<u64, String>,
}

impl KernelSymbolResolver {
    /// Creates a new `KernelSymbolResolver`
    ///
    /// This will load all kernel symbols from `/proc/kallsyms`.
    pub fn new() -> Result<Self, CreateResolverError> {
        let symbols = kernel_symbols()
            .map_err(|e| CreateResolverError::KernelSymbolResolverBuildError { error: e })?;
        Ok(Self { symbols })
    }
}

impl SymbolResolver for KernelSymbolResolver {
    fn resolve(&self, symbol: &mut SymbolInfo) {
        if symbol.process_id().is_some() || symbol.function_name.is_some() {
            return;
        }

        symbol.function_name = self
            .symbols
            .range(..=symbol.virtual_address())
            .next_back()
            .map(|(_, s)| s.clone());
    }
}

/// A SymbolResolver which uses the `addr2line` Rust library
pub struct Addr2LineResolver {
    state: RefCell<Addr2LineResolverState>,
}

/// Builder for a `Addr2LineResolver`
impl Addr2LineResolver {
    /// Returns `Addr2lineResolverBuilder` which allows to configure the `Addr2Resolver`
    pub fn builder() -> Addr2lineResolverBuilder {
        Addr2lineResolverBuilder {
            proc_map_lru_capacity: 512,
            object_resolver_capacity: 512,
        }
    }
}

/// A builder for `Addr2LineResolver` instances
pub struct Addr2lineResolverBuilder {
    proc_map_lru_capacity: usize,
    object_resolver_capacity: usize,
}

impl Addr2lineResolverBuilder {
    /// Configures the capacity of the LRU cache that is used to look up process memory maps
    pub fn proc_map_lru_capacity(&mut self, capacity: usize) -> &mut Self {
        self.proc_map_lru_capacity = capacity;
        self
    }

    /// Configures the capacity of the LRU cache that is used to hold information
    /// about libraries and executables in order to resolve function names.
    pub fn object_resolver_capacity(&mut self, capacity: usize) -> &mut Self {
        self.object_resolver_capacity = capacity;
        self
    }

    /// Builds an `Addr2LineResolver` with the provided configuration
    pub fn build(&self) -> Result<Addr2LineResolver, CreateResolverError> {
        Ok(Addr2LineResolver {
            state: RefCell::new(Addr2LineResolverState {
                proc_map: LruCache::new(self.proc_map_lru_capacity),
                object_resolvers: LruCache::new(self.object_resolver_capacity),
            }),
        })
    }
}

struct Addr2LineResolverState {
    proc_map: LruCache<u32, Option<ProcMemMap>>,
    object_resolvers: LruCache<PathBuf, Option<Addr2LineObjectContext>>,
}

impl SymbolResolver for Addr2LineResolver {
    fn resolve(&self, symbol: &mut SymbolInfo) {
        // Resolving a userspace symbol from a virtual memory address is a 2 step process
        // - First, we translate the address from a virtual memory address to the
        //   address that is actually used in the object file. If the information is
        //   already provided, we can skip this step.
        // - Next, we resolve the actual symbol inside the object.

        if symbol.object_path().is_none() || symbol.object_address().is_none() {
            let pid = match symbol.process_id() {
                Some(pid) => pid,
                None => return,
            };

            let mut guard = self.state.borrow_mut();
            let proc_map = match guard.proc_map.get_mut(&pid) {
                Some(Some(proc_map)) => proc_map,
                Some(None) => return,
                None => {
                    let proc_map = ProcMemMap::from_process_id(pid).ok();
                    guard.proc_map.insert(pid, proc_map);

                    match guard
                        .proc_map
                        .get_mut(&pid)
                        .expect("Entry was just inserted")
                        .as_ref()
                    {
                        Some(proc_map) => proc_map,
                        None => return,
                    }
                }
            };

            match proc_map.lookup(symbol.virtual_address()) {
                Some(lookup_result) => {
                    symbol.object_address = Some(lookup_result.address());
                    symbol.object_path = lookup_result.object_path().map(|path| path.to_path_buf());
                }
                None => return,
            };
        };

        let (object_path, object_address) = match (symbol.object_path(), symbol.object_address()) {
            (Some(object_path), Some(object_address)) => (object_path, object_address),
            _ => return,
        };

        let mut guard = self.state.borrow_mut();
        symbol.function_name = match guard.object_resolvers.get_mut(object_path) {
            Some(Some(p)) => p.resolve(object_address),
            Some(None) => return,
            None => match Addr2LineObjectContext::from_object_path(object_path) {
                Err(_) => {
                    // Cache the error, in order to avoid retrying loading the file
                    guard.object_resolvers.insert(object_path.to_owned(), None);
                    return;
                }
                Ok(addr2line) => {
                    let function_name = addr2line.resolve(object_address);
                    guard
                        .object_resolvers
                        .insert(object_path.to_owned(), Some(addr2line));
                    function_name
                }
            },
        };
    }
}

/// A [`SymbolResolver`] which uses the [`Addr2LineResolver`] for resolving
/// userspace functions, and the [`KernelSymbolResolver`] for resolving kernel functions.
struct CombinedResolver {
    kernel: KernelSymbolResolver,
    user: Addr2LineResolver,
}

impl CombinedResolver {
    pub fn new() -> Result<Self, CreateResolverError> {
        let kernel = KernelSymbolResolver::new()?;
        let user = Addr2LineResolver::builder().build()?;
        Ok(Self { kernel, user })
    }
}

impl SymbolResolver for CombinedResolver {
    fn resolve(&self, symbol: &mut SymbolInfo) {
        match symbol.is_user() {
            true => self.user.resolve(symbol),
            false => self.kernel.resolve(symbol),
        }
    }
}

/// A default resolver which can resolve kernel and userspace symbols,
/// and caches last observed symbol information in memory.
///
/// # Examples
///
/// ```no_run
/// # use aya::symbols::{DefaultResolver, SymbolResolver, SymbolInfo};
/// let resolver = DefaultResolver::new().unwrap();
///
/// // Resolve a kernel-space symbol based on an address obtained from a stack trace
/// let mut kernel_symbol = SymbolInfo::unresolved_kernel(0x1234_5678);
/// resolver.resolve(&mut kernel_symbol);
/// println!("{:?}", kernel_symbol.function_name());
///
/// // Resolve a user-space symbol based on an a process-id and address obtained from a stack trace
/// let mut user_symbol = SymbolInfo::unresolved_user(7654, 0x1234_5678);
/// resolver.resolve(&mut user_symbol);
/// println!("{:?}", user_symbol.function_name());
/// ```
pub struct DefaultResolver {
    inner: CachingResolver<CombinedResolver>,
}

impl DefaultResolver {
    /// Create a new DefaultResolver
    pub fn new() -> Result<Self, CreateResolverError> {
        let caching_resolver = CachingResolver::with_capacity(8192, CombinedResolver::new()?);
        Ok(Self {
            inner: caching_resolver,
        })
    }
}

impl SymbolResolver for DefaultResolver {
    fn resolve(&self, symbol: &mut SymbolInfo) {
        self.inner.resolve(symbol)
    }
}

/// Hash key for the `CachingResolver`
#[derive(Hash, PartialEq, Eq, Copy, Clone)]
struct CachingResolverHashKey {
    virtual_address: u64,
    process_id: Option<u32>,
}

/// A resolver which caches observed symbols
pub struct CachingResolver<T> {
    cache: RefCell<LruCache<CachingResolverHashKey, SymbolInfo>>,
    inner: T,
}

impl<T: SymbolResolver> CachingResolver<T> {
    /// Creates a new CachingResolve using a cache that can hold up to `capacity` results
    pub fn with_capacity(capacity: usize, inner: T) -> Self {
        Self {
            cache: RefCell::new(LruCache::new(capacity)),
            inner,
        }
    }
}

impl<T: SymbolResolver> SymbolResolver for CachingResolver<T> {
    fn resolve(&self, symbol: &mut SymbolInfo) {
        let key = CachingResolverHashKey {
            virtual_address: symbol.virtual_address(),
            process_id: symbol.process_id(),
        };

        let mut guard = self.cache.borrow_mut();
        match guard.get_mut(&key) {
            Some(result) => {
                *symbol = result.clone();
            }
            None => {
                self.inner.resolve(symbol);
                // TODO: Since we store potentially incomplete SymbolInfo here,
                // we might miss out the chance to get later on additional information
                guard.insert(key, symbol.clone());
            }
        }
    }
}

/// The error type that is used when resolving symbols using the addr2line library
#[derive(Debug, Error)]
pub enum Addr2LineError {
    /// Failed to read the context of the executable or library
    #[error("Failed to read object data at path {path}")]
    InvalidObjectPath {
        /// The object path
        path: PathBuf,
        /// The original io::Error
        source: io::Error,
    },
    /// Failed to parse data for an executable or library
    #[error("Failed to read object data at path {path}")]
    ParseError {
        /// The object path
        path: PathBuf,
        /// The original error
        source: addr2line::object::Error,
    },
    /// Failed to create the gimli resolver context
    #[error("Failed to read object data at path {path}")]
    CreateContextError {
        /// The object path
        path: PathBuf,
        /// The original error
        source: addr2line::gimli::Error,
    },
}

struct Addr2LineObjectContext {
    ctx: Context<EndianRcSlice<RunTimeEndian>>,
}

impl Addr2LineObjectContext {
    pub fn from_object_path(path: &Path) -> Result<Self, Addr2LineError> {
        let data = std::fs::read(path).map_err(|e| Addr2LineError::InvalidObjectPath {
            path: path.to_owned(),
            source: e,
        })?;
        let object: addr2line::object::File<_> = addr2line::object::File::parse(&data[..])
            .map_err(|e| Addr2LineError::ParseError {
                path: path.to_owned(),
                source: e,
            })?;
        let ctx = Context::new(&object).map_err(|e| Addr2LineError::CreateContextError {
            path: path.to_owned(),
            source: e,
        })?;

        Ok(Self { ctx })
    }
}

impl Addr2LineObjectContext {
    pub fn resolve(&self, address: u64) -> Option<String> {
        match self.ctx.find_frames(address) {
            Ok(mut frames) => {
                let mut result = None;

                while let Ok(Some(frame)) = frames.next() {
                    let frame = frame.function.and_then(|function_name| {
                        function_name
                            .demangle()
                            .map(|demangled_name| demangled_name.to_string())
                            .ok()
                    });

                    // Return the last frame in the stack of frames, since the inlined functions
                    // are often very unspecific and don't necessarily tell the user
                    // which function is really executed. E.g.
                    // - "core::result::Result<T,E>::as_ref"
                    // - "core::cell::BorrowRefMut::new"
                    if frame.is_some() {
                        result = frame;
                    }
                }

                result
            }
            Err(_) => None,
        }
    }
}

/// Parsed line for /proc/[pid]/maps
struct ProcMemMapEntry {
    address_range: (u64, u64),
    offset: u64,
    object_path: String,
}

/// Holds the memory map of a process, which can be obtained by reading `/proc/[pid]/map`.
///
/// This allows to translate virtual memory addresses inside a process into
/// a physical memory address, plus the path of the executable or library.
///
/// Example of a `/proc/[pid]/maps` entry:
/// 563b0178b000-563b01807000 r--p 00000000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01807000-563b01c4b000 r-xp 0007c000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01c4b000-563b01d85000 r--p 004c0000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01d86000-563b01dbe000 r--p 005fa000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 563b01dbe000-563b01dbf000 rw-p 00632000 00:40 3659174697971092           /home/myuser/code/ayatest/target/debug/ayatest
/// 7f38911ff000-7f38913ff000 rw-p 00000000 00:00 0
/// 7f38913ff000-7f3891400000 ---p 00000000 00:00 0
/// 7f3891400000-7f3891402000 rw-p 00000000 00:00 0
/// 7f3891402000-7f3891403000 ---p 00000000 00:00 0
/// 7f3891403000-7f3891603000 rw-p 00000000 00:00 0
/// 7f3892fbc000-7f3892fbd000 r--p 00000000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fbd000-7f3892fe0000 r-xp 00001000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fe0000-7f3892fe8000 r--p 00024000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fe9000-7f3892fea000 r--p 0002c000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
/// 7f3892fea000-7f3892feb000 rw-p 0002d000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
pub struct ProcMemMap {
    entries: Vec<ProcMemMapEntry>,
}

/// Looks up information for a virtual address
#[derive(Debug)]
pub struct ProcMemMapLookupResult {
    /// Physical memory address
    address: u64,
    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    object_path: Option<PathBuf>,
}

impl ProcMemMapLookupResult {
    /// Physical memory address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }
}

impl ProcMemMap {
    /// Loads the memory map for a given process from procfs
    pub fn from_process_id(pid: u32) -> Result<Self, ProcMemMapError> {
        let reader = BufReader::new(File::open(format!("/proc/{}/maps", pid)).map_err(|e| {
            ProcMemMapError::OpenProcMemMapError {
                process_id: pid,
                source: e,
            }
        })?);
        parse_maps(reader)
    }

    /// Tries to look up a virtual address, and obtain the physical address of a certain executable or library
    ///
    /// Returns `None` if the address can not be found
    pub fn lookup(&self, address: u64) -> Option<ProcMemMapLookupResult> {
        for entry in self.entries.iter() {
            if address >= entry.address_range.0 && address < entry.address_range.1 {
                let translated = address - entry.address_range.0 + entry.offset;

                let object_path = match &entry.object_path {
                    p if p.is_empty() => None,
                    p if p.starts_with('[') => None,
                    p => Some(PathBuf::from(p)),
                };

                return Some(ProcMemMapLookupResult {
                    address: translated,
                    object_path,
                });
            }
        }

        None
    }
}

/// Error type for interaction with process memory maps
#[derive(Debug, Error)]
pub enum ProcMemMapError {
    /// Failed to read the context of the executable or library
    #[error("Failed to open memory map for process {process_id}")]
    OpenProcMemMapError {
        /// Process ID
        process_id: u32,
        /// The original io::Error
        source: io::Error,
    },
    /// Failed to read a full line in the process memory map
    #[error("Can not parse line")]
    ReadLineError {
        /// The original io::Error
        source: std::io::Error,
    },
    /// Failed to parse address information in the process memory map
    #[error("Can not parse address: Line: {line}")]
    InvalidAddress {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse permissions in the process memory map
    #[error("Can not parse permissions: Line: {line}")]
    InvalidPermissions {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse an offset in the process memory map
    #[error("Can not parse offset: Line: {line}")]
    InvalidOffset {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse device data in the process memory map
    #[error("Can not parse device: Line: {line}")]
    InvalidDevice {
        /// The line which could not be parsed
        line: String,
    },
    /// Failed to parse inode data in the process memory map
    #[error("Can not parse inode: Line: {line}")]
    InvalidInode {
        /// The line which could not be parsed
        line: String,
    },
}

fn parse_maps(reader: impl BufRead) -> Result<ProcMemMap, ProcMemMapError> {
    // See https://man7.org/linux/man-pages/man5/proc.5.html for details
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| ProcMemMapError::ReadLineError { source: e })?;
        let mut parts = line.splitn(6, ' ');
        let address = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let mut address_parts = address.split('-');
        let start_address = address_parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let end_address = address_parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidAddress { line: line.clone() })?;
        let _perms = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidPermissions { line: line.clone() })?;
        let offset = parts
            .next()
            .and_then(|o| u64::from_str_radix(o, 16).ok())
            .ok_or_else(|| ProcMemMapError::InvalidOffset { line: line.clone() })?;
        let _dev = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidDevice { line: line.clone() })?;
        let _inode = parts
            .next()
            .ok_or_else(|| ProcMemMapError::InvalidInode { line: line.clone() })?;
        // TODO: Newlines in the path are escaped via an octal escape sequence.
        // We don't unescape it yet - therefore path with newlines are not supported
        let object_path = parts.next().unwrap_or("").trim().to_string();

        entries.push(ProcMemMapEntry {
            address_range: (start_address, end_address),
            offset,
            object_path,
        });
    }
    Ok(ProcMemMap { entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_process_map() {
        let data = "563b0178b000-563b01807000 r--p 00000000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01807000-563b01c4b000 r-xp 0007c000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01c4b000-563b01d85000 r--p 004c0000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01d86000-563b01dbe000 r--p 005fa000 00:40 3659174697971092           /usr/bin/something/something\n\
            563b01dbe000-563b01dbf000 rw-p 00632000 00:40 3659174697971092           /usr/bin/something/something\n\
            7f38911ff000-7f38913ff000 rw-p 00000000 00:00 0\n\
            7f38913ff000-7f3891400000 ---p 00000000 00:00 0\n\
            7f3891400000-7f3891402000 rw-p 00000000 00:00 0\n\
            7f3891402000-7f3891403000 ---p 00000000 00:00 0\n\
            7f3891403000-7f3891603000 rw-p 00000000 00:00 0\n\
            7f3892fbc000-7f3892fbd000 r--p 00000000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fbd000-7f3892fe0000 r-xp 00001000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fe0000-7f3892fe8000 r--p 00024000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fe9000-7f3892fea000 r--p 0002c000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            7f3892fea000-7f3892feb000 rw-p 0002d000 08:20 42625                      /usr/lib/x86_64-linux-gnu/ld-2.31.so\n\
            800000000000-900000000000 rw-p 00000000 00:00 0                          [stack:100000000000] ".as_bytes();
        let map = parse_maps(&mut BufReader::new(data)).unwrap();

        let result = map.lookup(0x563b01807200).unwrap();
        assert_eq!(result.address(), 0x200 + 0x7c000);
        assert_eq!(
            result.object_path().unwrap().to_str().unwrap(),
            "/usr/bin/something/something"
        );

        let result = map.lookup(0x7f3891400100).unwrap();
        assert_eq!(result.address(), 0x100);
        assert_eq!(result.object_path(), None);

        let result = map.lookup(0x7f3892fbe111).unwrap();
        assert_eq!(result.address(), 0x1111 + 0x1000);
        assert_eq!(
            result.object_path().unwrap().to_str().unwrap(),
            "/usr/lib/x86_64-linux-gnu/ld-2.31.so"
        );

        let result = map.lookup(0x800000005000).unwrap();
        assert_eq!(result.address(), 0x5000);
        assert_eq!(result.object_path(), None);
    }
}
