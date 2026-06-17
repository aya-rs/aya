//! Extern type resolution and relocation.
use std::{os::fd::RawFd, string::ToString as _};

use crate::{
    Object,
    btf::{
        Btf, BtfError, BtfKind, BtfType,
        view::{BtfView, SplitBtf},
    },
    util::{HashMap, HashSet},
};

impl Object {
    /// Resolves extern kernel symbols through kernel `BTF` and `kallsyms`.
    ///
    /// Module BTF discovery is performed lazily through `discover_modules` only when typed externs
    /// cannot all be resolved from `vmlinux`.
    pub fn resolve_externs<P, F>(
        &mut self,
        vmlinux: Option<&Btf>,
        discover_modules: F,
    ) -> Result<ResolvedExterns<P>, ResolveExternsError<P::Error>>
    where
        P: ExternModuleBtfProvider,
        F: FnOnce() -> Result<P, P::Error>,
    {
        if self.btf.is_none() {
            return Ok(ResolvedExterns::without_modules());
        }

        if self.has_strong_typed_ksyms() && vmlinux.is_none() {
            return Err(KsymsError::TypedKsymRequiresKernelBtf.into());
        }

        let modules = if self.needs_module_btf(vmlinux) {
            Some(discover_modules().map_err(ResolveExternsError::ModuleBtf)?)
        } else {
            None
        };

        let resolver_modules = if let Some(modules) = &modules {
            modules
                .extern_resolution_modules()
                .map_err(ResolveExternsError::ModuleBtf)?
        } else {
            Vec::new()
        };

        self.resolve_externs_with_resolver(&ExternResolver::new(vmlinux, &resolver_modules))?;

        if self.has_resolved_module_btf_targets() {
            Ok(ResolvedExterns::with_modules(modules.expect(
                "module BTF target resolved without module BTF provider",
            )))
        } else {
            Ok(ResolvedExterns::without_modules())
        }
    }

    fn resolve_externs_with_resolver(
        &mut self,
        resolver: &ExternResolver<'_>,
    ) -> Result<(), KsymsError> {
        self.resolve_typed_externs(resolver)?;
        self.resolve_typeless_externs()?;

        Ok(())
    }

    fn needs_module_btf(&self, vmlinux: Option<&Btf>) -> bool {
        let Some(obj_btf) = self.btf.as_ref() else {
            return false;
        };

        if obj_btf.externs.is_empty() {
            return false;
        }

        let Some(vmlinux) = vmlinux else {
            return false;
        };

        for (name, extern_desc) in obj_btf
            .externs
            .iter()
            .filter(|(_, extern_desc)| extern_desc.type_id.is_some())
        {
            let Ok(kind) = extern_btf_kind(obj_btf, name, extern_desc) else {
                continue;
            };
            let lookup_name = extern_desc.lookup_name(name, kind);
            if vmlinux.id_by_type_name_kind(lookup_name, kind).is_err() {
                return true;
            }
        }

        false
    }

    fn has_resolved_module_btf_targets(&self) -> bool {
        self.btf.as_ref().is_some_and(|btf| {
            btf.externs
                .iter()
                .any(|(_, ext)| matches!(ext.resolved, Some(ResolvedKsymTarget::ModuleBtf { .. })))
        })
    }

    /// Returns whether the object contains strong typed ksyms that require kernel `BTF`.
    pub(crate) fn has_strong_typed_ksyms(&self) -> bool {
        self.btf.as_ref().is_some_and(|btf| {
            btf.externs.iter().any(|(_, ext)| {
                ext.extern_type == ExternType::Ksym && ext.type_id.is_some() && !ext.is_weak
            })
        })
    }

    /// Resolves typed externs through kernel `BTF`.
    pub(crate) fn resolve_typed_externs(
        &mut self,
        resolver: &ExternResolver<'_>,
    ) -> Result<(), KsymsError> {
        let mut resolutions = Vec::new();
        {
            let obj_btf = self
                .btf
                .as_ref()
                .expect("resolve_typed_externs called without local BTF");

            for (name, extern_desc) in obj_btf
                .externs
                .iter()
                .filter(|(_, extern_desc)| extern_desc.type_id.is_some())
            {
                let resolution = match extern_btf_kind(obj_btf, name, extern_desc)? {
                    BtfKind::Func => self.resolve_extern_function(name, extern_desc, resolver)?,
                    BtfKind::Var => self.resolve_extern_variable(name, extern_desc, resolver)?,
                    _ => {
                        return Err(KsymsError::InvalidExternType { name: name.clone() });
                    }
                };

                resolutions.push((name.clone(), resolution));
            }
        }

        let obj_mut = self
            .btf
            .as_mut()
            .expect("resolve_typed_externs called without local BTF");

        for (name, resolved) in resolutions {
            if let Some(ext) = obj_mut.externs.get_mut(&name) {
                ext.resolved = Some(resolved);
            }
        }

        Ok(())
    }

    /// Resolves typeless extern vars found in `.ksyms` section through `kallsyms`.
    pub(crate) fn resolve_typeless_externs(&mut self) -> Result<(), KsymsError> {
        let unresolved: Vec<String> = self.unresolved_typeless_ksym_vars();

        if !unresolved.is_empty() {
            let file = std::fs::File::open("/proc/kallsyms")?;
            let reader = std::io::BufReader::new(file);
            self.resolve_kallsyms_from_reader(reader, &unresolved)?;
        }

        // Default unresolved weak ksyms to address 0 so pointer checks evaluate to false.
        if let Some(obj_btf) = self.btf.as_mut() {
            for ext in obj_btf.externs.externs.values_mut() {
                if ext.extern_type == ExternType::Ksym
                    && ext.resolved.is_none()
                    && ext.is_weak
                    && ext.type_id.is_none()
                {
                    ext.resolved = Some(ResolvedKsymTarget::WeakMissing);
                }
            }
        }

        Ok(())
    }

    /// Resolves typeless ksym addresses by matching symbol names against parsed kallsyms lines.
    fn resolve_kallsyms_from_reader<R, S>(
        &mut self,
        reader: R,
        unresolved: &[S],
    ) -> Result<(), KsymsError>
    where
        R: std::io::BufRead,
        S: AsRef<str>,
    {
        let obj_btf = self
            .btf
            .as_mut()
            .expect("resolve_kallsyms_from_reader called without local BTF");

        let unresolved: HashSet<_> = unresolved.iter().map(AsRef::as_ref).collect();

        for line in reader.lines() {
            let line = line?;
            let mut parts = line.split_whitespace();
            let (Some(addr_str), Some(_sym_type), Some(sym_name)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };

            if !unresolved.contains(sym_name) {
                continue;
            }

            let addr = u64::from_str_radix(addr_str, 16).map_err(|_err| {
                KsymsError::KallsymsParseError(format!("invalid address: {addr_str}"))
            })?;
            if addr == 0 {
                continue;
            }

            if let Some(ext) = obj_btf.externs.get_mut(sym_name) {
                if let Some(ResolvedKsymTarget::Address {
                    addr: existing_addr,
                }) = ext.resolved
                {
                    if existing_addr != addr {
                        return Err(KsymsError::AmbiguousResolution {
                            name: sym_name.to_string(),
                            first_addr: existing_addr,
                            second_addr: addr,
                        });
                    }
                    continue;
                }

                ext.resolved = Some(ResolvedKsymTarget::Address { addr });
            }
        }

        // Reject unresolved strong typeless ksyms after the kallsyms pass.
        // Typed ksyms fail earlier during BTF resolution.
        for (name, ext) in obj_btf.externs.iter() {
            if ext.extern_type == ExternType::Ksym
                && ext.resolved.is_none()
                && !ext.is_weak
                && ext.type_id.is_none()
            {
                return Err(KsymsError::VariableNotFound { name: name.clone() });
            }
        }

        Ok(())
    }

    /// Returns unresolved typeless ksym variables from [`ExternCollection`].
    fn unresolved_typeless_ksym_vars(&self) -> Vec<String> {
        let Some(obj_btf) = self.btf.as_ref() else {
            return Vec::new();
        };

        obj_btf
            .externs
            .externs
            .iter()
            .filter(|(_, ext)| {
                ext.extern_type == ExternType::Ksym
                    && ext.resolved.is_none()
                    && ext.type_id.is_none()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn resolve_extern_function(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        resolver: &ExternResolver<'_>,
    ) -> Result<ResolvedKsymTarget, KsymsError> {
        let lookup_name = extern_desc.lookup_name(name, BtfKind::Func);

        if let Some(vmlinux) = resolver.vmlinux {
            match vmlinux.id_by_type_name_kind(lookup_name, BtfKind::Func) {
                Ok(func_id) => {
                    return self.resolve_extern_function_in_btf(
                        lookup_name,
                        extern_desc,
                        vmlinux,
                        func_id,
                        BtfTarget::Vmlinux,
                    );
                }
                Err(BtfError::UnknownBtfTypeName { .. }) => {}
                Err(err) => return Err(err.into()),
            }
        }

        if let Some(vmlinux) = resolver.vmlinux {
            for module in resolver.modules {
                let split = SplitBtf::new(vmlinux, module.btf);
                match split.id_by_type_name_kind_own(lookup_name, BtfKind::Func) {
                    Ok(func_id) => {
                        return self.resolve_extern_function_in_btf(
                            lookup_name,
                            extern_desc,
                            &split,
                            func_id,
                            BtfTarget::Module {
                                fd_idx: module.fd_idx,
                                obj_fd: module.btf_obj_fd,
                            },
                        );
                    }
                    Err(BtfError::UnknownBtfTypeName { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        if extern_desc.is_weak {
            Ok(ResolvedKsymTarget::WeakMissing)
        } else {
            Err(KsymsError::FunctionNotFound {
                name: lookup_name.to_string(),
            })
        }
    }

    fn resolve_extern_variable(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        resolver: &ExternResolver<'_>,
    ) -> Result<ResolvedKsymTarget, KsymsError> {
        let lookup_name = extern_desc.lookup_name(name, BtfKind::Var);

        if let Some(vmlinux) = resolver.vmlinux {
            match vmlinux.id_by_type_name_kind(lookup_name, BtfKind::Var) {
                Ok(var_id) => {
                    return self.resolve_extern_variable_in_btf(
                        lookup_name,
                        extern_desc,
                        vmlinux,
                        var_id,
                        BtfTarget::Vmlinux,
                    );
                }
                Err(BtfError::UnknownBtfTypeName { .. }) => {}
                Err(err) => return Err(err.into()),
            }
        }

        if let Some(vmlinux) = resolver.vmlinux {
            for module in resolver.modules {
                let split = SplitBtf::new(vmlinux, module.btf);
                match split.id_by_type_name_kind_own(lookup_name, BtfKind::Var) {
                    Ok(var_id) => {
                        return self.resolve_extern_variable_in_btf(
                            lookup_name,
                            extern_desc,
                            &split,
                            var_id,
                            BtfTarget::Module {
                                fd_idx: module.fd_idx,
                                obj_fd: module.btf_obj_fd,
                            },
                        );
                    }
                    Err(BtfError::UnknownBtfTypeName { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        if extern_desc.is_weak {
            Ok(ResolvedKsymTarget::WeakMissing)
        } else {
            Err(KsymsError::VariableNotFound {
                name: lookup_name.to_string(),
            })
        }
    }

    fn resolve_extern_function_in_btf<T: BtfView + ?Sized>(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        target_btf: &T,
        target_func_id: u32,
        target: BtfTarget,
    ) -> Result<ResolvedKsymTarget, KsymsError> {
        let target_func_type = target_btf.type_by_id(target_func_id)?;
        let target_proto_id = match target_func_type {
            BtfType::Func(func) => func.btf_type,
            _ => {
                return Err(KsymsError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: target_func_id,
                }));
            }
        };

        let local_proto_id = extern_desc.type_id.expect("typed extern must have type_id");
        let obj_btf = self
            .btf
            .as_ref()
            .expect("resolve_extern_function called without local BTF");
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_proto_id, target_btf, target_proto_id)?;

        if !compatible {
            if extern_desc.is_weak {
                return Ok(ResolvedKsymTarget::WeakMissing);
            }
            return Err(KsymsError::IncompatibleFunctionSignature {
                name: name.to_string(),
            });
        }

        Ok(target.resolved(target_func_id))
    }

    fn resolve_extern_variable_in_btf<T: BtfView + ?Sized>(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        target_btf: &T,
        target_var_id: u32,
        target: BtfTarget,
    ) -> Result<ResolvedKsymTarget, KsymsError> {
        let target_var_type = target_btf.type_by_id(target_var_id)?;
        let target_type_id = match target_var_type {
            BtfType::Var(var) => var.btf_type,
            _ => {
                return Err(KsymsError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: target_var_id,
                }));
            }
        };

        let local_type_id = extern_desc.type_id.expect("typed extern must have type_id");
        let obj_btf = self
            .btf
            .as_ref()
            .expect("resolve_extern_variable called without local BTF");
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_type_id, target_btf, target_type_id)?;

        if !compatible {
            return Err(KsymsError::IncompatibleVariableType {
                name: name.to_string(),
            });
        }

        Ok(target.resolved(target_var_id))
    }
}

fn extern_btf_kind(btf: &Btf, name: &str, extern_desc: &ExternDesc) -> Result<BtfKind, KsymsError> {
    match btf.type_by_id(extern_desc.btf_id)? {
        BtfType::Func(_) => Ok(BtfKind::Func),
        BtfType::Var(_) => Ok(BtfKind::Var),
        _ => Err(KsymsError::InvalidExternType {
            name: name.to_owned(),
        }),
    }
}

/// Errors that can occur during ksyms operations.
#[derive(Debug, thiserror::Error)]
pub enum KsymsError {
    /// A typed ksym was encountered but kernel BTF is unavailable.
    #[error("typed ksyms require kernel BTF for resolution")]
    TypedKsymRequiresKernelBtf,

    /// A non-weak extern variable was not found in kernel BTF or kallsyms.
    #[error("kernel variable '{name}' not found")]
    VariableNotFound {
        /// The name of the variable that was not found.
        name: String,
    },

    /// The extern function's signature is incompatible with the kernel function.
    #[error("kernel function '{name}' has incompatible signature")]
    IncompatibleFunctionSignature {
        /// The name of the function with incompatible signature.
        name: String,
    },

    /// The extern variable's type is incompatible with the kernel variable.
    #[error("kernel variable '{name}' has incompatible type")]
    IncompatibleVariableType {
        /// The name of the variable with incompatible type.
        name: String,
    },

    /// The extern symbol has an invalid BTF type (neither `Func` nor `Var`).
    #[error("extern '{name}' has invalid BTF type (neither Func nor Var)")]
    InvalidExternType {
        /// The name of the extern with invalid type.
        name: String,
    },

    /// An error occurred while working with BTF data.
    #[error("BTF error: {0}")]
    BtfError(#[from] BtfError),

    /// Resolved extern's kallsyms address does not match against the loaded kallsyms.
    #[error("extern (ksym) '{name}': resolution is ambiguous: {first_addr:#x} or {second_addr:#x}")]
    AmbiguousResolution {
        /// The name of the symbol with ambiguous resolution.
        name: String,
        /// The first address found.
        first_addr: u64,
        /// The second (conflicting) address found.
        second_addr: u64,
    },

    /// Could not read kallsyms entries.
    #[error("failed to read /proc/kallsyms: {0}")]
    KallsymsReadError(#[from] std::io::Error),

    /// Failed to parse kallsyms data.
    #[error("failed to parse kallsyms: {0}")]
    KallsymsParseError(String),

    /// A non-weak typed extern function was not found in kernel BTF.
    #[error("kernel function '{name}' not found in kernel BTF")]
    FunctionNotFound {
        /// The function name.
        name: String,
    },
}

pub(crate) struct ExternResolver<'a> {
    vmlinux: Option<&'a Btf>,
    modules: &'a [ExternResolverModule<'a>],
}

impl<'a> ExternResolver<'a> {
    pub(crate) const fn new(
        vmlinux: Option<&'a Btf>,
        modules: &'a [ExternResolverModule<'a>],
    ) -> Self {
        Self { vmlinux, modules }
    }

    #[cfg(test)]
    pub(crate) const fn vmlinux_only(vmlinux: Option<&'a Btf>) -> Self {
        Self {
            vmlinux,
            modules: &[],
        }
    }
}

/// A module BTF made available to extern resolution.
#[derive(Clone, Copy)]
pub struct ExternResolverModule<'a> {
    /// Parsed module BTF.
    pub btf: &'a Btf,
    /// Index into the loader's BTF fd array. Index 0 is reserved for vmlinux.
    pub fd_idx: u16,
    /// Literal module BTF object FD, used by `BPF_PSEUDO_BTF_ID` relocations.
    pub btf_obj_fd: RawFd,
}

/// Supplies module BTFs to extern resolution after lazy discovery.
pub trait ExternModuleBtfProvider {
    /// Error returned while building module BTF resolution inputs.
    type Error;

    /// Returns module BTF descriptors available to extern resolution.
    fn extern_resolution_modules(&self) -> Result<Vec<ExternResolverModule<'_>>, Self::Error>;
}

/// Error returned while resolving externs with lazy module BTF discovery.
#[derive(Debug, thiserror::Error)]
pub enum ResolveExternsError<E> {
    /// Extern resolution failed.
    #[error("kernel symbol error: {0}")]
    Ksyms(#[from] KsymsError),
    /// Module BTF discovery or preparation failed.
    #[error("module BTF discovery failed: {0}")]
    ModuleBtf(E),
}

/// Result of extern resolution, including module BTF ownership when it must stay alive.
#[derive(Debug)]
pub struct ResolvedExterns<P> {
    modules: Option<P>,
}

impl<P> ResolvedExterns<P> {
    const fn without_modules() -> Self {
        Self { modules: None }
    }

    const fn with_modules(modules: P) -> Self {
        Self {
            modules: Some(modules),
        }
    }

    /// Returns module BTF ownership when resolved externs require it for program load.
    pub fn into_modules(self) -> Option<P> {
        self.modules
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedKsymTarget {
    VmlinuxBtf {
        type_id: u32,
    },
    ModuleBtf {
        type_id: u32,
        btf_fd_idx: u16,
        btf_obj_fd: RawFd,
    },
    Address {
        addr: u64,
    },
    WeakMissing,
}

#[derive(Debug, Clone, Copy)]
enum BtfTarget {
    Vmlinux,
    Module { fd_idx: u16, obj_fd: RawFd },
}

impl BtfTarget {
    const fn resolved(self, type_id: u32) -> ResolvedKsymTarget {
        match self {
            Self::Vmlinux => ResolvedKsymTarget::VmlinuxBtf { type_id },
            Self::Module { fd_idx, obj_fd } => ResolvedKsymTarget::ModuleBtf {
                type_id,
                btf_fd_idx: fd_idx,
                btf_obj_fd: obj_fd,
            },
        }
    }
}

/// Type of extern symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternType {
    /// Kernel symbol - variable or function (`.ksyms` section).
    Ksym,
}

/// Descriptor for an extern symbol.
#[derive(Debug, Clone)]
pub(crate) struct ExternDesc {
    /// Symbol name.
    pub(crate) name: String,

    /// Type of extern.
    pub(crate) extern_type: ExternType,

    /// BTF type ID in local (program) BTF.
    pub(crate) btf_id: u32,

    /// Whether this is a weak symbol.
    pub(crate) is_weak: bool,

    /// For ksym: resolved type ID (after skipping modifiers/typedefs).
    pub(crate) type_id: Option<u32>,

    /// For names with flavors: stripped essential name.
    pub(crate) essential_name: Option<String>,

    /// Resolved target for this extern.
    pub(crate) resolved: Option<ResolvedKsymTarget>,
}

/// Given `some_struct_name___with_flavor` return the length of a name prefix
/// before last triple underscore. Struct name part after last triple
/// underscore is ignored by BPF CO-RE relocation during relocation matching.
fn essential_name_len(name: &str) -> usize {
    let n = name.len();
    if n < 5 {
        return n;
    }

    for i in (0..=n - 5).rev() {
        if is_flavor_sep(name, i) {
            return i + 1;
        }
    }

    n
}

fn is_flavor_sep(s: &str, pos: usize) -> bool {
    let bytes = s.as_bytes();
    if pos + 4 >= bytes.len() {
        return false;
    }
    bytes[pos] != b'_'
        && bytes[pos + 1] == b'_'
        && bytes[pos + 2] == b'_'
        && bytes[pos + 3] == b'_'
        && bytes[pos + 4] != b'_'
}

impl ExternDesc {
    pub(crate) fn new(name: String, extern_type: ExternType, btf_id: u32, is_weak: bool) -> Self {
        let essential_len = essential_name_len(&name);
        let essential_name =
            (essential_len != name.len()).then(|| name[..essential_len].to_string());

        Self {
            name,
            extern_type,
            btf_id,
            is_weak,
            type_id: None,
            essential_name,
            resolved: None,
        }
    }

    fn lookup_name<'a>(&'a self, symbol_name: &'a str, kind: BtfKind) -> &'a str {
        match kind {
            BtfKind::Func => self.essential_name.as_deref().unwrap_or(symbol_name),
            BtfKind::Var => symbol_name,
            _ => symbol_name,
        }
    }
}

/// Collection of extern symbols.
#[derive(Debug, Default, Clone)]
pub(crate) struct ExternCollection {
    /// Map of extern descriptors by name.
    pub(crate) externs: HashMap<String, ExternDesc>,

    /// BTF ID of the placeholder var used for `.ksyms` function entries (if created).
    pub(crate) ksym_func_placeholder_id: Option<u32>,

    /// Index ID of `.ksyms` datasec entry in BTF types.
    pub(crate) datasec_id: Option<u32>,
}

impl ExternCollection {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn insert(&mut self, name: String, desc: ExternDesc) {
        self.externs.insert(name, desc);
    }

    pub(crate) fn get_mut(&mut self, name: &str) -> Option<&mut ExternDesc> {
        self.externs.get_mut(name)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &ExternDesc)> {
        self.externs.iter()
    }

    pub(crate) const fn set_ksym_func_placeholder_id(&mut self, id: u32) {
        self.ksym_func_placeholder_id = Some(id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.externs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, convert::Infallible, ffi::CString};

    use object::Endianness;

    use super::{
        ExternCollection, ExternDesc, ExternModuleBtfProvider, ExternResolver,
        ExternResolverModule, ExternType, KsymsError, ResolveExternsError, ResolvedKsymTarget,
    };
    use crate::{
        Object,
        btf::{
            Btf, BtfParam, BtfType, Func, FuncLinkage, FuncProto, Int, IntEncoding, Ptr, Var,
            VarLinkage,
        },
    };

    fn object_with_externs(externs: ExternCollection) -> Object {
        let mut btf = Btf::new();
        btf.externs = externs;

        Object {
            endianness: Endianness::default(),
            license: CString::new("GPL").unwrap(),
            kernel_version: None,
            btf: Some(btf),
            btf_ext: None,
            maps: Default::default(),
            programs: Default::default(),
            functions: BTreeMap::new(),
            relocations: Default::default(),
            symbol_table: Default::default(),
            symbols_by_section: Default::default(),
            section_infos: Default::default(),
            symbol_offset_by_name: Default::default(),
        }
    }

    fn object_with_btf_and_externs(mut btf: Btf, externs: ExternCollection) -> Object {
        btf.externs = externs;

        Object {
            endianness: Endianness::default(),
            license: CString::new("GPL").unwrap(),
            kernel_version: None,
            btf: Some(btf),
            btf_ext: None,
            maps: Default::default(),
            programs: Default::default(),
            functions: BTreeMap::new(),
            relocations: Default::default(),
            symbol_table: Default::default(),
            symbols_by_section: Default::default(),
            section_infos: Default::default(),
            symbol_offset_by_name: Default::default(),
        }
    }

    fn add_int(btf: &mut Btf, name: &str) -> u32 {
        let name_offset = btf.add_string(name);
        btf.add_type(BtfType::Int(Int::new(
            name_offset,
            4,
            IntEncoding::Signed,
            0,
        )))
    }

    fn add_var(btf: &mut Btf, name: &str, type_id: u32) -> u32 {
        let name_offset = btf.add_string(name);
        btf.add_type(BtfType::Var(Var::new(
            name_offset,
            type_id,
            VarLinkage::Global,
        )))
    }

    fn add_func_proto(btf: &mut Btf, return_type: u32, params: Vec<BtfParam>) -> u32 {
        btf.add_type(BtfType::FuncProto(FuncProto::new(params, return_type)))
    }

    fn add_func(btf: &mut Btf, name: &str, proto_id: u32) -> u32 {
        let name_offset = btf.add_string(name);
        btf.add_type(BtfType::Func(Func::new(
            name_offset,
            proto_id,
            FuncLinkage::Global,
        )))
    }

    fn add_split_var(base: &Btf, split: &mut Btf, name: &str, type_id: u32) -> u32 {
        let name_offset = base.string_len() + split.add_string(name);
        let local_id = split.add_type(BtfType::Var(Var::new(
            name_offset,
            type_id,
            VarLinkage::Global,
        )));
        base.type_count() + local_id - 1
    }

    fn add_split_func(base: &Btf, split: &mut Btf, name: &str, proto_id: u32) -> u32 {
        let name_offset = base.string_len() + split.add_string(name);
        let local_id = split.add_type(BtfType::Func(Func::new(
            name_offset,
            proto_id,
            FuncLinkage::Global,
        )));
        base.type_count() + local_id - 1
    }

    struct NoModuleBtfProvider;

    impl ExternModuleBtfProvider for NoModuleBtfProvider {
        type Error = Infallible;

        fn extern_resolution_modules(&self) -> Result<Vec<ExternResolverModule<'_>>, Self::Error> {
            Ok(Vec::new())
        }
    }

    struct TestModuleBtfProvider<'a> {
        btf: &'a Btf,
        fd_idx: u16,
        btf_obj_fd: i32,
    }

    impl ExternModuleBtfProvider for TestModuleBtfProvider<'_> {
        type Error = Infallible;

        fn extern_resolution_modules(&self) -> Result<Vec<ExternResolverModule<'_>>, Self::Error> {
            Ok(vec![ExternResolverModule {
                btf: self.btf,
                fd_idx: self.fd_idx,
                btf_obj_fd: self.btf_obj_fd,
            }])
        }
    }

    #[test]
    fn resolve_externs_requires_kernel_btf_for_typed_ksyms() {
        let mut externs = ExternCollection::new();

        let mut typed = ExternDesc::new("typed".into(), ExternType::Ksym, 1, false);
        typed.type_id = Some(42);
        externs.insert(typed.name.clone(), typed);

        let mut object = object_with_externs(externs);

        let err = object
            .resolve_externs(None, || -> Result<NoModuleBtfProvider, Infallible> {
                panic!("module BTF discovery should not run without vmlinux BTF")
            })
            .err()
            .unwrap();
        assert!(matches!(
            err,
            ResolveExternsError::Ksyms(KsymsError::TypedKsymRequiresKernelBtf)
        ));
    }

    #[test]
    fn resolve_externs_allows_weak_typed_ksyms_without_kernel_btf() {
        let mut btf = Btf::new();
        let int_id = add_int(&mut btf, "int");
        let var_id = add_var(&mut btf, "typed", int_id);

        let mut externs = ExternCollection::new();
        let mut typed = ExternDesc::new("typed".into(), ExternType::Ksym, var_id, true);
        typed.type_id = Some(int_id);
        externs.insert(typed.name.clone(), typed);

        let mut object = object_with_btf_and_externs(btf, externs);

        object
            .resolve_externs(None, || -> Result<NoModuleBtfProvider, Infallible> {
                panic!("module BTF discovery should not run without vmlinux BTF")
            })
            .unwrap();

        let ext = &object.btf.as_ref().unwrap().externs.externs["typed"];
        assert_eq!(ext.resolved, Some(ResolvedKsymTarget::WeakMissing));
    }

    #[test]
    fn resolve_typed_externs_rejects_invalid_extern_type() {
        let mut btf = Btf::new();
        let int_id = add_int(&mut btf, "int");

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("bad".into(), ExternType::Ksym, int_id, false);
        ext.type_id = Some(int_id);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_btf_and_externs(btf, externs);
        let kernel_btf = Btf::new();

        let err = object
            .resolve_typed_externs(&ExternResolver::vmlinux_only(Some(&kernel_btf)))
            .unwrap_err();
        assert!(matches!(err, KsymsError::InvalidExternType { name } if name == "bad"));
    }

    #[test]
    fn resolve_extern_variable_incompatible_type() {
        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_var_id = add_var(&mut local_btf, "foo", local_int_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("foo".into(), ExternType::Ksym, local_var_id, false);
        ext.type_id = Some(local_int_id);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut kernel_btf = Btf::new();
        let kernel_int_id = add_int(&mut kernel_btf, "int");
        let ptr_name_offset = kernel_btf.add_string("int_ptr");
        let kernel_ptr_id =
            kernel_btf.add_type(BtfType::Ptr(Ptr::new(ptr_name_offset, kernel_int_id)));
        add_var(&mut kernel_btf, "foo", kernel_ptr_id);

        let err = object
            .resolve_typed_externs(&ExternResolver::vmlinux_only(Some(&kernel_btf)))
            .unwrap_err();
        assert!(matches!(err, KsymsError::IncompatibleVariableType { name } if name == "foo"));
    }

    #[test]
    fn resolve_extern_function_incompatible_signature() {
        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_proto_id = add_func_proto(&mut local_btf, local_int_id, vec![]);
        let local_func_id = add_func(&mut local_btf, "bar", local_proto_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("bar".into(), ExternType::Ksym, local_func_id, false);
        ext.type_id = Some(local_proto_id);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut kernel_btf = Btf::new();
        let kernel_int_id = add_int(&mut kernel_btf, "int");
        let kernel_param = BtfParam {
            name_offset: kernel_btf.add_string("x"),
            btf_type: kernel_int_id,
        };
        let kernel_proto_id = add_func_proto(&mut kernel_btf, kernel_int_id, vec![kernel_param]);
        add_func(&mut kernel_btf, "bar", kernel_proto_id);

        let err = object
            .resolve_typed_externs(&ExternResolver::vmlinux_only(Some(&kernel_btf)))
            .unwrap_err();
        assert!(matches!(err, KsymsError::IncompatibleFunctionSignature { name } if name == "bar"));
    }

    #[test]
    fn resolve_typed_variable_from_module_btf() {
        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_var_id = add_var(&mut local_btf, "module_var", local_int_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("module_var".into(), ExternType::Ksym, local_var_id, false);
        ext.type_id = Some(local_int_id);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut vmlinux = Btf::new();
        let vmlinux_int_id = add_int(&mut vmlinux, "int");

        let mut module_btf = Btf::new();
        let module_var_id = add_split_var(&vmlinux, &mut module_btf, "module_var", vmlinux_int_id);

        let modules = [ExternResolverModule {
            btf: &module_btf,
            fd_idx: 7,
            btf_obj_fd: 70,
        }];
        let resolver = ExternResolver {
            vmlinux: Some(&vmlinux),
            modules: &modules,
        };

        object.resolve_typed_externs(&resolver).unwrap();

        let ext = &object.btf.as_ref().unwrap().externs.externs["module_var"];
        assert_eq!(
            ext.resolved,
            Some(ResolvedKsymTarget::ModuleBtf {
                type_id: module_var_id,
                btf_fd_idx: 7,
                btf_obj_fd: 70,
            })
        );
        assert!(object.has_resolved_module_btf_targets());
    }

    #[test]
    fn resolve_typed_function_from_module_btf() {
        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_proto_id = add_func_proto(&mut local_btf, local_int_id, vec![]);
        let local_func_id = add_func(&mut local_btf, "module_func", local_proto_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("module_func".into(), ExternType::Ksym, local_func_id, false);
        ext.type_id = Some(local_proto_id);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut vmlinux = Btf::new();
        let vmlinux_int_id = add_int(&mut vmlinux, "int");

        let mut module_btf = Btf::new();
        let module_proto_id = add_func_proto(&mut module_btf, vmlinux_int_id, vec![]);
        let module_proto_id = vmlinux.type_count() + module_proto_id - 1;
        let module_func_id =
            add_split_func(&vmlinux, &mut module_btf, "module_func", module_proto_id);

        let modules = [ExternResolverModule {
            btf: &module_btf,
            fd_idx: 2,
            btf_obj_fd: 20,
        }];
        let resolver = ExternResolver {
            vmlinux: Some(&vmlinux),
            modules: &modules,
        };

        object.resolve_typed_externs(&resolver).unwrap();

        let ext = &object.btf.as_ref().unwrap().externs.externs["module_func"];
        assert_eq!(
            ext.resolved,
            Some(ResolvedKsymTarget::ModuleBtf {
                type_id: module_func_id,
                btf_fd_idx: 2,
                btf_obj_fd: 20,
            })
        );
        assert!(object.has_resolved_module_btf_targets());
    }

    #[test]
    fn resolve_externs_discovers_module_btf_lazily() {
        let resolved = object_with_externs(ExternCollection::new())
            .resolve_externs(None, || -> Result<NoModuleBtfProvider, Infallible> {
                panic!("module BTF discovery should not run without externs")
            })
            .unwrap();
        assert!(resolved.into_modules().is_none());

        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_var_id = add_var(&mut local_btf, "present", local_int_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("present".into(), ExternType::Ksym, local_var_id, false);
        ext.type_id = Some(local_int_id);
        externs.insert(ext.name.clone(), ext);
        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut vmlinux = Btf::new();
        let vmlinux_int_id = add_int(&mut vmlinux, "int");
        add_var(&mut vmlinux, "present", vmlinux_int_id);

        let resolved = object
            .resolve_externs(
                Some(&vmlinux),
                || -> Result<NoModuleBtfProvider, Infallible> {
                    panic!("module BTF discovery should not run when vmlinux resolves all externs")
                },
            )
            .unwrap();
        assert!(resolved.into_modules().is_none());

        let mut local_btf = Btf::new();
        let local_int_id = add_int(&mut local_btf, "int");
        let local_var_id = add_var(&mut local_btf, "module_var", local_int_id);

        let mut externs = ExternCollection::new();
        let mut ext = ExternDesc::new("module_var".into(), ExternType::Ksym, local_var_id, false);
        ext.type_id = Some(local_int_id);
        externs.insert(ext.name.clone(), ext);
        let mut object = object_with_btf_and_externs(local_btf, externs);

        let mut vmlinux = Btf::new();
        let vmlinux_int_id = add_int(&mut vmlinux, "int");
        let mut module_btf = Btf::new();
        add_split_var(&vmlinux, &mut module_btf, "module_var", vmlinux_int_id);

        let resolved = object
            .resolve_externs(Some(&vmlinux), || {
                Ok(TestModuleBtfProvider {
                    btf: &module_btf,
                    fd_idx: 7,
                    btf_obj_fd: 70,
                })
            })
            .unwrap();
        assert!(resolved.into_modules().is_some());
    }

    mod kallsyms_tests {
        use super::*;

        impl Object {
            /// Resolves typeless ksym addresses by matching symbol names against parsed kallsyms lines.
            fn resolve_kallsyms_from_lines<I, S, U>(
                &mut self,
                lines: I,
                unresolved: &[U],
            ) -> Result<(), KsymsError>
            where
                I: IntoIterator<Item = S>,
                S: AsRef<str>,
                U: AsRef<str>,
            {
                let text = lines
                    .into_iter()
                    .map(|line| String::from(line.as_ref()))
                    .collect::<Vec<_>>()
                    .join("\n");
                self.resolve_kallsyms_from_reader(std::io::Cursor::new(text), unresolved)
            }

            fn finalize_weak_typeless_ksyms_for_test(&mut self) {
                if let Some(obj_btf) = self.btf.as_mut() {
                    for ext in obj_btf.externs.externs.values_mut() {
                        if ext.extern_type == ExternType::Ksym
                            && ext.resolved.is_none()
                            && ext.is_weak
                        {
                            ext.resolved = Some(ResolvedKsymTarget::WeakMissing);
                        }
                    }
                }
            }
        }

        #[test]
        fn unresolved_typeless_ksym_vars_excludes_typed_vars() {
            let mut externs = ExternCollection::new();

            let mut typed = ExternDesc::new("typed".into(), ExternType::Ksym, 1, true);
            typed.type_id = Some(42);
            externs.insert(typed.name.clone(), typed);

            let typeless = ExternDesc::new("typeless".into(), ExternType::Ksym, 2, true);
            externs.insert(typeless.name.clone(), typeless);

            let object = object_with_externs(externs);

            assert_eq!(
                object.unresolved_typeless_ksym_vars(),
                vec![String::from("typeless")]
            );
        }

        #[test]
        fn resolve_kallsyms_from_lines_ambiguous_address() {
            let mut externs = ExternCollection::new();
            let ext = ExternDesc::new("init_task".into(), ExternType::Ksym, 1, false);
            externs.insert(ext.name.clone(), ext);

            let mut object = object_with_externs(externs);
            let lines = vec![
                String::from("1000 D init_task"),
                String::from("3000 D other"),
                String::from("2000 D init_task"),
            ];
            let unresolved = vec![String::from("init_task")];

            let err = object
                .resolve_kallsyms_from_lines(&lines, &unresolved)
                .unwrap_err();

            match err {
                KsymsError::AmbiguousResolution {
                    name,
                    first_addr,
                    second_addr,
                } => {
                    assert_eq!(name, "init_task");
                    assert_eq!(first_addr, 0x1000);
                    assert_eq!(second_addr, 0x2000);
                }
                other => panic!("expected AmbiguousResolution, got {other:?}"),
            }
        }

        #[test]
        fn resolve_kallsyms_from_lines_bad_address() {
            let mut externs = ExternCollection::new();
            let ext = ExternDesc::new("init_task".into(), ExternType::Ksym, 1, false);
            externs.insert(ext.name.clone(), ext);

            let mut object = object_with_externs(externs);
            let lines = vec![String::from("not_hex D init_task")];
            let unresolved = vec![String::from("init_task")];

            let err = object
                .resolve_kallsyms_from_lines(&lines, &unresolved)
                .unwrap_err();

            match err {
                KsymsError::KallsymsParseError(msg) => {
                    assert!(msg.contains("invalid address"), "unexpected error: {msg}");
                }
                other => panic!("expected KallsymsParseError, got {other:?}"),
            }
        }

        #[test]
        fn resolve_kallsyms_from_lines_rejects_masked_strong_address() {
            let mut externs = ExternCollection::new();
            let ext = ExternDesc::new("init_task".into(), ExternType::Ksym, 1, false);
            externs.insert(ext.name.clone(), ext);

            let mut object = object_with_externs(externs);
            let lines = vec![String::from("0000000000000000 D init_task")];
            let unresolved = vec![String::from("init_task")];

            let err = object
                .resolve_kallsyms_from_lines(&lines, &unresolved)
                .unwrap_err();

            assert!(matches!(
                err,
                KsymsError::VariableNotFound { name } if name == "init_task"
            ));
        }

        #[test]
        fn resolve_typeless_externs_sets_weak_missing_target() {
            let mut externs = ExternCollection::new();
            let ext = ExternDesc::new("missing".into(), ExternType::Ksym, 1, true);
            externs.insert(ext.name.clone(), ext);

            let mut object = object_with_externs(externs);

            object.finalize_weak_typeless_ksyms_for_test();

            let ext = &object.btf.as_ref().unwrap().externs.externs["missing"];
            assert_eq!(ext.resolved, Some(ResolvedKsymTarget::WeakMissing));
        }
    }
}
