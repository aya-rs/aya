//! Extern type resolution, relocation
use alloc::{
    string::{String, ToString as _},
    vec::Vec,
};

use crate::{
    Object,
    btf::{Btf, BtfError, BtfKind, BtfType},
    util::HashMap,
};

impl Object {
    /// Resolves typed externs through kernel `BTF`.
    pub fn resolve_typed_externs(
        &mut self,
        kernel_btf: &mut Btf,
    ) -> core::result::Result<(), KsymsError> {
        let mut resolutions = Vec::new();
        {
            let obj_btf = self.btf.as_ref().ok_or(KsymsError::NoBtf)?;

            for (name, extern_desc) in obj_btf.externs.iter() {
                if extern_desc.type_id.is_none() {
                    continue;
                }

                let btf_type = obj_btf.type_by_id(extern_desc.btf_id)?;
                let kernel_btf_id = match btf_type {
                    BtfType::Func(_) => {
                        self.resolve_extern_function_internal(name, extern_desc, kernel_btf)?
                    }
                    BtfType::Var(_) => {
                        self.resolve_extern_variable_internal(name, extern_desc, kernel_btf)?
                    }
                    _ => {
                        return Err(KsymsError::InvalidExternType { name: name.clone() });
                    }
                };

                if let Some(btf_id) = kernel_btf_id {
                    resolutions.push((name.clone(), btf_id));
                }
            }
        }

        let obj_mut = self.btf.as_mut().ok_or(KsymsError::NoBtf)?;

        for (name, kernel_btf_id) in resolutions {
            if let Some(ext) = obj_mut.externs.get_mut(&name) {
                ext.kernel_btf_id = Some(kernel_btf_id);
                ext.is_resolved = true;
            }
        }

        Ok(())
    }

    /// Resolves typeless extern vars found in `.ksyms` section through `kallsyms`.
    #[cfg(feature = "std")]
    pub fn resolve_typeless_externs(&mut self) -> core::result::Result<(), KsymsError> {
        use std::{fs::File, io::BufRead as _};
        let unresolved: Vec<String> = self.get_unresolved_ksym_vars();

        if !unresolved.is_empty() {
            let file = File::open("/proc/kallsyms")?;

            let reader = std::io::BufReader::new(file);
            let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

            self.resolve_kallsyms_from_lines(&lines, &unresolved)?;
        }

        // Finalize unresolved weak externs by setting ksym_addr = 0
        // This allows pointer checks like `if (weak_func)` to evaluate to false
        self.finalize_weak_externs()?;

        Ok(())
    }

    /// Sets `ksym_addr = Some(0)` for all unresolved weak ksym externs.
    fn finalize_weak_externs(&mut self) -> core::result::Result<(), KsymsError> {
        let Some(obj_btf) = self.btf.as_mut() else {
            return Ok(());
        };

        for (_, ext) in obj_btf.externs.externs.iter_mut() {
            if ext.extern_type == ExternType::Ksym && !ext.is_resolved && ext.is_weak {
                ext.ksym_addr = Some(0);
            }
        }

        Ok(())
    }

    fn resolve_kallsyms_from_lines(
        &mut self,
        lines: &[String],
        unresolved: &[String],
    ) -> core::result::Result<(), KsymsError> {
        let Some(obj_btf) = self.btf.as_mut() else {
            return Err(KsymsError::NoBtf);
        };

        let mut resolved_count = 0;

        for line in lines {
            // Parse: <addr> <type> <name> [<module>]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let addr_str = parts[0];
            let sym_name = parts[2];

            if !unresolved.iter().any(|s| s.as_str() == sym_name) {
                continue;
            }

            let addr = u64::from_str_radix(addr_str, 16).map_err(|_| {
                KsymsError::KallsymsParseError(alloc::format!("invalid address: {}", addr_str))
            })?;

            if let Some(ext) = obj_btf.externs.get_mut(sym_name) {
                if ext.is_resolved {
                    if let Some(existing_addr) = ext.ksym_addr {
                        if existing_addr != addr {
                            return Err(KsymsError::AmbiguousResolution {
                                name: sym_name.to_string(),
                                first_addr: existing_addr,
                                second_addr: addr,
                            });
                        }
                    }
                }

                ext.ksym_addr = Some(addr);
                ext.is_resolved = true;
                resolved_count += 1;
            }

            if resolved_count == unresolved.len() {
                break;
            }
        }

        // Check for unresolved non-weak symbols
        for (name, ext) in obj_btf.externs.externs.iter() {
            if ext.extern_type == ExternType::Ksym && !ext.is_resolved && !ext.is_weak {
                return Err(KsymsError::UnresolvedExtern { name: name.clone() });
            }
        }

        Ok(())
    }

    /// Gets unresolved ksyms variables from [`ExternCollection`].
    fn get_unresolved_ksym_vars(&self) -> Vec<String> {
        let Some(obj_btf) = self.btf.as_ref() else {
            return Vec::new();
        };

        obj_btf
            .externs
            .externs
            .iter()
            .filter(|(_, ext)| {
                ext.extern_type == ExternType::Ksym && !ext.is_func && !ext.is_resolved
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Resolves a single extern function. Returns BTF ID if found, otherwise
    /// returns `None`.
    fn resolve_extern_function_internal(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        kernel_btf: &Btf,
    ) -> core::result::Result<Option<u32>, KsymsError> {
        let lookup_name = extern_desc.essent_name.as_deref().unwrap_or(name);
        let kernel_func_id = match kernel_btf.id_by_type_name_kind(lookup_name, BtfKind::Func) {
            Ok(id) => id,
            Err(_) => {
                if extern_desc.is_weak {
                    return Ok(None);
                }

                return Err(KsymsError::FunctionNotFound {
                    name: lookup_name.to_string(),
                });
            }
        };

        let kernel_func_type = kernel_btf.type_by_id(kernel_func_id)?;
        let kernel_proto_id = match kernel_func_type {
            BtfType::Func(func) => func.btf_type,
            _ => {
                return Err(KsymsError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: kernel_func_id,
                }));
            }
        };

        let local_proto_id =
            extern_desc
                .type_id
                .ok_or(KsymsError::BtfError(BtfError::UnknownBtfType {
                    type_id: 0,
                }))?;

        let obj_btf = self.btf.as_ref().ok_or(KsymsError::NoBtf)?;
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_proto_id, kernel_btf, kernel_proto_id)?;

        if !compatible {
            if extern_desc.is_weak {
                return Ok(None);
            }
            return Err(KsymsError::IncompatibleFunctionSignature {
                name: lookup_name.to_string(),
            });
        }

        Ok(Some(kernel_func_id))
    }

    /// Resolves a single extern variable. Returns BTF ID if found, otherwise
    /// returns `None`.
    fn resolve_extern_variable_internal(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        kernel_btf: &Btf,
    ) -> core::result::Result<Option<u32>, KsymsError> {
        let kernel_var_id = match kernel_btf.id_by_type_name_kind(name, BtfKind::Var) {
            Ok(id) => id,
            Err(_) => {
                if extern_desc.is_weak {
                    return Ok(None);
                }
                return Err(KsymsError::VariableNotFound {
                    name: name.to_string(),
                });
            }
        };

        let kernel_var_type = kernel_btf.type_by_id(kernel_var_id)?;
        let kernel_type_id = match kernel_var_type {
            BtfType::Var(var) => var.btf_type,
            _ => {
                return Err(KsymsError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: kernel_var_id,
                }));
            }
        };

        let local_type_id =
            extern_desc
                .type_id
                .ok_or(KsymsError::BtfError(BtfError::UnknownBtfType {
                    type_id: 0,
                }))?;

        let obj_btf = self.btf.as_ref().ok_or(KsymsError::NoBtf)?;
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_type_id, kernel_btf, kernel_type_id)?;

        if !compatible {
            return Err(KsymsError::IncompatibleVariableType {
                name: name.to_string(),
            });
        }

        Ok(Some(kernel_var_id))
    }
}

/// Errors that can occur during `ksyms`` operation fails
#[derive(Debug, thiserror::Error)]
pub enum KsymsError {
    /// A non-weak extern variable was not found in kernel BTF
    #[error("kernel variable '{name}' not found in kernel BTF or kallsyms")]
    VariableNotFound {
        /// The name of the variable that was not found
        name: String,
    },

    /// The extern function's signature is incompatible with the kernel function
    #[error("kernel function '{name}' has incompatible signature")]
    IncompatibleFunctionSignature {
        /// The name of the function with incompatible signature
        name: String,
    },

    /// The extern variable's type is incompatible with the kernel variable
    #[error("kernel variable '{name}' has incompatible type")]
    IncompatibleVariableType {
        /// The name of the variable with incompatible type
        name: String,
    },

    /// The extern symbol has an invalid BTF type (neither Func nor Var)
    #[error("extern '{name}' has invalid BTF type (neither Func nor Var)")]
    InvalidExternType {
        /// The name of the extern with invalid type
        name: String,
    },

    /// An error occurred while working with BTF data
    #[error("BTF error: {0}")]
    BtfError(#[from] BtfError),

    /// The object file has no BTF information
    #[error("object has no BTF information")]
    NoBtf,

    /// Resolved Extern's kallsyms address does not match agains the loaded kallsyms
    #[error("extern (ksym) '{name}': resolution is ambiguous: {first_addr:#x} or {second_addr:#x}")]
    AmbiguousResolution {
        /// The name of the symbol with ambiguous resolution
        name: String,
        /// The first address found
        first_addr: u64,
        /// The second (conflicting) address found  
        second_addr: u64,
    },

    /// Could not read kallsyms entries
    #[cfg(feature = "std")]
    #[error("failed to read /proc/kallsyms: {0}")]
    KallsymsReadError(#[from] std::io::Error),

    /// Failed to parse kallsyms data
    #[error("failed to parse kallsyms: {0}")]
    KallsymsParseError(String),

    /// An unresolved non-weak extern was encountered during patching
    #[error(
        "extern symbol '{name}' is not resolved (non-weak externs must be resolved before patching)"
    )]
    UnresolvedExtern {
        /// The name of the unresolved extern
        name: String,
    },

    /// Function not found when trying to patch its instructions
    #[error("function '{name}' not found")]
    FunctionNotFound {
        /// The section index
        name: String,
    },
}

/// Type of extern symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternType {
    /// Kernel configuration variable (.kconfig section)
    Kconfig,
    /// Kernel symbol - variable or function (.ksyms section)
    Ksym,
}

/// Descriptor for an extern symbol
#[derive(Debug, Clone)]
pub(crate) struct ExternDesc {
    /// Symbol name
    pub(crate) name: String,

    /// Type of extern (Kconfig or Ksym)
    pub(crate) extern_type: ExternType,

    /// BTF type ID in local (program) BTF
    pub(crate) btf_id: u32,

    /// Whether this is a weak symbol
    pub(crate) is_weak: bool,

    /// Whether this is a function (vs variable)
    pub(crate) is_func: bool,

    /// Whether extern has been resolved
    pub(crate) is_resolved: bool,

    /// For ksym: kernel BTF ID (after resolution)
    pub(crate) kernel_btf_id: Option<u32>,

    /// For ksym variables: resolved kernel address
    pub(crate) ksym_addr: Option<u64>,

    /// For ksym: resolved type ID (after skipping modifiers/typedefs)
    pub(crate) type_id: Option<u32>,

    /// For names with flavors: stripped essential name
    pub(crate) essent_name: Option<String>,
}

/// Given 'some_struct_name___with_flavor' return the length of a name prefix
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
    pub(crate) fn new(
        name: String,
        extern_type: ExternType,
        btf_id: u32,
        is_weak: bool,
        is_func: bool,
    ) -> Self {
        let essent_len = essential_name_len(&name);
        let essent_name = if essent_len != name.len() {
            Some(name[..essent_len].to_string())
        } else {
            None
        };

        Self {
            name: name.clone(),
            extern_type,
            btf_id,
            is_weak,
            is_func,
            is_resolved: false,
            kernel_btf_id: None,
            ksym_addr: None,
            type_id: None,
            essent_name,
        }
    }
}

/// Collection of extern symbols
#[derive(Debug, Default, Clone)]
pub struct ExternCollection {
    /// Map of extern descriptors by name
    pub(crate) externs: HashMap<String, ExternDesc>,

    /// BTF ID of dummy ksym variable (if created)
    pub(crate) dummy_ksym_var_id: Option<u32>,

    /// Index ID of `.ksyms`datasec entry in BTF types.
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

    pub(crate) fn set_dummy_var_id(&mut self, id: u32) {
        self.dummy_ksym_var_id = Some(id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.externs.is_empty()
    }
}
