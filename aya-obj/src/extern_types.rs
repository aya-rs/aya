use std::{
    collections::HashMap,
    format,
    string::{String, ToString as _},
    vec::Vec,
};

use crate::{
    Object,
    btf::{Btf, BtfError, BtfKind, BtfType},
};

impl Object {
    /// Resolve all extern kernel symbols (functions and variables) against kernel BTF
    ///
    /// This is the main entry point for resolving extern symbols declared in .ksyms section.
    /// It dispatches to separate handlers for functions and variables.
    ///
    /// # Arguments
    ///
    /// * `kernel_btf` - Kernel BTF loaded from `/sys/kernel/btf/vmlinux`
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all non-weak extern symbols were successfully resolved.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aya_obj::{Object, btf::Btf};
    ///
    /// let mut obj = Object::parse(&data)?;
    /// let kernel_btf = Btf::from_sys_fs()?;
    ///
    /// // Resolve all extern kernel symbols (functions and variables)
    /// obj.resolve_extern_ksyms(&kernel_btf)?;
    /// ```
    pub fn resolve_extern_ksyms(
        &mut self,
        kernel_btf: &Btf,
    ) -> std::result::Result<(), KsymResolveError> {
        // Check if we have any externs to resolve
        if self.externs.externs.is_empty() {
            return Ok(());
        }

        let obj_btf = self.btf.as_ref().ok_or(KsymResolveError::NoBtf)?;

        // Dispatch based on extern type (like libbpf does at line 8232-8236)
        let mut resolutions = Vec::new();

        for (name, extern_desc) in self.externs.iter() {
            // Skip if extern has no type_id (typeless ksyms - not supported yet)
            if extern_desc.type_id.is_none() {
                continue;
            }

            // Dispatch to appropriate resolver
            let btf_type = obj_btf.type_by_id(extern_desc.btf_id)?;
            let kernel_btf_id = match btf_type {
                BtfType::Func(_) => {
                    if extern_desc.is_weak {
                        return Err(KsymResolveError::WeakExternFunctionUnsupported {
                            name: name.to_string(),
                        });
                    }
                    // Resolve function
                    self.resolve_extern_function_internal(name, extern_desc, obj_btf, kernel_btf)?
                }
                BtfType::Var(_) => {
                    // Resolve variable
                    self.resolve_extern_variable_internal(name, extern_desc, obj_btf, kernel_btf)?
                }
                _ => {
                    return Err(KsymResolveError::InvalidExternType { name: name.clone() });
                }
            };

            // Collect resolution if not None (None means weak extern not found)
            if let Some(btf_id) = kernel_btf_id {
                resolutions.push((name.clone(), btf_id));
            }
        }

        // Apply all resolutions
        for (name, kernel_btf_id) in resolutions {
            if let Some(ext) = self.externs.get_mut(&name) {
                ext.kernel_btf_id = Some(kernel_btf_id);
                ext.is_resolved = true;
            }
        }

        self.resolve_kallsyms()?;

        Ok(())
    }

    fn resolve_kallsyms(&mut self) -> std::result::Result<(), KsymResolveError> {
        use std::{
            fs::File,
            io::{BufRead as _, BufReader},
        };

        // Find all unresolved variable externs
        let unresolved: Vec<String> = self
            .externs
            .externs
            .iter()
            .filter(|(_, ext)| {
                ext.extern_type == ExternType::Ksym && !ext.is_func && !ext.is_resolved
            })
            .map(|(name, _)| name.clone())
            .collect();

        if unresolved.is_empty() {
            return Ok(());
        }

        // Read kallsyms
        let file =
            File::open("/proc/kallsyms").map_err(|e| KsymResolveError::KallsymsReadError {
                error: e.to_string(),
            })?;

        let reader = BufReader::new(file);
        let mut resolved_count = 0;

        for line in reader.lines() {
            let line = line.map_err(|e| KsymResolveError::KallsymsReadError {
                error: e.to_string(),
            })?;

            // Parse: <addr> <type> <name> [<module>]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let addr_str = parts[0];
            let sym_name = parts[2];

            // Check if this symbol is one we need
            if !unresolved.contains(&sym_name.to_string()) {
                continue;
            }

            // Parse address
            let addr = u64::from_str_radix(addr_str, 16).map_err(|_| {
                KsymResolveError::KallsymsReadError {
                    error: format!("invalid address: {}", addr_str),
                }
            })?;

            // Update extern descriptor
            if let Some(ext) = self.externs.get_mut(sym_name) {
                ext.ksym_addr = Some(addr);
                ext.is_resolved = true;
                resolved_count += 1;
            }

            // Early exit if we've resolved everything
            if resolved_count == unresolved.len() {
                break;
            }
        }

        // Check for unresolved non-weak symbols
        for (name, ext) in self.externs.externs.iter() {
            if !ext.is_resolved && !ext.is_weak {
                return Err(KsymResolveError::VariableNotFound { name: name.clone() });
            }
        }

        Ok(())
    }

    fn resolve_extern_function_internal(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        obj_btf: &Btf,
        kernel_btf: &Btf,
    ) -> std::result::Result<Option<u32>, KsymResolveError> {
        // Look up function in kernel BTF
        let kernel_func_id = match kernel_btf.id_by_type_name_kind(name, BtfKind::Func) {
            Ok(id) => id,
            Err(_) => {
                return Err(KsymResolveError::FunctionNotFound {
                    name: name.to_string(),
                });
            }
        };

        // Get kernel function prototype
        let kernel_func_type = kernel_btf.type_by_id(kernel_func_id)?;
        let kernel_proto_id = match kernel_func_type {
            BtfType::Func(func) => func.btf_type,
            _ => {
                return Err(KsymResolveError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: kernel_func_id,
                }));
            }
        };

        // Get local function prototype
        let local_proto_id =
            extern_desc
                .type_id
                .ok_or(KsymResolveError::BtfError(BtfError::UnknownBtfType {
                    type_id: 0,
                }))?;

        // Check compatibility
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_proto_id, kernel_btf, kernel_proto_id)?;

        if !compatible {
            return Err(KsymResolveError::IncompatibleFunctionSignature {
                name: name.to_string(),
            });
        }

        Ok(Some(kernel_func_id))
    }

    /// Internal: Resolve a single extern variable
    /// Returns Some(btf_id) on success, None for weak externs not found
    fn resolve_extern_variable_internal(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        obj_btf: &Btf,
        kernel_btf: &Btf,
    ) -> std::result::Result<Option<u32>, KsymResolveError> {
        // Look up variable in kernel BTF
        let kernel_var_id = match kernel_btf.id_by_type_name_kind(name, BtfKind::Var) {
            Ok(id) => id,
            Err(_) => {
                return Err(KsymResolveError::VariableNotFound {
                    name: name.to_string(),
                });
            }
        };

        // Get the variable's type (VAR points to actual type)
        let kernel_var_type = kernel_btf.type_by_id(kernel_var_id)?;
        let kernel_type_id = match kernel_var_type {
            BtfType::Var(var) => var.btf_type,
            _ => {
                return Err(KsymResolveError::BtfError(BtfError::UnexpectedBtfType {
                    type_id: kernel_var_id,
                }));
            }
        };

        // Get local variable's type
        let local_type_id =
            extern_desc
                .type_id
                .ok_or(KsymResolveError::BtfError(BtfError::UnknownBtfType {
                    type_id: 0,
                }))?;

        // Check type compatibility
        let compatible =
            crate::btf::types_are_compatible(obj_btf, local_type_id, kernel_btf, kernel_type_id)?;

        if !compatible {
            return Err(KsymResolveError::IncompatibleVariableType {
                name: name.to_string(),
            });
        }

        Ok(Some(kernel_var_id))
    }
}
/// Errors that can occur during ksym resolution
#[derive(Debug, thiserror::Error)]
pub enum KsymResolveError {
    /// A non-weak extern function was not found in kernel BTF
    #[error("kernel function '{name}' not found in kernel BTF")]
    FunctionNotFound {
        /// The name of the function that was not found
        name: String,
    },

    /// A non-weak extern variable was not found in kernel BTF or kallsyms
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

    /// The object file has no BTF information
    #[error("Weak extern functions are not supported")]
    WeakExternFunctionUnsupported {
        /// The name of the extern with weak type
        name: String,
    },

    /// Could not read kallsyms entries
    #[error("failed to read /proc/kallsyms: {error}")]
    KallsymsReadError {
        /// Could not read kallsyms entries
        error: String,
    },
}

/// Errors that can occur during extern symbol instruction patching
#[derive(Debug, thiserror::Error)]
pub enum KsymPatchError {
    /// An extern symbol was not found during instruction patching
    #[error("extern symbol '{name}' not found in extern collection")]
    ExternNotFound {
        /// The name of the missing extern
        name: String,
    },

    /// An unresolved non-weak extern was encountered during patching
    #[error(
        "extern symbol '{name}' is not resolved (non-weak externs must be resolved before patching)"
    )]
    UnresolvedExtern {
        /// The name of the unresolved extern
        name: String,
    },

    /// Invalid instruction offset encountered
    #[error("invalid instruction offset {offset} in function '{function_name}'")]
    InvalidInstructionOffset {
        /// The invalid offset
        offset: usize,
        /// The function name
        function_name: String,
    },

    /// An extern function call instruction was expected but not found
    #[error("expected call instruction at offset {offset} in function '{function_name}'")]
    ExpectedCallInstruction {
        /// The instruction offset
        offset: usize,
        /// The function name
        function_name: String,
    },

    /// An ld_imm64 instruction was expected but not found
    #[error("expected ld_imm64 instruction at offset {offset} in function '{function_name}'")]
    ExpectedLdImm64Instruction {
        /// The instruction offset
        offset: usize,
        /// The function name
        function_name: String,
    },

    /// Program not found when trying to patch its instructions
    #[error("program '{name}' not found")]
    ProgramNotFound {
        /// The program name
        name: String,
    },

    /// Function not found when trying to patch its instructions
    #[error("function not found for program at section {section_index}, address {address:#x}")]
    FunctionNotFound {
        /// The section index
        section_index: usize,
        /// The address
        address: u64,
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
}

impl ExternDesc {
    pub(crate) fn new(
        name: String,
        extern_type: ExternType,
        btf_id: u32,
        is_weak: bool,
        is_func: bool,
    ) -> Self {
        Self {
            name,
            extern_type,
            btf_id,
            is_weak,
            is_func,
            is_resolved: false,
            kernel_btf_id: None,
            ksym_addr: None,
            type_id: None,
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
