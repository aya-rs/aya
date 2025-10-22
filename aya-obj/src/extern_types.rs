//! Extern type resolution and relocation.
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
    /// Resolves extern kernel symbols through kernel `BTF` and `kallsyms`.
    pub fn resolve_externs(&mut self, kernel_btf: Option<&Btf>) -> Result<(), KsymsError> {
        if self.btf.is_none() {
            return Ok(());
        }

        if let Some(kernel_btf) = kernel_btf {
            self.resolve_typed_externs(kernel_btf)?;
        } else if self.has_typed_ksyms() {
            return Err(KsymsError::TypedKsymRequiresKernelBtf);
        }

        #[cfg(feature = "std")]
        self.resolve_typeless_externs()?;

        Ok(())
    }

    /// Returns whether the object contains typed ksyms that require kernel `BTF`.
    pub(crate) fn has_typed_ksyms(&self) -> bool {
        self.btf.as_ref().is_some_and(|btf| {
            btf.externs
                .iter()
                .any(|(_, ext)| ext.extern_type == ExternType::Ksym && ext.type_id.is_some())
        })
    }

    /// Resolves typed externs through kernel `BTF`.
    pub(crate) fn resolve_typed_externs(&mut self, kernel_btf: &Btf) -> Result<(), KsymsError> {
        let mut resolutions = Vec::new();
        {
            let obj_btf = self
                .btf
                .as_ref()
                .expect("resolve_typed_externs called without local BTF");

            for (name, extern_desc) in obj_btf.externs.iter() {
                if extern_desc.type_id.is_none() {
                    continue;
                }

                let btf_type = obj_btf.type_by_id(extern_desc.btf_id)?;
                let kernel_btf_id = match btf_type {
                    BtfType::Func(_) => {
                        self.resolve_extern_function(name, extern_desc, kernel_btf)?
                    }
                    BtfType::Var(_) => {
                        self.resolve_extern_variable(name, extern_desc, kernel_btf)?
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

        let obj_mut = self
            .btf
            .as_mut()
            .expect("resolve_typed_externs called without local BTF");

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
    pub(crate) fn resolve_typeless_externs(&mut self) -> Result<(), KsymsError> {
        use std::fs::File;
        let unresolved: Vec<String> = self.unresolved_typeless_ksym_vars();

        if !unresolved.is_empty() {
            let file = File::open("/proc/kallsyms")?;
            let reader = std::io::BufReader::new(file);
            self.resolve_kallsyms_from_reader(reader, &unresolved)?;
        }

        // Finalize unresolved weak externs by setting ksym_addr = 0
        // This allows pointer checks like `if (weak_func)` to evaluate to false
        self.finalize_weak_externs();

        Ok(())
    }

    /// Sets `ksym_addr = Some(0)` for all unresolved weak ksym externs.
    #[cfg(feature = "std")]
    fn finalize_weak_externs(&mut self) {
        let Some(obj_btf) = self.btf.as_mut() else {
            return;
        };

        for ext in obj_btf.externs.externs.values_mut() {
            if ext.extern_type == ExternType::Ksym && !ext.is_resolved && ext.is_weak {
                ext.ksym_addr = Some(0);
            }
        }
    }

    /// Resolves typeless ksym addresses by matching symbol names against parsed kallsyms lines.
    #[cfg(feature = "std")]
    fn resolve_kallsyms_from_reader<R: std::io::BufRead>(
        &mut self,
        reader: R,
        unresolved: &[String],
    ) -> Result<(), KsymsError> {
        let obj_btf = self
            .btf
            .as_mut()
            .expect("resolve_kallsyms_from_lines called without local BTF");

        for line in reader.lines() {
            let line = line?;
            let mut parts = line.split_whitespace();
            let (Some(addr_str), Some(_sym_type), Some(sym_name)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };

            if !unresolved.iter().any(|s| s.as_str() == sym_name) {
                continue;
            }

            let addr = u64::from_str_radix(addr_str, 16).map_err(|_err| {
                KsymsError::KallsymsParseError(alloc::format!("invalid address: {addr_str}"))
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
                    continue;
                }

                ext.ksym_addr = Some(addr);
                ext.is_resolved = true;
            }
        }

        // Check for unresolved non-weak typeless ksyms.
        // Typed ksyms reach this function only as the kallsyms fallback path; failures
        // to resolve them via BTF surface earlier as VariableNotFound/FunctionNotFound.
        for (name, ext) in &obj_btf.externs.externs {
            if ext.extern_type == ExternType::Ksym && !ext.is_resolved && !ext.is_weak {
                return Err(KsymsError::VariableNotFound { name: name.clone() });
            }
        }

        Ok(())
    }

    /// Resolves typeless ksym addresses by matching symbol names against parsed kallsyms lines.
    #[cfg(all(feature = "std", test))]
    fn resolve_kallsyms_from_lines<I, S>(
        &mut self,
        lines: I,
        unresolved: &[String],
    ) -> Result<(), KsymsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let rendered = lines
            .into_iter()
            .map(|line| Ok::<String, std::io::Error>(String::from(line.as_ref())));
        self.resolve_kallsyms_from_reader(
            std::io::Cursor::new(rendered.collect::<Result<Vec<_>, _>>()?.join("\n")),
            unresolved,
        )
    }

    /// Returns unresolved typeless ksym variables from [`ExternCollection`].
    #[cfg(feature = "std")]
    fn unresolved_typeless_ksym_vars(&self) -> Vec<String> {
        let Some(obj_btf) = self.btf.as_ref() else {
            return Vec::new();
        };

        obj_btf
            .externs
            .externs
            .iter()
            .filter(|(_, ext)| {
                ext.extern_type == ExternType::Ksym && !ext.is_resolved && ext.type_id.is_none()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Resolves a single extern function. Returns BTF ID if found, otherwise
    /// returns `None`.
    fn resolve_extern_function(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        kernel_btf: &Btf,
    ) -> Result<Option<u32>, KsymsError> {
        let lookup_name = extern_desc.essential_name.as_deref().unwrap_or(name);
        let Ok(kernel_func_id) = kernel_btf.id_by_type_name_kind(lookup_name, BtfKind::Func) else {
            if extern_desc.is_weak {
                return Ok(None);
            }

            return Err(KsymsError::FunctionNotFound {
                name: lookup_name.to_string(),
            });
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

        let obj_btf = self
            .btf
            .as_ref()
            .expect("resolve_extern_function called without local BTF");
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
    fn resolve_extern_variable(
        &self,
        name: &str,
        extern_desc: &ExternDesc,
        kernel_btf: &Btf,
    ) -> Result<Option<u32>, KsymsError> {
        let Ok(kernel_var_id) = kernel_btf.id_by_type_name_kind(name, BtfKind::Var) else {
            if extern_desc.is_weak {
                return Ok(None);
            }
            return Err(KsymsError::VariableNotFound {
                name: name.to_string(),
            });
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

        let obj_btf = self
            .btf
            .as_ref()
            .expect("resolve_extern_variable called without local BTF");
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

/// Errors that can occur during ksyms operations.
#[derive(Debug, thiserror::Error)]
pub enum KsymsError {
    /// A typed ksym was encountered but kernel BTF is unavailable.
    #[error("typed ksyms require kernel BTF for resolution")]
    TypedKsymRequiresKernelBtf,

    /// A non-weak typed extern variable was not found in kernel BTF.
    #[error("kernel variable '{name}' not found in kernel BTF")]
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
    #[cfg(feature = "std")]
    #[error("failed to read /proc/kallsyms: {0}")]
    KallsymsReadError(#[from] std::io::Error),

    /// Failed to parse kallsyms data.
    #[error("failed to parse kallsyms: {0}")]
    KallsymsParseError(String),

    /// Function not found when trying to patch its instructions.
    #[error("function '{name}' not found")]
    FunctionNotFound {
        /// The function name.
        name: String,
    },
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

    /// Whether extern has been resolved.
    pub(crate) is_resolved: bool,

    /// For ksym: kernel BTF ID (after resolution).
    pub(crate) kernel_btf_id: Option<u32>,

    /// For ksym variables: resolved kernel address.
    pub(crate) ksym_addr: Option<u64>,

    /// For ksym: resolved type ID (after skipping modifiers/typedefs).
    pub(crate) type_id: Option<u32>,

    /// For names with flavors: stripped essential name.
    pub(crate) essential_name: Option<String>,
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
            is_resolved: false,
            kernel_btf_id: None,
            ksym_addr: None,
            type_id: None,
            essential_name,
        }
    }
}

/// Collection of extern symbols.
#[derive(Debug, Default, Clone)]
pub(crate) struct ExternCollection {
    /// Map of extern descriptors by name.
    pub(crate) externs: HashMap<String, ExternDesc>,

    /// BTF ID of the placeholder ksym variable (if created).
    pub(crate) dummy_ksym_var_id: Option<u32>,

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

    pub(crate) const fn set_dummy_var_id(&mut self, id: u32) {
        self.dummy_ksym_var_id = Some(id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.externs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, ffi::CString, string::ToString as _, vec, vec::Vec};

    use object::Endianness;

    use super::{ExternCollection, ExternDesc, ExternType, KsymsError};
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

    #[test]
    fn resolve_externs_requires_kernel_btf_for_typed_ksyms() {
        let mut externs = ExternCollection::new();

        let mut typed = ExternDesc::new("typed".into(), ExternType::Ksym, 1, false);
        typed.type_id = Some(42);
        externs.insert(typed.name.clone(), typed);

        let mut object = object_with_externs(externs);

        let err = object.resolve_externs(None).unwrap_err();
        assert!(matches!(err, KsymsError::TypedKsymRequiresKernelBtf));
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

        let err = object.resolve_typed_externs(&kernel_btf).unwrap_err();
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

        let err = object.resolve_typed_externs(&kernel_btf).unwrap_err();
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

        let err = object.resolve_typed_externs(&kernel_btf).unwrap_err();
        assert!(matches!(err, KsymsError::IncompatibleFunctionSignature { name } if name == "bar"));
    }

    #[cfg(feature = "std")]
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
            vec!["typeless".to_string()]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn resolve_kallsyms_from_lines_ambiguous_address() {
        let mut externs = ExternCollection::new();
        let ext = ExternDesc::new("init_task".into(), ExternType::Ksym, 1, false);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_externs(externs);
        let lines = vec![
            "1000 D init_task".to_string(),
            "3000 D other".to_string(),
            "2000 D init_task".to_string(),
        ];
        let unresolved = vec!["init_task".to_string()];

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

    #[cfg(feature = "std")]
    #[test]
    fn resolve_kallsyms_from_lines_bad_address() {
        let mut externs = ExternCollection::new();
        let ext = ExternDesc::new("init_task".into(), ExternType::Ksym, 1, false);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_externs(externs);
        let lines = vec!["not_hex D init_task".to_string()];
        let unresolved = vec!["init_task".to_string()];

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

    #[cfg(feature = "std")]
    #[test]
    fn finalize_weak_externs_sets_zero() {
        let mut externs = ExternCollection::new();
        let ext = ExternDesc::new("missing".into(), ExternType::Ksym, 1, true);
        externs.insert(ext.name.clone(), ext);

        let mut object = object_with_externs(externs);

        object.finalize_weak_externs();

        let ext = &object.btf.as_ref().unwrap().externs.externs["missing"];
        assert_eq!(ext.ksym_addr, Some(0));
        assert!(!ext.is_resolved);
    }
}
