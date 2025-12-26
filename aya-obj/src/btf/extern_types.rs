use alloc::vec::Vec;

use log::debug;

use crate::{
    KsymsError, Object,
    btf::{Btf, BtfError, BtfType, DataSec, DataSecEntry},
    extern_types::{ExternDesc, ExternType},
    relocation::Symbol,
    util::HashMap,
};
impl Btf {
    /// Creates a dummy global variable named "dummy_ksym" with a 4-byte int type for unresolved kernel symbols.
    pub(crate) fn create_dummy_ksym_var(&mut self) -> Result<u32, BtfError> {
        let int_type_id = {
            let mut found_id = None;
            for (idx, t) in self.types().enumerate() {
                if let BtfType::Int(int) = t {
                    if int.size == 4 {
                        found_id = Some((idx) as u32);
                        break;
                    }
                }
            }
            found_id
        };

        let int_type_id = if let Some(id) = int_type_id {
            id
        } else {
            let name_offset = self.add_string("int");
            self.add_type(BtfType::Int(crate::btf::Int::new(
                name_offset,
                4,
                crate::btf::IntEncoding::Signed,
                0,
            )))
        };

        debug!("Found/created int type_id: {}", int_type_id);
        if let Ok(BtfType::Int(int)) = self.type_by_id(int_type_id) {
            debug!(
                "Int type size: {}, encoding: {:?}",
                int.size,
                int.encoding()
            );
        }

        let name_offset = self.add_string("dummy_ksym");
        let dummy_var_id = self.add_type(BtfType::Var(crate::btf::Var::new(
            name_offset,
            int_type_id,
            crate::btf::VarLinkage::Global,
        )));

        debug!("Created dummy_var type_id: {}", dummy_var_id);
        if let Ok(BtfType::Var(var)) = self.type_by_id(dummy_var_id) {
            debug!("Dummy var points to type_id: {}", var.btf_type);
        }

        Ok(dummy_var_id)
    }

    /// Searches for the `.ksyms` datasec in BTF, returns it if found.
    fn find_ksyms_datasec(&self) -> Result<Option<(u32, DataSec)>, BtfError> {
        for (idx, btf_type) in self.types().enumerate() {
            if let BtfType::DataSec(datasec) = btf_type {
                let name = self.type_name(btf_type)?;
                if name == ".ksyms" {
                    return Ok(Some((idx as u32, datasec.clone())));
                }
            }
        }

        Ok(None)
    }

    /// Checks if datasec contains any functions.
    pub(crate) fn datasec_has_functions(&self, datasec: &DataSec) -> bool {
        datasec.entries.iter().any(|entry| {
            self.type_by_id(entry.btf_type)
                .map(|t| matches!(t, BtfType::Func(_)))
                .unwrap_or(false)
        })
    }

    /// Collects extern descriptors from datasec entries.
    pub(crate) fn collect_extern_entries(
        &self,
        datasec: &DataSec,
        symbol_table: &HashMap<usize, Symbol>,
    ) -> Result<Vec<ExternDesc>, BtfError> {
        let mut result = Vec::new();

        for entry in &datasec.entries {
            let Some(extern_desc) = self.process_datasec_entry(entry, symbol_table)? else {
                continue;
            };

            result.push(extern_desc);
        }

        Ok(result)
    }

    /// Processes a single datasec entry, returns [`ExternDesc`] if it's an extern.
    fn process_datasec_entry(
        &self,
        entry: &DataSecEntry,
        symbol_table: &HashMap<usize, Symbol>,
    ) -> Result<Option<ExternDesc>, BtfError> {
        let btf_type = self.type_by_id(entry.btf_type)?;

        let (name, is_func, var_btf_type) = match btf_type {
            BtfType::Func(func) => {
                let name = self.string_at(func.name_offset)?.into_owned();
                (name, true, func.btf_type)
            }
            BtfType::Var(var) => {
                let name = self.string_at(var.name_offset)?.into_owned();
                (name, false, var.btf_type)
            }
            _ => return Ok(None),
        };

        let symbol = find_symbol_by_name(symbol_table, &name).ok_or(BtfError::InvalidSymbolName)?;

        // Resolve through modifiers (const, volatile, typedef, etc.)
        // Type ID 0 represents void in BTF
        let resolved_type_id = self.resolve_type(var_btf_type).unwrap_or(var_btf_type);

        // Typeless ksyms are declared as `extern const void symbol __ksym`
        // They resolve to void (type_id 0) and are resolved via /proc/kallsyms
        let is_typeless = !is_func && resolved_type_id == 0;

        let mut extern_desc = ExternDesc::new(
            name,
            ExternType::Ksym,
            entry.btf_type,
            symbol.is_weak,
            is_func,
        );

        // For typeless ksyms, don't set type_id so they skip kernel BTF resolution
        if !is_typeless {
            extern_desc.type_id = Some(resolved_type_id);
        }

        Ok(Some(extern_desc))
    }
}

fn find_symbol_by_name<'a>(
    symbol_table: &'a HashMap<usize, Symbol>,
    name: &str,
) -> Option<&'a Symbol> {
    symbol_table
        .values()
        .find(|sym| sym.name.as_deref() == Some(name))
}

impl Object {
    /// Collects extern kernel symbols from BTF datasec entries.
    pub fn collect_ksyms_from_btf(&mut self) -> Result<(), KsymsError> {
        let btf = self.btf.as_mut().ok_or(KsymsError::NoBtf)?;
        let Some((datasec_id, datasec)) = btf.find_ksyms_datasec()? else {
            return Ok(());
        };

        if btf.datasec_has_functions(&datasec) {
            let dummy_var_id = btf.create_dummy_ksym_var()?;
            btf.externs.set_dummy_var_id(dummy_var_id);
        }

        let collected = btf.collect_extern_entries(&datasec, &self.symbol_table)?;

        for extern_desc in collected {
            btf.externs.insert(extern_desc.name.clone(), extern_desc);
        }

        if !btf.externs.is_empty() {
            btf.externs.datasec_id = Some(datasec_id);
        }

        Ok(())
    }
}
