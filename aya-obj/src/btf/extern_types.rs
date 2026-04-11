use alloc::vec::Vec;

use log::debug;

use crate::{
    Object,
    btf::{Btf, BtfError, BtfType, DataSec, DataSecEntry},
    extern_types::{ExternDesc, ExternType},
    relocation::Symbol,
    util::HashMap,
};

impl Btf {
    /// Creates a placeholder global variable for `.ksyms` function entries.
    ///
    /// Kernel BTF datasec entries are variable-oriented, so function entries in `.ksyms`
    /// need a placeholder variable type during datasec fixup.
    pub(crate) fn create_ksym_func_placeholder(&mut self) -> u32 {
        let maybe_int_type_id = self.types().enumerate().find_map(|(idx, t)| match t {
            BtfType::Int(int) if int.size == 4 => Some(idx as u32),
            _ => None,
        });

        let int_type_id = if let Some(id) = maybe_int_type_id {
            debug!("found 4-byte int type_id: {id}");
            id
        } else {
            let name_offset = self.add_string("int");
            let int_type_id = self.add_type(BtfType::Int(crate::btf::Int::new(
                name_offset,
                4,
                crate::btf::IntEncoding::Signed,
                0,
            )));
            debug!("created 4-byte int type_id: {int_type_id}");
            int_type_id
        };

        let name_offset = self.add_string("ksym_func_placeholder");
        let placeholder_id = self.add_type(BtfType::Var(crate::btf::Var::new(
            name_offset,
            int_type_id,
            crate::btf::VarLinkage::Global,
        )));

        debug!("created ksym function placeholder type_id: {placeholder_id}");
        placeholder_id
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
    pub(crate) fn datasec_has_functions(&self, datasec: &DataSec) -> Result<bool, BtfError> {
        for entry in &datasec.entries {
            let t = self.type_by_id(entry.btf_type)?;
            if matches!(t, BtfType::Func(_)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns an iterator over extern descriptors from datasec entries.
    pub(crate) fn extern_entries<'a>(
        &'a self,
        datasec: &'a DataSec,
        symbol_table: &'a HashMap<usize, Symbol>,
    ) -> impl Iterator<Item = Result<ExternDesc, BtfError>> + 'a {
        datasec
            .entries
            .iter()
            .map(move |entry| self.process_datasec_entry(entry, symbol_table))
    }

    /// Processes a single datasec entry into an [`ExternDesc`].
    fn process_datasec_entry(
        &self,
        entry: &DataSecEntry,
        symbol_table: &HashMap<usize, Symbol>,
    ) -> Result<ExternDesc, BtfError> {
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
            _ => return Err(BtfError::InvalidDatasec),
        };

        let symbol = find_symbol_by_name(symbol_table, &name).ok_or(BtfError::InvalidSymbolName)?;

        // Resolve through modifiers (const, volatile, typedef, etc.)
        // Type ID 0 represents void in BTF
        let resolved_type_id = self.resolve_type(var_btf_type).unwrap_or(var_btf_type);

        // Typeless ksyms are declared as `extern const void symbol __ksym`
        // They resolve to void (type_id 0) and are resolved via /proc/kallsyms
        let is_typeless = !is_func && resolved_type_id == 0;

        let mut extern_desc =
            ExternDesc::new(name, ExternType::Ksym, entry.btf_type, symbol.is_weak);

        // For typeless ksyms, don't set type_id so they skip kernel BTF resolution
        if !is_typeless {
            extern_desc.type_id = Some(resolved_type_id);
        }

        Ok(extern_desc)
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
    pub(crate) fn collect_ksyms_from_btf(&mut self) -> Result<(), BtfError> {
        let Some(btf) = self.btf.as_mut() else {
            return Ok(());
        };
        let Some((datasec_id, datasec)) = btf.find_ksyms_datasec()? else {
            return Ok(());
        };

        if btf.datasec_has_functions(&datasec)? {
            let dummy_var_id = btf.create_ksym_func_placeholder();
            btf.externs.set_dummy_var_id(dummy_var_id);
        }

        let collected: Vec<ExternDesc> = btf
            .extern_entries(&datasec, &self.symbol_table)
            .collect::<Result<Vec<_>, _>>()?;

        for extern_desc in collected {
            btf.externs.insert(extern_desc.name.clone(), extern_desc);
        }

        if !btf.externs.is_empty() {
            btf.externs.datasec_id = Some(datasec_id);
        }

        Ok(())
    }
}
