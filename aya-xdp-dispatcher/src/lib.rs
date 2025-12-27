mod error;
use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap},
    env::temp_dir,
    fs,
};

use aya::{
    Ebpf, EbpfLoader,
    programs::{
        Extension, Xdp, XdpFlags,
        links::{FdLink, PinnedLink},
    },
};
use aya_xdp_dispatcher_ebpf::XdpDispatcherConfig;
pub use error::*;
use named_lock::NamedLock;
use uuid::Uuid;

const AYA_XDP_DISPATCHER_EBPF_PROGRAM: &[u8] = &[];

const RTDIR_FS_XDP: &str = "/sys/fs/bpf/xdp-dispatcher";

pub const MAX_PROGARMS: usize = 10;

fn default_proceed_on_mask() -> u32 {
    let mut proceed_on_mask: u32 = 0;
    for action in [2, 31] {
        proceed_on_mask |= 1 << action;
    }
    proceed_on_mask
}

pub struct EbpfPrograms<'a> {
    pub ebpf_id: Uuid,
    pub loader: EbpfLoader<'a>,
    programs: Vec<(&'a str, u8)>,
    bpf_bytes: &'a [u8],
}

impl<'a> EbpfPrograms<'a> {
    pub fn new(ebpf_id: Uuid, loader: EbpfLoader<'a>, bpf_bytes: &'a [u8]) -> Self {
        Self {
            ebpf_id,
            loader,
            programs: Vec::new(),
            bpf_bytes,
        }
    }

    pub fn set_priority(mut self, program: &'a str, priority: u8) -> Self {
        self.programs.push((program, priority));
        self
    }
}

#[derive(Clone)]
struct ExtensionAttrs {
    priority: u8,
    ebpf_id: Uuid,
    program_name: String,
    loaded: bool,
}

impl ExtensionAttrs {
    fn from_pin_name(pin: &str) -> Option<Self> {
        // program format is extension_<priority>_<ebpfid>_<program_name>
        let attrs = pin.strip_prefix("extension_")?;
        let mut split_iter = attrs.splitn(3, '_');
        let priority = split_iter.next()?.parse().ok()?;
        let ebpf_id = split_iter.next()?.parse().ok()?;
        let program_name = split_iter.next()?.to_owned();

        Some(Self {
            priority,
            ebpf_id,
            program_name,
            loaded: true,
        })
    }

    fn to_pin_name(&self) -> String {
        format!(
            "extension_{}_{}_{}",
            self.priority, self.ebpf_id, self.program_name
        )
    }
}

pub struct XdpDispatcher {
    if_index: u32,
    xdp_flags: XdpFlags,
    owned_ebpfs: HashMap<Uuid, Ebpf>,
    owned_extension_priorities: HashMap<(Uuid, String), u8>,
}

impl XdpDispatcher {
    fn cleanup_prev_revision(path: &str) -> Result<()> {
        std::fs::remove_dir_all(path)?;

        Ok(())
    }

    fn current_rev(dispatcher_dir: &str) -> Result<usize> {
        let mut current_rev = 0;
        for entry in fs::read_dir(dispatcher_dir)? {
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(ftype) = entry.file_type() else {
                continue;
            };
            if !ftype.is_dir() {
                continue;
            }

            let Some(rev) = entry
                .file_name()
                .to_str()
                .and_then(|f| f.parse::<usize>().ok())
            else {
                continue;
            };
            current_rev = rev.max(current_rev);
        }

        Ok(current_rev)
    }

    fn existing_extensions_iter(
        ext_dir: &str,
    ) -> Result<impl Iterator<Item = (ExtensionAttrs, Extension)>> {
        Ok(fs::read_dir(ext_dir)?.filter_map(|entry| {
            let entry = entry.ok()?;
            let fname = entry.file_name();
            let file_name = fname.to_str()?;
            // program format is extension_<priority>_<ebpfid>_<program_name>
            let attrs = ExtensionAttrs::from_pin_name(file_name)?;

            let extension = Extension::from_pin(entry.path()).ok()?;
            Some((attrs, extension))
        }))
    }

    fn load_xdp_dispatcher_with_exts<Ext: BorrowMut<Extension>>(
        total_programs: u8,
        if_index: u32,
        dispatcher_dir: &str,
        current_ext_dir: &str,
        next_ext_dir: &str,
        extensions: impl IntoIterator<Item = Vec<(ExtensionAttrs, Ext)>>,
        xdp_flags: XdpFlags,
    ) -> Result<()> {
        let mut dispatcher_bpf = EbpfLoader::new()
            .override_global(
                "CONFIG",
                &XdpDispatcherConfig {
                    num_progs_enabled: total_programs,
                    chain_call_actions: [default_proceed_on_mask(); 10],
                },
                true,
            )
            .load(AYA_XDP_DISPATCHER_EBPF_PROGRAM)?;
        let dispatcher_xdp: &mut Xdp = dispatcher_bpf
            .program_mut("dispatcher")
            .unwrap()
            .try_into()
            .unwrap();
        dispatcher_xdp.load()?;

        for (i, (attrs, mut ext)) in extensions.into_iter().flatten().enumerate() {
            let ext = ext.borrow_mut();
            let link_id = if !attrs.loaded {
                ext.load(dispatcher_xdp.fd()?.try_clone()?, &format!("prog{i}"))?;
                ext.attach()?
            } else {
                ext.attach_to_program(dispatcher_xdp.fd()?, &format!("prog{i}"))?
            };
            let link_o = ext.take_link(link_id)?;
            let link_fd: FdLink = link_o.into();
            link_fd.pin(format!("{next_ext_dir}/link_{i}"))?;
            ext.pin(format!("{next_ext_dir}/{}", attrs.to_pin_name()))?;
        }
        dispatcher_xdp.pin(format!("{next_ext_dir}/dispatcher_pin"))?;

        let dispatcher_link = format!("{dispatcher_dir}/dispatcher_link");
        if let Ok(pinned_link) = PinnedLink::from_pin(&dispatcher_link) {
            let pinned_link: FdLink = pinned_link.into();
            dispatcher_xdp.attach_to_link(pinned_link.try_into()?)?;
            Self::cleanup_prev_revision(current_ext_dir)?;
        } else {
            let link = dispatcher_xdp.attach_to_if_index(if_index, xdp_flags)?;
            let link_o = dispatcher_xdp.take_link(link)?;
            let link_fd: FdLink = link_o.try_into().unwrap();
            link_fd.pin(&dispatcher_link)?;
        }

        Ok(())
    }

    fn dispatcher_lock(if_index: u32) -> Result<NamedLock> {
        let lock_path = temp_dir().join(format!("dispatcher_{if_index}_lock"));
        Ok(NamedLock::with_path(lock_path)?)
    }

    pub fn new_with_programs(
        if_index: u32,
        xdp_flags: XdpFlags,
        bpfs: Vec<&'_ mut EbpfPrograms<'_>>,
    ) -> Result<Self> {
        let dispatcher_dir = format!("{RTDIR_FS_XDP}/dispatcher_{if_index}");
        fs::create_dir_all(&dispatcher_dir)?;

        // implicit: drop order is important here! _lock_guard must be dropped before `this`
        // else it will cause a deadlock if `new_with_programs` fails
        let mut this = Self {
            if_index,
            owned_ebpfs: HashMap::new(),
            owned_extension_priorities: HashMap::new(),
            xdp_flags,
        };

        let lock = Self::dispatcher_lock(if_index)?;
        let _lock_guard = lock.lock()?;

        let current_rev = Self::current_rev(&dispatcher_dir)?;

        let current_ext_dir = format!("{dispatcher_dir}/{current_rev}");
        let next_ext_dir = format!("{dispatcher_dir}/{}", current_rev + 1);
        fs::create_dir_all(&next_ext_dir)?;

        let mut ext_o: Vec<_>;
        let mut extensions = BTreeMap::new();
        if fs::exists(&current_ext_dir)? {
            ext_o = Self::existing_extensions_iter(&current_ext_dir)?.collect();
            for (attrs, ext) in ext_o.iter_mut() {
                extensions
                    .entry(attrs.priority)
                    .or_insert(vec![])
                    .push((attrs.clone(), ext));
            }
        }

        let mut total_programs = extensions.len();
        for bpf in bpfs.iter() {
            total_programs += bpf.programs.len();
            if total_programs > MAX_PROGARMS {
                return Err(Error::MaxPrograms(MAX_PROGARMS));
            }
        }

        for bpf in bpfs {
            for (program, _) in &bpf.programs {
                bpf.loader.extension(program);
            }
            let ebpf = bpf.loader.load(bpf.bpf_bytes)?;
            this.owned_ebpfs.insert(bpf.ebpf_id, ebpf);
            for (program, priority) in &bpf.programs {
                this.owned_extension_priorities
                    .insert((bpf.ebpf_id, program.to_string()), *priority);
            }
        }
        for (ebpf_id, ebpf) in this.owned_ebpfs.iter_mut() {
            for (program_name, program) in ebpf.programs_mut() {
                if !this
                    .owned_extension_priorities
                    .contains_key(&(*ebpf_id, program_name.to_string()))
                {
                    continue;
                }
                let ext: &mut Extension = program.try_into().unwrap();
                let priority = *this
                    .owned_extension_priorities
                    .get(&(*ebpf_id, program_name.to_owned()))
                    .unwrap();

                extensions.entry(priority).or_default().push((
                    ExtensionAttrs {
                        priority,
                        ebpf_id: *ebpf_id,
                        program_name: program_name.to_string(),
                        loaded: false,
                    },
                    ext,
                ));
            }
        }

        Self::load_xdp_dispatcher_with_exts(
            total_programs as u8,
            if_index,
            &dispatcher_dir,
            &current_ext_dir,
            &next_ext_dir,
            extensions.into_values(),
            xdp_flags,
        )?;

        Ok(this)
    }

    pub fn ebpf_mut(&mut self, ebpf_id: Uuid) -> Option<&mut Ebpf> {
        self.owned_ebpfs.get_mut(&ebpf_id)
    }

    fn cleanup(&mut self) -> Result<()> {
        let dispatcher_dir = format!("{RTDIR_FS_XDP}/dispatcher_{}", self.if_index);

        let lock = Self::dispatcher_lock(self.if_index)?;
        let _lock_guard = lock.lock();

        let current_rev = Self::current_rev(&dispatcher_dir)?;
        let current_ext_dir = format!("{dispatcher_dir}/{current_rev}");

        let mut extensions = BTreeMap::new();
        for (attrs, ext) in Self::existing_extensions_iter(&current_ext_dir)? {
            if self
                .owned_extension_priorities
                .get(&(attrs.ebpf_id, attrs.program_name.to_owned()))
                .copied()
                == Some(attrs.priority)
            {
                continue;
            }
            extensions
                .entry(attrs.priority)
                .or_insert(vec![])
                .push((attrs, ext));
        }

        if extensions.is_empty() {
            let dispatcher_link = format!("{dispatcher_dir}/dispatcher_link");
            if fs::exists(&dispatcher_link)? {
                fs::remove_file(dispatcher_link)?;
            }
            Self::cleanup_prev_revision(&current_ext_dir)?;

            return Ok(());
        }

        let next_ext_dir = format!("{dispatcher_dir}/{}", current_rev + 1);
        fs::create_dir_all(&next_ext_dir)?;

        Self::load_xdp_dispatcher_with_exts(
            extensions.len() as u8,
            self.if_index,
            &dispatcher_dir,
            &current_ext_dir,
            &next_ext_dir,
            extensions.into_values(),
            self.xdp_flags,
        )?;

        Ok(())
    }
}

impl Drop for XdpDispatcher {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("failed to cleanup dispatcher {e}");
        }
    }
}
