mod error;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    programs::{
        Extension, Xdp, XdpFlags,
        links::{FdLink, PinnedLink},
    },
};
use aya_xdp_dispatcher_ebpf::{
    MAX_DISPATCHER_ACTIONS, XDP_DISPATCHER_MAGIC, XDP_DISPATCHER_RETVAL, XDP_DISPATCHER_VERSION,
    XdpDispatcherConfig,
};
use bytemuck::try_pod_read_unaligned;
pub use error::*;
use nix::fcntl::{Flock, FlockArg};
use uuid::Uuid;

const AYA_XDP_DISPATCHER_EBPF_PROGRAM: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-xdp-dispatcher-ebpf"));

const RTDIR_FS_XDP: &str = "/sys/fs/bpf/xdp";

pub const MAX_PROGRAMS: usize = MAX_DISPATCHER_ACTIONS;

pub const DEFAULT_PRIORITY: u32 = 50;

// XDP action values (matching kernel xdp_action enum).
const XDP_PASS: u32 = 2;

const DEFAULT_CHAIN_CALL_ACTIONS: u32 = (1 << XDP_PASS) | (1 << XDP_DISPATCHER_RETVAL);

pub struct ProgramConfig {
    /// Run priority (lower = runs first). Default: 50.
    pub priority: u32,
    pub chain_call_actions: u32,
    /// Whether this program was loaded with `BPF_F_XDP_HAS_FRAGS`.
    pub has_frags: bool,
}

impl Default for ProgramConfig {
    fn default() -> Self {
        Self {
            priority: DEFAULT_PRIORITY,
            chain_call_actions: DEFAULT_CHAIN_CALL_ACTIONS,
            has_frags: false,
        }
    }
}

pub struct EbpfPrograms<'a> {
    pub ebpf_id: Uuid,
    pub loader: EbpfLoader<'a>,
    programs: Vec<(&'a str, ProgramConfig)>,
    bpf_bytes: &'a [u8],
}

impl<'a> EbpfPrograms<'a> {
    pub const fn new(ebpf_id: Uuid, loader: EbpfLoader<'a>, bpf_bytes: &'a [u8]) -> Self {
        Self {
            ebpf_id,
            loader,
            programs: Vec::new(),
            bpf_bytes,
        }
    }

    #[must_use]
    pub fn set_priority(mut self, program: &'a str, priority: u32) -> Self {
        self.programs.push((
            program,
            ProgramConfig {
                priority,
                ..Default::default()
            },
        ));
        self
    }

    #[must_use]
    pub fn with_config(mut self, program: &'a str, config: ProgramConfig) -> Self {
        self.programs.push((program, config));
        self
    }
}

#[derive(Clone)]
struct SlotEntry {
    priority: u32,
    chain_call_actions: u32,
    program_flags: u32,
    ebpf_id: Option<Uuid>,
    program_name: Option<String>,
    existing_prog_path: Option<PathBuf>,
}

pub struct XdpDispatcher {
    if_index: u32,
    xdp_flags: XdpFlags,
    owned_ebpfs: HashMap<Uuid, Ebpf>,
    owned_prog_ids: Vec<u32>,
}

impl XdpDispatcher {
    fn lock_xdp_dir() -> Result<Flock<File>> {
        fs::create_dir_all(RTDIR_FS_XDP)?;
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY)
            .open(RTDIR_FS_XDP)?;
        Flock::lock(f, FlockArg::LockExclusive).map_err(|(_, e)| Error::Lock(e))
    }

    fn find_existing_dir(if_index: u32) -> Result<Option<PathBuf>> {
        let prefix = format!("dispatch-{if_index}-");
        for entry in fs::read_dir(RTDIR_FS_XDP)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.starts_with(&prefix))
            {
                return Ok(Some(entry.path()));
            }
        }
        Ok(None)
    }

    fn read_config(dispatcher_dir: &Path) -> Result<XdpDispatcherConfig> {
        let bytes = fs::read(dispatcher_dir.join("config"))?;
        try_pod_read_unaligned(&bytes).map_err(|_pod| Error::InvalidConfig)
    }

    fn write_config(dispatcher_dir: &Path, config: &XdpDispatcherConfig) -> Result<()> {
        let bytes = bytemuck::bytes_of(config);
        fs::write(dispatcher_dir.join("config"), bytes)?;
        Ok(())
    }

    fn read_existing_slots(dispatcher_dir: &Path, config: &XdpDispatcherConfig) -> Vec<SlotEntry> {
        (0..MAX_PROGRAMS)
            .filter_map(|i| {
                let prog_path = dispatcher_dir.join(format!("prog{i}-prog"));
                prog_path.exists().then_some(SlotEntry {
                    priority: config.run_prios[i],
                    chain_call_actions: config.chain_call_actions[i],
                    program_flags: config.program_flags[i],
                    ebpf_id: None,
                    program_name: None,
                    existing_prog_path: Some(prog_path),
                })
            })
            .collect()
    }

    /// Core loader: build a new dispatcher with `slots`, pin everything in bpffs, then attach.
    ///
    /// On success returns `(new_dispatcher_dir, ext_prog_ids)`.
    /// On concurrent-modification the caller should retry.
    fn do_load(
        if_index: u32,
        xdp_flags: XdpFlags,
        mut slots: Vec<SlotEntry>,
        owned_ebpfs: &mut HashMap<Uuid, Ebpf>,
        existing_dir: Option<&Path>,
    ) -> Result<Vec<u32>> {
        slots.sort_by_key(|s| s.priority);

        let num_progs = slots.len() as u8;
        let is_xdp_frags =
            u8::from(!slots.is_empty() && slots.iter().all(|s| s.program_flags != 0));

        let mut chain_call_actions = [DEFAULT_CHAIN_CALL_ACTIONS; MAX_DISPATCHER_ACTIONS];
        let mut run_prios = [DEFAULT_PRIORITY; MAX_DISPATCHER_ACTIONS];
        let mut program_flags = [0u32; MAX_DISPATCHER_ACTIONS];
        for (i, slot) in slots.iter().enumerate() {
            // Spec: XDP_DISPATCHER_RETVAL must always be set.
            chain_call_actions[i] = slot.chain_call_actions | (1 << XDP_DISPATCHER_RETVAL);
            run_prios[i] = slot.priority;
            program_flags[i] = slot.program_flags;
        }

        let config = XdpDispatcherConfig {
            magic: XDP_DISPATCHER_MAGIC,
            dispatcher_version: XDP_DISPATCHER_VERSION,
            num_progs_enabled: num_progs,
            is_xdp_frags,
            chain_call_actions,
            run_prios,
            program_flags,
        };

        let mut dispatcher_bpf = EbpfLoader::new()
            .override_global("conf", &config, true)
            .load(AYA_XDP_DISPATCHER_EBPF_PROGRAM)?;

        let dispatcher_xdp: &mut Xdp = dispatcher_bpf
            .program_mut("xdp_dispatcher")
            .unwrap()
            .try_into()
            .unwrap();
        dispatcher_xdp.load()?;

        let dispatcher_fd = dispatcher_xdp.fd()?.try_clone()?;

        let did = dispatcher_xdp.info()?.id();
        let new_dir = PathBuf::from(RTDIR_FS_XDP).join(format!("dispatch-{if_index}-{did}"));
        fs::create_dir_all(&new_dir)?;
        let rtdir_guard = FolderFailureGuard(&new_dir);

        let mut ext_prog_ids: Vec<u32> = Vec::new();
        for (i, slot) in slots.iter_mut().enumerate() {
            let func_name = format!("prog{i}");
            let prog_pin = new_dir.join(format!("prog{i}-prog"));
            let link_pin = new_dir.join(format!("prog{i}-link"));

            let ext_prog_id = if let Some(prog_path) = &slot.existing_prog_path {
                let mut ext = Extension::from_pin(prog_path)?;
                let prog_id = ext.info()?.id();
                let link_id = ext.attach_to_program(&dispatcher_fd, &func_name)?;
                let link_o = ext.take_link(link_id)?;
                let link_fd: FdLink = link_o.into();
                link_fd.pin(&link_pin)?;
                ext.pin(&prog_pin)?;
                prog_id
            } else {
                let ebpf_id = slot.ebpf_id.unwrap();
                let prog_name = slot.program_name.as_deref().unwrap();
                let ebpf = owned_ebpfs.get_mut(&ebpf_id).unwrap();
                let ext: &mut Extension = ebpf.program_mut(prog_name).unwrap().try_into().unwrap();
                ext.load(dispatcher_fd.try_clone()?, &func_name)?;
                let prog_id = ext.info()?.id();
                let link_id = ext.attach()?;
                let link_o = ext.take_link(link_id)?;
                let link_fd: FdLink = link_o.into();
                link_fd.pin(&link_pin)?;
                ext.pin(&prog_pin)?;
                prog_id
            };

            ext_prog_ids.push(ext_prog_id);
        }

        Self::write_config(&new_dir, &config)?;

        let new_link_pin = new_dir.join("link");
        if let Some(existing_dir) = existing_dir {
            let existing_link_pin = existing_dir.join("link");
            let pinned_link = PinnedLink::from_pin(&existing_link_pin)?;
            let pinned_fd: FdLink = pinned_link.into();
            let xdp_link = pinned_fd.try_into()?;
            let link_id = dispatcher_xdp.attach_to_link(xdp_link)?;
            let link_o = dispatcher_xdp.take_link(link_id)?;
            let link_fd: FdLink = link_o.try_into().map_err(|_link_err| Error::NoFdLink)?;
            link_fd.pin(&new_link_pin)?;
        } else {
            let attach_flags = xdp_flags | XdpFlags::UPDATE_IF_NOEXIST;
            match dispatcher_xdp.attach_to_if_index(if_index, attach_flags) {
                Ok(link_id) => {
                    let link_o = dispatcher_xdp.take_link(link_id)?;
                    let link_fd: FdLink = link_o.try_into().map_err(|_link_err| Error::NoFdLink)?;
                    link_fd.pin(&new_link_pin)?;
                }
                Err(e) => {
                    return if is_eexist(&e) {
                        Err(Error::ConcurrentModification)
                    } else {
                        Err(e.into())
                    };
                }
            }
        }

        rtdir_guard.disarm();
        Ok(ext_prog_ids)
    }

    /// Load and attach `bpfs` onto the XDP dispatcher for `if_index`.
    ///
    /// If programs already exist on the interface (loaded by a previous call), they are
    /// preserved and the new programs are merged in by priority. The dispatcher is then
    /// atomically replaced on the interface.
    pub fn new_with_programs(
        if_index: u32,
        xdp_flags: XdpFlags,
        bpfs: Vec<&'_ mut EbpfPrograms<'_>>,
    ) -> Result<Self> {
        let mut owned_ebpfs: HashMap<Uuid, Ebpf> = HashMap::new();
        let mut new_slots: Vec<SlotEntry> = Vec::new();

        for bpf in bpfs {
            for (name, _) in &bpf.programs {
                bpf.loader.extension(name);
            }
            let ebpf = bpf.loader.load(bpf.bpf_bytes)?;
            owned_ebpfs.insert(bpf.ebpf_id, ebpf);
            for (name, cfg) in &bpf.programs {
                new_slots.push(SlotEntry {
                    priority: cfg.priority,
                    chain_call_actions: cfg.chain_call_actions,
                    program_flags: cfg.has_frags.into(),
                    ebpf_id: Some(bpf.ebpf_id),
                    program_name: Some((*name).to_string()),
                    existing_prog_path: None,
                });
            }
        }

        let owned_prog_ids = loop {
            let _lock = Self::lock_xdp_dir()?;

            let existing_dir = Self::find_existing_dir(if_index)?;
            let mut all_slots = new_slots.clone();

            if let Some(dir) = existing_dir.as_ref() {
                if let Ok(config) = Self::read_config(dir) {
                    if config.magic == XDP_DISPATCHER_MAGIC
                        && config.dispatcher_version == XDP_DISPATCHER_VERSION
                    {
                        all_slots.extend(Self::read_existing_slots(dir, &config));
                    }
                }
            }

            if all_slots.len() > MAX_PROGRAMS {
                return Err(Error::MaxPrograms(MAX_PROGRAMS));
            }

            match Self::do_load(
                if_index,
                xdp_flags,
                all_slots,
                &mut owned_ebpfs,
                existing_dir.as_deref(),
            ) {
                Ok(ids) => {
                    if let Some(old_dir) = existing_dir.as_ref() {
                        drop(fs::remove_dir_all(old_dir));
                    }
                    break ids;
                }
                Err(Error::ConcurrentModification) => (),
                Err(e) => return Err(e),
            }
        };
        Ok(Self {
            if_index,
            xdp_flags,
            owned_ebpfs,
            owned_prog_ids,
        })
    }

    /// Access the loaded `Ebpf` object for the given ID.
    pub fn ebpf_mut(&mut self, ebpf_id: Uuid) -> Option<&mut Ebpf> {
        self.owned_ebpfs.get_mut(&ebpf_id)
    }

    /// Remove our programs from the dispatcher, replacing it with a new one containing
    /// only the remaining programs. Called on drop.
    fn cleanup(&self) -> Result<()> {
        let _lock = Self::lock_xdp_dir()?;

        let Some(existing_dir) = Self::find_existing_dir(self.if_index)? else {
            return Ok(());
        };

        let Ok(config) = Self::read_config(&existing_dir) else {
            return Ok(());
        };

        let remaining: Vec<SlotEntry> = Self::read_existing_slots(&existing_dir, &config)
            .into_iter()
            .filter(|slot| {
                let Some(path) = slot.existing_prog_path.as_ref() else {
                    return true;
                };
                let id = aya::programs::ProgramInfo::from_pin(path)
                    .map(|info| info.id())
                    .unwrap_or(0);
                !self.owned_prog_ids.contains(&id)
            })
            .collect();

        if remaining.is_empty() {
            let link_pin = existing_dir.join("link");
            if link_pin.exists() {
                // Opening the pin keeps the link alive during our cleanup
                // the PinnedLink decrements its reference count and detaches.
                drop(PinnedLink::from_pin(&link_pin));
                drop(fs::remove_file(&link_pin));
            }
            drop(fs::remove_dir_all(&existing_dir));
            return Ok(());
        }

        let mut no_ebpfs: HashMap<Uuid, Ebpf> = HashMap::new();
        match Self::do_load(
            self.if_index,
            self.xdp_flags,
            remaining,
            &mut no_ebpfs,
            Some(&existing_dir),
        ) {
            Ok(_) => {
                fs::remove_dir_all(&existing_dir)?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for XdpDispatcher {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            log::error!("aya-xdp-dispatcher: cleanup failed: {e}");
        }
    }
}

#[must_use = "must disarm the guard on success to avoid deleting the directory"]
struct FolderFailureGuard<'a>(&'a Path);

impl FolderFailureGuard<'_> {
    const fn disarm(self) {
        #[expect(
            clippy::mem_forget,
            reason = "we specifically want to avoid running the destructor when disarmed"
        )]
        std::mem::forget(self)
    }
}

impl Drop for FolderFailureGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(self.0) {
            log::error!(
                "aya-xdp-dispatcher: failed to remove directory {}: {e}",
                self.0.display()
            );
        }
    }
}

fn is_eexist(err: &aya::programs::ProgramError) -> bool {
    use aya::programs::ProgramError;
    if let ProgramError::SyscallError(sc) = err {
        return sc.io_error.raw_os_error() == Some(nix::libc::EEXIST);
    }
    false
}
