#![expect(
    clippy::self_named_module_files,
    reason = "the test harness uses a flat tests module"
)]
#![expect(clippy::print_stderr, reason = "integration tests print skip reasons")]
#![expect(
    clippy::use_debug,
    reason = "debug formatting aids diagnostics in tests"
)]

use std::{
    collections::HashSet,
    fs, io,
    os::fd::{AsFd, AsRawFd as _},
    path::{Path, PathBuf},
    ptr,
};

use aya::{
    Ebpf,
    programs::{Program, ProgramError, links::LinkError, loaded_links},
    sys::SyscallError,
    test_helpers::{NetNsGuard, with_tracefs_probes},
    util::KernelVersion,
};
use aya_obj::generated::bpf_attach_type;

fn run_netns_tokio<F, Fut, T>(test: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let _netns = NetNsGuard::new().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(test())
}

// Tests must run serially (--test-threads=1, as configured by xtask and Bazel).
fn check_tracefs_cleanup<L>(pmu: &str, count: usize, attach: impl FnOnce() -> L, finish: fn(L)) {
    fn events(path: &Path) -> HashSet<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join(format!("{pmu}_events")).try_exists().unwrap())
        .unwrap();
    let events_path = tracefs.join(format!("{pmu}_events"));
    let before = events(&events_path);
    let link = with_tracefs_probes(attach);
    let attached = events(&events_path);
    // These snapshots are system-wide, so concurrent tests could make us count
    // another test's events as ours.
    let added: Vec<_> = attached.difference(&before).collect();
    assert_eq!(added.len(), count);

    // Run detach or the rejected conversion before checking the registrations.
    finish(link);

    let remaining = events(&events_path);
    for event in added {
        assert!(
            !remaining.contains(event),
            "event still registered: {event}"
        );
    }
}

#[track_caller]
fn assert_link_program(link_id: u32, program_id: Option<u32>) {
    // loaded_links() also enumerates links owned by other tests. A parallel test
    // may drop its link after its ID is found, causing the subsequent fd lookup
    // to fail with ENOENT. Only ignore this race; other errors must fail the test.
    let actual = loaded_links()
        .filter_map(|result| match result {
            Ok(info) => Some(info),
            Err(LinkError::SyscallError(SyscallError {
                call: "bpf_link_get_fd_by_id",
                io_error,
            })) if io_error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(err) => panic!("{err:?}"),
        })
        .find(|link| link.id() == link_id)
        .map(|link| link.program_id());
    assert_eq!(actual, program_id, "unexpected program for link {link_id}");
}

trait AdoptLinkProgramOps {
    const PROGRAM_TYPE: aya::programs::ProgramType;

    type LinkId;
    type OwnedLink;

    fn load(&mut self) -> Result<(), ProgramError>;
    fn take_link(&mut self, id: Self::LinkId) -> Result<Self::OwnedLink, ProgramError>;
    fn adopt_link(
        &mut self,
        link: Self::OwnedLink,
    ) -> Result<Self::LinkId, (ProgramError, Self::OwnedLink)>;
    fn detach(&mut self, id: Self::LinkId) -> Result<(), ProgramError>;
}

macro_rules! impl_adopt_link_program_ops {
    ($program:ty, $link_id:ty, $link:ty) => {
        impl AdoptLinkProgramOps for $program {
            const PROGRAM_TYPE: aya::programs::ProgramType = <$program>::PROGRAM_TYPE;

            type LinkId = $link_id;
            type OwnedLink = $link;

            fn load(&mut self) -> Result<(), ProgramError> {
                <$program>::load(self)
            }

            fn take_link(&mut self, id: Self::LinkId) -> Result<Self::OwnedLink, ProgramError> {
                <$program>::take_link(self, id)
            }

            fn adopt_link(
                &mut self,
                link: Self::OwnedLink,
            ) -> Result<Self::LinkId, (ProgramError, Self::OwnedLink)> {
                <$program>::adopt_link(self, link)
            }

            fn detach(&mut self, id: Self::LinkId) -> Result<(), ProgramError> {
                <$program>::detach(self, id)
            }
        }
    };
}

// BPF_PROG_QUERY works before link introspection was introduced, so these tests
// can inspect real attachments on both Linux 5.7 and legacy BPF_PROG_ATTACH kernels.
fn attached_program(target: &impl AsFd, attach_type: impl Into<bpf_attach_type>) -> Option<u32> {
    let attach_type = attach_type.into();
    let mut program_id = 0;
    let mut count = 1;
    // SAFETY: The output pointers are writable, with room for one program ID.
    // Each test uses a private cgroup or netns with a single attachment at this hook.
    let result = unsafe {
        libbpf_rs::libbpf_sys::bpf_prog_query(
            target.as_fd().as_raw_fd(),
            attach_type as u32,
            0,
            ptr::null_mut(),
            &raw mut program_id,
            &raw mut count,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    match count {
        0 => None,
        1 => Some(program_id),
        count => panic!("unexpected number of attached programs: {count}"),
    }
}

fn run_adopt_link_program_test<P, F, T>(
    program_name: &str,
    attach: F,
    target: &T,
    existing_target: Option<&T>,
    attach_type: bpf_attach_type,
    drop_program: bool,
) where
    P: AdoptLinkProgramOps,
    P::OwnedLink: std::fmt::Debug,
    F: Fn(&mut P, &T) -> P::LinkId,
    T: AsFd,
    for<'a> &'a mut Program: TryInto<&'a mut P, Error = ProgramError>,
{
    let mut old_bpf = Ebpf::load(crate::TEST).unwrap();
    let old: &mut P = old_bpf
        .program_mut(program_name)
        .unwrap()
        .try_into()
        .unwrap();
    old.load().unwrap();
    let id = attach(old, target);
    let link = old.take_link(id).unwrap();
    let old_program_id = old_bpf.program(program_name).unwrap().info().unwrap().id();
    // Cgroup links can be updated on 5.7, but enumeration and link info require
    // 5.8. Query the attachment on every kernel; additionally check link identity
    // when introspection is available.
    let kernel_link_id =
        (KernelVersion::current().unwrap() >= KernelVersion::new(5, 8, 0)).then(|| {
            loaded_links()
                .filter_map(|result| match result {
                    Ok(info) => Some(info),
                    Err(LinkError::SyscallError(SyscallError {
                        call: "bpf_link_get_fd_by_id",
                        io_error,
                    })) if io_error.raw_os_error() == Some(libc::ENOENT) => None,
                    Err(err) => panic!("{err:?}"),
                })
                .find(|link| link.program_id() == old_program_id)
                .unwrap()
                .id()
        });
    let assert_attached = |program_id| {
        assert_eq!(attached_program(target, attach_type), program_id);
        if let Some(kernel_link_id) = kernel_link_id {
            assert_link_program(kernel_link_id, program_id);
        }
    };
    assert_attached(Some(old_program_id));

    // Load a second instance so the kernel program ID exposes whether adoption
    // updated the existing link.
    let mut new_bpf = Ebpf::load(crate::TEST).unwrap();
    let new: &mut P = new_bpf
        .program_mut(program_name)
        .unwrap()
        .try_into()
        .unwrap();
    new.load().unwrap();
    let new_program_id = new_bpf.program(program_name).unwrap().info().unwrap().id();
    assert_ne!(old_program_id, new_program_id);
    let new: &mut P = new_bpf
        .program_mut(program_name)
        .unwrap()
        .try_into()
        .unwrap();
    // Give the receiver an attachment of its own before it adopts the old link.
    let existing_id = existing_target.map(|target| {
        let id = attach(new, target);
        assert_eq!(attached_program(target, attach_type), Some(new_program_id));
        id
    });
    let id = new.adopt_link(link).unwrap();
    assert_attached(Some(new_program_id));

    // Dropping the old owner must leave the link attached to the new program.
    drop(old_bpf);
    assert_attached(Some(new_program_id));

    // Adoption must preserve the receiver's original link ID and attachment.
    let existing_link = existing_id.map(|id| new.take_link(id).unwrap());
    if let Some(target) = existing_target {
        assert_eq!(attached_program(target, attach_type), Some(new_program_id));
    }

    // The returned ID belongs to the receiving program. It can also adopt its own link.
    let link = new.take_link(id).unwrap();
    let id = new.adopt_link(link).unwrap();
    assert_attached(Some(new_program_id));

    // Both explicit detach and dropping the new owner must release the kernel link.
    if drop_program {
        drop(new_bpf);
    } else {
        new.detach(id).unwrap();
    }
    assert_attached(None);

    // The independently owned link survives cleanup of the adopted link and
    // detaches only when its own handle is dropped.
    if let Some(target) = existing_target {
        assert_eq!(attached_program(target, attach_type), Some(new_program_id));
        drop(existing_link);
        assert_eq!(attached_program(target, attach_type), None);
    }
}

mod array;
mod bloom_filter;
mod bpf_probe_read;
mod btf_map_of_maps;
mod btf_maps;
mod btf_relocations;
mod cgroup_array;
mod cgroup_programs;
mod cgroup_storage;
mod cgrp_storage;
mod elf;
mod feature_probe;
mod fexit;
mod flow_dissector;
mod hash_map;
mod info;
mod inode_storage;
mod iter;
mod kprobe;
mod ksyms;
mod linear_data_structures;
mod load;
mod log;
mod lpm_trie;
mod lsm;
mod map_pin;
mod maps_disjoint;
mod per_cpu_array;
mod perf_event_array;
mod perf_event_bp;
mod printk;
mod prog_array;
mod prog_test_run;
mod raw_tracepoint;
mod rbpf;
mod relocations;
mod ring_buf;
mod sk_lookup;
mod sk_reuseport;
mod sk_storage;
mod smoke;
mod sock_map;
mod socket_filter;
mod stack_trace;
mod stack_trace_lsm;
mod strncmp;
mod tc_classid;
mod tc_netlink;
mod tcx;
mod uprobe_cookie;
mod uprobe_multi;
mod xdp;
