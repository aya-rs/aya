use std::{fs::File, os::fd::AsRawFd as _};

use aya::{
    EbpfLoader,
    maps::{Array, CgroupArray, MapType},
    programs::{SchedClassifier, UProbe, uprobe::UProbeScope},
    sys::is_map_supported,
    test_helpers::{Cgroup, is_cgroup2},
    util::KernelVersion,
};
use integration_common::cgroup_array::{NOT_UNDER_INDEX, TestResult, UNDER_INDEX};
use rstest::rstest;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_current_task_under_cgroup() {
    std::hint::black_box(());
}

#[rstest]
#[case::legacy("CGROUPS_LEGACY", "RESULT_LEGACY", "current_task_under_cgroup_legacy")]
#[case::btf("CGROUPS", "RESULT", "current_task_under_cgroup_btf")]
#[test_attr(test_log::test)]
fn current_task_under_cgroup(
    #[case] cgroups_map: &str,
    #[case] result_map: &str,
    #[case] prog: &str,
) {
    if !is_map_supported(MapType::CgroupArray).unwrap() {
        eprintln!("skipping test - cgroup array map not supported");
        return;
    }

    if !is_cgroup2() {
        eprintln!("skipping test - /sys/fs/cgroup is not cgroup2");
        return;
    }

    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(4, 9, 0) {
        eprintln!(
            "skipping test - bpf_current_task_under_cgroup added in 4.9, kernel is {kernel_version:?}"
        );
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::CGROUP_ARRAY)
        .expect("load cgroup_array program");

    // Load and attach the uprobe first so the loaded program holds a reference
    // to the cgroup array; the typed map below can then be dropped safely.
    {
        let program: &mut UProbe = bpf
            .program_mut(prog)
            .unwrap_or_else(|| panic!("missing program {prog}"))
            .try_into()
            .unwrap_or_else(|err| panic!("program {prog} is not a uprobe: {err}"));
        program
            .load()
            .unwrap_or_else(|err| panic!("load {prog}: {err}"));
        program
            .attach(
                "trigger_current_task_under_cgroup",
                "/proc/self/exe",
                UProbeScope::AllProcesses,
            )
            .unwrap_or_else(|err| panic!("attach {prog}: {err}"));
    }

    // The cgroup root is an ancestor of every task; a fresh child cgroup that
    // the test process is not moved into is not.
    let root = Cgroup::root();
    let not_under = root.create_child(prog).unwrap();
    let under = File::open("/sys/fs/cgroup").expect("open cgroup root");

    let mut cgroups: CgroupArray<_> = bpf.take_map(cgroups_map).unwrap().try_into().unwrap();
    cgroups
        .set(UNDER_INDEX, under.as_raw_fd(), 0)
        .expect("set UNDER_INDEX");
    cgroups
        .set(NOT_UNDER_INDEX, not_under.fd().unwrap().as_raw_fd(), 0)
        .expect("set NOT_UNDER_INDEX");

    let result = Array::<_, TestResult>::try_from(bpf.map(result_map).unwrap()).unwrap();

    trigger_current_task_under_cgroup();

    let TestResult {
        under,
        not_under: not_under_result,
        ran,
    } = result.get(&0, 0).unwrap();
    assert!(ran, "uprobe did not run");
    assert_eq!(under, 1);
    assert_eq!(not_under_result, 0);
}

#[test_log::test]
fn skb_under_cgroup_loads() {
    if !is_map_supported(MapType::CgroupArray).unwrap() {
        eprintln!("skipping test - cgroup array map not supported");
        return;
    }

    let mut bpf = EbpfLoader::new()
        .load(crate::CGROUP_ARRAY)
        .expect("load cgroup_array program");

    let program: &mut SchedClassifier = bpf
        .program_mut("skb_under_cgroup")
        .expect("missing program skb_under_cgroup")
        .try_into()
        .expect("program skb_under_cgroup is not a classifier");
    program.load().expect("load skb_under_cgroup");
}
