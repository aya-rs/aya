#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array as BtfArray, CgroupArray as BtfCgroupArray},
    cty::c_long,
    macros::{btf_map, classifier, map, uprobe},
    maps::{Array as LegacyArray, CgroupArray as LegacyCgroupArray},
    programs::{ProbeContext, TcContext},
};
use integration_common::cgroup_array::{NOT_UNDER_INDEX, TestResult, UNDER_INDEX};

#[btf_map]
static CGROUPS: BtfCgroupArray<2, 0> = BtfCgroupArray::new();

#[btf_map]
static RESULT: BtfArray<TestResult, 1, 0> = BtfArray::new();

#[map]
static CGROUPS_LEGACY: LegacyCgroupArray = LegacyCgroupArray::with_max_entries(2, 0);

#[map]
static RESULT_LEGACY: LegacyArray<TestResult> = LegacyArray::with_max_entries(1, 0);

const fn encode(result: Result<bool, c_long>) -> i64 {
    match result {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(ret) => ret,
    }
}

macro_rules! define_current_task_under_cgroup_test {
    ($cgroups:ident, $result:ident, $probe:ident $(,)?) => {
        #[uprobe]
        fn $probe(_ctx: ProbeContext) -> Result<(), c_long> {
            let under = encode($cgroups.current_task_under_cgroup(UNDER_INDEX));
            let not_under = encode($cgroups.current_task_under_cgroup(NOT_UNDER_INDEX));
            let ptr = $result.get_ptr_mut(0).ok_or(-1)?;
            unsafe {
                *ptr = TestResult {
                    under,
                    not_under,
                    ran: true,
                };
            }
            Ok(())
        }
    };
}

define_current_task_under_cgroup_test!(CGROUPS, RESULT, current_task_under_cgroup_btf);
define_current_task_under_cgroup_test!(
    CGROUPS_LEGACY,
    RESULT_LEGACY,
    current_task_under_cgroup_legacy,
);

// Compile and codegen coverage for `skb_under_cgroup` against both map
// variants. This program is never attached by the test.
#[classifier]
fn skb_under_cgroup(ctx: TcContext) -> i32 {
    let legacy = ctx.skb_under_cgroup(&CGROUPS_LEGACY, 0).unwrap_or(false);
    let btf = ctx.skb_under_cgroup(&CGROUPS, 0).unwrap_or(false);
    i32::from(legacy || btf)
}
