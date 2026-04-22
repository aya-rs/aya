use aya::{
    Ebpf,
    maps::{Array, LpmTrie, lpm_trie::Key},
    programs::UProbe,
};
use integration_common::lpm_trie::{LPM_MATCH_SLOT, NO_MATCH_SLOT, REMOVE_SLOT, TestResult};
use test_case::test_case;

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_lpm_trie() {
    core::hint::black_box(());
}

#[test_case("test_btf_lpm_trie", "ROUTES", "RESULTS" ; "btf")]
#[test_case("test_lpm_trie_legacy", "ROUTES_LEGACY", "RESULTS_LEGACY" ; "legacy")]
#[test_log::test]
fn lpm_trie_basic(prog_name: &str, routes_map: &str, results_map: &str) {
    let mut bpf = Ebpf::load(crate::LPM_TRIE).unwrap();

    {
        let mut routes: LpmTrie<_, [u8; 4], u32> =
            bpf.map_mut(routes_map).unwrap().try_into().unwrap();
        routes
            .insert(&Key::new(16, [192, 168, 0, 0]), 42u32, 0)
            .unwrap();
        routes
            .insert(&Key::new(24, [192, 168, 1, 0]), 7u32, 0)
            .unwrap();
    }

    let prog: &mut UProbe = bpf
        .program_mut(prog_name)
        .unwrap_or_else(|| panic!("missing program {prog_name}"))
        .try_into()
        .unwrap_or_else(|err| panic!("program {prog_name} is not a uprobe: {err}"));
    prog.load()
        .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
    prog.attach(
        "trigger_lpm_trie",
        "/proc/self/exe",
        aya::programs::uprobe::UProbeScope::AllProcesses,
    )
    .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

    trigger_lpm_trie();

    let results = Array::<_, TestResult>::try_from(bpf.map(results_map).unwrap()).unwrap();

    let TestResult { ran, value } = results.get(&LPM_MATCH_SLOT, 0).unwrap();
    assert!(ran, "LPM-match probe did not run");
    assert_eq!(
        value, 7,
        "longest-prefix-match should return the /24 value, not the /16"
    );

    let TestResult { ran, value } = results.get(&NO_MATCH_SLOT, 0).unwrap();
    assert!(ran, "no-match probe did not run");
    assert_eq!(
        value, 0,
        "get() should return None for a key outside the trie"
    );

    let TestResult { ran, value } = results.get(&REMOVE_SLOT, 0).unwrap();
    assert!(ran, "after-remove probe did not run");
    assert_eq!(
        value, 42,
        "after removing the /24, longest-prefix-match should fall back to the /16"
    );
}
