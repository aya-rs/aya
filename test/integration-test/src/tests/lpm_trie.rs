use aya::{
    Ebpf,
    maps::{Array, LpmTrie, lpm_trie::Key},
    programs::UProbe,
};
use integration_common::lpm_trie::{LPM_MATCH_SLOT, NO_MATCH_SLOT, REMOVE_SLOT, TestResult};

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_lpm_trie_btf() {
    core::hint::black_box(());
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_lpm_trie_legacy() {
    core::hint::black_box(());
}

#[test_log::test]
fn lpm_trie_basic() {
    let mut bpf = Ebpf::load(crate::LPM_TRIE).unwrap();

    for (variant, prog_name, symbol, routes_map, results_map) in [
        (
            "btf",
            "test_btf_lpm_trie",
            "trigger_lpm_trie_btf",
            "ROUTES",
            "RESULTS",
        ),
        (
            "legacy",
            "test_lpm_trie_legacy",
            "trigger_lpm_trie_legacy",
            "ROUTES_LEGACY",
            "RESULTS_LEGACY",
        ),
    ] {
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
            .unwrap_or_else(|_| panic!("program {prog_name} is not a uprobe"));
        prog.load()
            .unwrap_or_else(|err| panic!("load {prog_name}: {err}"));
        prog.attach(symbol, "/proc/self/exe", None)
            .unwrap_or_else(|err| panic!("attach {prog_name}: {err}"));

        if variant == "btf" {
            trigger_lpm_trie_btf();
        } else {
            trigger_lpm_trie_legacy();
        }

        let results = Array::<_, TestResult>::try_from(bpf.map(results_map).unwrap()).unwrap();

        let lpm_match = results.get(&LPM_MATCH_SLOT, 0).unwrap();
        assert_eq!(lpm_match.ran, 1, "{variant}: LPM-match probe did not run");
        assert_eq!(
            lpm_match.value, 7,
            "{variant}: longest-prefix-match should return the /24 value, not the /16"
        );

        let no_match = results.get(&NO_MATCH_SLOT, 0).unwrap();
        assert_eq!(no_match.ran, 1, "{variant}: no-match probe did not run");
        assert_eq!(
            no_match.value, 0,
            "{variant}: get() should return None for a key outside the trie"
        );

        let after_remove = results.get(&REMOVE_SLOT, 0).unwrap();
        assert_eq!(
            after_remove.ran, 1,
            "{variant}: after-remove probe did not run"
        );
        assert_eq!(
            after_remove.value, 42,
            "{variant}: after removing the /24, longest-prefix-match should fall back to the /16"
        );
    }
}
