use aya::{
    Ebpf,
    maps::{Array, LpmTrie, lpm_trie::Key},
    programs::UProbe,
};
use integration_common::btf_lpm_trie::{LPM_MATCH_SLOT, NO_MATCH_SLOT, REMOVE_SLOT, TestResult};

#[test_log::test]
fn btf_lpm_trie() {
    let mut bpf = Ebpf::load(crate::BTF_LPM_TRIE).unwrap();

    {
        let mut routes: LpmTrie<_, [u8; 4], u32> =
            bpf.map_mut("ROUTES").unwrap().try_into().unwrap();
        // Insert a broad /16 and a more-specific /24. The probe also removes
        // the /24 to exercise LpmTrie::remove on the BTF side.
        routes
            .insert(&Key::new(16, [192, 168, 0, 0]), 42u32, 0)
            .unwrap();
        routes
            .insert(&Key::new(24, [192, 168, 1, 0]), 7u32, 0)
            .unwrap();
    }

    let prog: &mut UProbe = bpf
        .program_mut("test_btf_lpm_trie")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach("trigger_btf_lpm_trie", "/proc/self/exe", None)
        .unwrap();

    trigger_btf_lpm_trie();

    let results = Array::<_, TestResult>::try_from(bpf.map("RESULTS").unwrap()).unwrap();

    let lpm_match = results.get(&LPM_MATCH_SLOT, 0).unwrap();
    assert_eq!(lpm_match.ran, 1, "LPM-match probe did not run");
    assert_eq!(
        lpm_match.value, 7,
        "longest-prefix-match should return the /24 value, not the /16"
    );

    let no_match = results.get(&NO_MATCH_SLOT, 0).unwrap();
    assert_eq!(no_match.ran, 1, "no-match probe did not run");
    assert_eq!(
        no_match.value, 0,
        "get() should return None for a key outside the trie"
    );

    let after_remove = results.get(&REMOVE_SLOT, 0).unwrap();
    assert_eq!(after_remove.ran, 1, "after-remove probe did not run");
    assert_eq!(
        after_remove.value, 42,
        "after removing the /24, longest-prefix-match should fall back to the /16"
    );
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_lpm_trie() {
    core::hint::black_box(());
}
