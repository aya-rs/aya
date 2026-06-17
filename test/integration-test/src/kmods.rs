macro_rules! kmod {
    ($($uppercase:ident => $name:literal),* $(,)?) => {
        $(
            pub const $uppercase: &str = $name;
        )*
    };
}

kmod!(
    KMOD_AYA_KSYMS_TEST => "aya_ksyms_test",
);
