use std::cell::OnceCell;

pub fn workspace_root() -> &'static str {
    static mut WORKSPACE_ROOT: OnceCell<String> = OnceCell::new();
    unsafe { &mut WORKSPACE_ROOT }.get_or_init(|| {
        let cmd = cargo_metadata::MetadataCommand::new();
        cmd.exec().unwrap().workspace_root.to_string()
    })
}
