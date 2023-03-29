use std::process::Command;

pub(crate) struct DummyInterface;

impl DummyInterface {
    pub const TEST_DUMMY: &str = "aya-dummy";

    pub fn new() -> Self {
        let output = Command::new("ip")
            .args(["link", "add", Self::TEST_DUMMY, "type", "dummy"])
            .output()
            .expect("failed to run ip command");

        assert!(output.status.success());
        Self
    }
}

impl Drop for DummyInterface {
    fn drop(&mut self) {
        let output = Command::new("ip")
            .args(["link", "del", Self::TEST_DUMMY])
            .output()
            .expect("failed to run ip command");
        assert!(output.status.success())
    }
}
