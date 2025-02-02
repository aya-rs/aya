use std::{fs::File, io::BufRead as _, thread::sleep};

use aya::programs::tc;

use crate::utils::NetNsGuard;

// FIXME: Delete this test before merging.
// This is used to test the modprobe command inside the vm.
#[test]
fn modprobe() {
    let _netns = NetNsGuard::new();

    let res = tc::qdisc_add_clsact("lo");

    sleep(std::time::Duration::from_secs(1));

    // Need to read some kernel logs here to see if the module was loaded.
    let f = File::open("/modprobe.log").unwrap();
    let mut reader = std::io::BufReader::new(f);
    let mut line = String::new();
    loop {
        let bytes_read = reader.read_line(&mut line).unwrap();
        if bytes_read == 0 {
            break;
        }
        println!("{}", line);
        line.clear();
    }

    assert!(res.is_ok());
}
