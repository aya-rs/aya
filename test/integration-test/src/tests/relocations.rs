use anyhow::{Context, Result};
use std::{process::Command, thread::sleep, time::Duration};

use aya::{maps::Array, programs::TracePoint, BpfLoader, Btf, Endianness};

use super::{integration_test, IntegrationTest};

#[integration_test]
fn relocate_field() {
    let test = RelocationTest {
        local_definition: r#"
            struct foo {
              __u8 a;
              __u8 b;
              __u8 c;
              __u8 d;
            } __attribute__((preserve_access_index));
        "#,
        target_btf: r#"
            struct foo {
              __u8 a;
              __u8 c;
              __u8 b;
              __u8 d;
            } s1;
        "#,
        relocation_code: r#"
            __u8 memory[] = {1, 2, 3, 4};
            __u32 value = BPF_CORE_READ((struct foo *)&memory, c);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 2);
    assert_eq!(test.run_no_btf().unwrap(), 3);
}

#[integration_test]
fn relocate_enum() {
    let test = RelocationTest {
        local_definition: r#"
            enum foo { D = 1 };
        "#,
        target_btf: r#"
            enum foo { D = 4 } e1;
        "#,
        relocation_code: r#"
            __u32 value = bpf_core_enum_value(enum foo, D);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 4);
    assert_eq!(test.run_no_btf().unwrap(), 0);
}

#[integration_test]
fn relocate_pointer() {
    let test = RelocationTest {
        local_definition: r#"
            struct foo {};
            struct bar { struct foo *f; };
        "#,
        target_btf: r#""#,
        relocation_code: r#"
            __u8 memory[] = {0, 0, 0, 0, 0, 0, 0, 42};
            struct foo *f = BPF_CORE_READ((struct bar *)&memory, f);
            __u32 value = (f == (struct foo *) 42);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 1);
}

/// Utility code for running relocation tests:
/// - Generates the eBPF program using probided local definition and relocation code
/// - Generates the BTF from the target btf code
struct RelocationTest {
    /// Data structure definition, local to the eBPF program and embedded in the eBPF bytecode
    local_definition: &'static str,
    /// Target data structure definition. What the vmlinux would actually contain.
    target_btf: &'static str,
    /// Code executed by the eBPF program to test the relocation.
    /// The format should be:
    // __u8 memory[] = { ... };
    // __u32 value = BPF_CORE_READ((struct foo *)&memory, ...);
    //
    // The generated code will be executed by attaching a tracepoint to sched_switch
    // and emitting `__u32 value` an a map. See the code template below for more details.
    relocation_code: &'static str,
}

impl RelocationTest {
    /// Build a RelocationTestRunner
    fn build(&self) -> Result<RelocationTestRunner> {
        Ok(RelocationTestRunner {
            ebpf: self.build_ebpf()?,
            btf: self.build_btf()?,
        })
    }

    /// - Generate the source eBPF filling a template
    /// - Compile it with clang
    fn build_ebpf(&self) -> Result<Vec<u8>> {
        let local_definition = self.local_definition;
        let relocation_code = self.relocation_code;
        let tmp_dir = tempfile::tempdir().context("Error making temp dir")?;
        let ebpf_file = tmp_dir.path().join("ebpf_program.c");
        std::fs::write(
            &ebpf_file,
            format!(
                r#"
                    #include <linux/bpf.h>

                    #include <bpf/bpf_core_read.h>
                    #include <bpf/bpf_helpers.h>
                    #include <bpf/bpf_tracing.h>

                    {local_definition}

                    struct {{
                      __uint(type, BPF_MAP_TYPE_ARRAY);
                      __type(key, __u32);
                      __type(value, __u32);
                      __uint(max_entries, 1);
                    }} output_map SEC(".maps");

                    SEC("tracepoint/bpf_prog") int bpf_prog(void *ctx) {{
                      __u32 key = 0;
                      {relocation_code}
                      bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);
                      return 0;
                    }}

                    char _license[] SEC("license") = "GPL";
                "#
            ),
        )
        .context("Writing bpf program failed")?;
        Command::new("clang")
            .current_dir(tmp_dir.path())
            .args(["-c", "-g", "-O2", "-target", "bpf"])
            .args([
                "-I",
                &std::env::var("LIBBPF_INCLUDE").context("LIBBPF_INCLUDE not set")?,
            ])
            .arg(&ebpf_file)
            .status()
            .context("Failed to run clang")?
            .success()
            .then_some(())
            .context("Failed to compile eBPF program")?;
        let ebpf = std::fs::read(ebpf_file.with_extension("o"))
            .context("Error reading compiled eBPF program")?;
        Ok(ebpf)
    }

    /// - Generate the target BTF source with a mock main()
    /// - Compile it with clang
    /// - Extract the BTF with pahole
    fn build_btf(&self) -> Result<Btf> {
        let target_btf = self.target_btf;
        let tmp_dir = tempfile::tempdir().context("Error making temp dir")?;
        // BTF files can be generated and inspected with these commands:
        // $ clang -c -g -O2 -target bpf target.c
        // $ pahole --btf_encode_detached=target.btf -V target.o
        // $ bpftool btf dump file ./target.btf  format c
        let btf_file = tmp_dir.path().join("target_btf.c");
        std::fs::write(
            &btf_file,
            format!(
                r#"
                    #include <linux/types.h>
                    {target_btf}
                    int main() {{ return 0; }}
                "#
            ),
        )
        .context("Writing bpf program failed")?;
        Command::new("clang")
            .current_dir(tmp_dir.path())
            .args(["-c", "-g", "-O2", "-target", "bpf"])
            .arg(&btf_file)
            .status()
            .context("Failed to run clang")?
            .success()
            .then_some(())
            .context("Failed to compile BTF")?;
        Command::new("pahole")
            .current_dir(tmp_dir.path())
            .arg("--btf_encode_detached=target.btf")
            .arg(btf_file.with_extension("o"))
            .status()
            .context("Failed to run pahole")?
            .success()
            .then_some(())
            .context("Failed to extract BTF")?;
        let btf = Btf::parse_file(tmp_dir.path().join("target.btf"), Endianness::default())
            .context("Error parsing generated BTF")?;
        Ok(btf)
    }
}

struct RelocationTestRunner {
    ebpf: Vec<u8>,
    btf: Btf,
}

impl RelocationTestRunner {
    /// Run test and return the output value
    fn run(&self) -> Result<u32> {
        self.run_internal(true)
    }

    /// Run without loading btf
    fn run_no_btf(&self) -> Result<u32> {
        self.run_internal(false)
    }

    fn run_internal(&self, with_relocations: bool) -> Result<u32> {
        let mut loader = BpfLoader::new();
        if with_relocations {
            loader.btf(Some(&self.btf));
        }
        let mut bpf = loader.load(&self.ebpf).context("Loading eBPF failed")?;
        let program: &mut TracePoint = bpf
            .program_mut("bpf_prog")
            .context("bpf_prog not found")?
            .try_into()
            .context("program not a tracepoint")?;
        program.load().context("Loading tracepoint failed")?;
        // Attach to sched_switch and wait some time to make sure it executed at least once
        program
            .attach("sched", "sched_switch")
            .context("attach failed")?;
        sleep(Duration::from_millis(1000));
        // To inspect the loaded eBPF bytecode, increse the timeout and run:
        // $ sudo bpftool prog dump xlated name bpf_prog

        let output_map: Array<_, u32> = bpf.take_map("output_map").unwrap().try_into().unwrap();
        let key = 0;
        output_map.get(&key, 0).context("Getting key 0 failed")
    }
}
