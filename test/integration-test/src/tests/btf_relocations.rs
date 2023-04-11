use anyhow::{Context, Result};
use std::{path::PathBuf, process::Command, thread::sleep, time::Duration};
use tempfile::TempDir;

use aya::{maps::Array, programs::TracePoint, BpfLoader, Btf, Endianness};

use super::integration_test;

// In the tests below we often use values like 0xAAAAAAAA or -0x7AAAAAAA. Those values have no
// special meaning, they just have "nice" bit patterns that can be helpful while debugging.

#[integration_test]
fn relocate_field() {
    let test = RelocationTest {
        local_definition: r#"
            struct foo {
              __u8 a;
              __u8 b;
              __u8 c;
              __u8 d;
            };
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
            struct foo *ptr = (struct foo *) &memory;
            value = __builtin_preserve_access_index(ptr->c);
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
            enum foo { D = 0xAAAAAAAA };
        "#,
        target_btf: r#"
            enum foo { D = 0xBBBBBBBB } e1;
        "#,
        relocation_code: r#"
            #define BPF_ENUMVAL_VALUE 1
            value = __builtin_preserve_enum_value(*(typeof(enum foo) *)D, BPF_ENUMVAL_VALUE);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 0xBBBBBBBB);
    assert_eq!(test.run_no_btf().unwrap(), 0xAAAAAAAA);
}

#[integration_test]
fn relocate_enum_signed() {
    let test = RelocationTest {
        local_definition: r#"
            enum foo { D = -0x7AAAAAAA };
        "#,
        target_btf: r#"
            enum foo { D = -0x7BBBBBBB } e1;
        "#,
        relocation_code: r#"
            #define BPF_ENUMVAL_VALUE 1
            value = __builtin_preserve_enum_value(*(typeof(enum foo) *)D, BPF_ENUMVAL_VALUE);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap() as i64, -0x7BBBBBBBi64);
    assert_eq!(test.run_no_btf().unwrap() as i64, -0x7AAAAAAAi64);
}

#[integration_test]
fn relocate_enum64() {
    let test = RelocationTest {
        local_definition: r#"
            enum foo { D = 0xAAAAAAAABBBBBBBB };
        "#,
        target_btf: r#"
            enum foo { D = 0xCCCCCCCCDDDDDDDD } e1;
        "#,
        relocation_code: r#"
            #define BPF_ENUMVAL_VALUE 1
            value = __builtin_preserve_enum_value(*(typeof(enum foo) *)D, BPF_ENUMVAL_VALUE);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 0xCCCCCCCCDDDDDDDD);
    assert_eq!(test.run_no_btf().unwrap(), 0xAAAAAAAABBBBBBBB);
}

#[integration_test]
fn relocate_enum64_signed() {
    let test = RelocationTest {
        local_definition: r#"
            enum foo { D = -0xAAAAAAABBBBBBBB };
        "#,
        target_btf: r#"
            enum foo { D = -0xCCCCCCCDDDDDDDD } e1;
        "#,
        relocation_code: r#"
            #define BPF_ENUMVAL_VALUE 1
            value = __builtin_preserve_enum_value(*(typeof(enum foo) *)D, BPF_ENUMVAL_VALUE);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap() as i64, -0xCCCCCCCDDDDDDDDi64);
    assert_eq!(test.run_no_btf().unwrap() as i64, -0xAAAAAAABBBBBBBBi64);
}

#[integration_test]
fn relocate_pointer() {
    let test = RelocationTest {
        local_definition: r#"
            struct foo {};
            struct bar { struct foo *f; };
        "#,
        target_btf: r#"
            struct foo {};
            struct bar { struct foo *f; };
        "#,
        relocation_code: r#"
            __u8 memory[] = {42, 0, 0, 0, 0, 0, 0, 0};
            struct bar* ptr = (struct bar *) &memory;
            value = (__u64) __builtin_preserve_access_index(ptr->f);
        "#,
    }
    .build()
    .unwrap();
    assert_eq!(test.run().unwrap(), 42);
    assert_eq!(test.run_no_btf().unwrap(), 42);
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
        let (_tmp_dir, compiled_file) = compile(&format!(
            r#"
                #include <linux/bpf.h>

                static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

                {local_definition}

                struct {{
                  int (*type)[BPF_MAP_TYPE_ARRAY];
                  __u32 *key;
                  __u64 *value;
                  int (*max_entries)[1];
                }} output_map
                __attribute__((section(".maps"), used));

                __attribute__((section("tracepoint/bpf_prog"), used))
                int bpf_prog(void *ctx) {{
                  __u32 key = 0;
                  __u64 value = 0;
                  {relocation_code}
                  bpf_map_update_elem(&output_map, &key, &value, BPF_ANY);
                  return 0;
                }}

                char _license[] __attribute__((section("license"), used)) = "GPL";
            "#
        ))
        .context("Failed to compile eBPF program")?;
        let bytecode =
            std::fs::read(compiled_file).context("Error reading compiled eBPF program")?;
        Ok(bytecode)
    }

    /// - Generate the target BTF source with a mock main()
    /// - Compile it with clang
    /// - Extract the BTF with llvm-objcopy
    fn build_btf(&self) -> Result<Btf> {
        let target_btf = self.target_btf;
        let relocation_code = self.relocation_code;
        // BTF files can be generated and inspected with these commands:
        // $ clang -c -g -O2 -target bpf target.c
        // $ pahole --btf_encode_detached=target.btf -V target.o
        // $ bpftool btf dump file ./target.btf  format c
        let (tmp_dir, compiled_file) = compile(&format!(
            r#"
                #include <linux/bpf.h>

                {target_btf}
                int main() {{
                    __u64 value = 0;
                    // This is needed to make sure to emit BTF for the defined types,
                    // it could be dead code eliminated if we don't.
                    {relocation_code};
                    return value;
                }}
            "#
        ))
        .context("Failed to compile BTF")?;
        Command::new("llvm-objcopy")
            .current_dir(tmp_dir.path())
            .args(["--dump-section", ".BTF=target.btf"])
            .arg(compiled_file)
            .status()
            .context("Failed to run llvm-objcopy")?
            .success()
            .then_some(())
            .context("Failed to extract BTF")?;
        let btf = Btf::parse_file(tmp_dir.path().join("target.btf"), Endianness::default())
            .context("Error parsing generated BTF")?;
        Ok(btf)
    }
}

/// Compile an eBPF program and return the path of the compiled object.
/// Also returns a TempDir handler, dropping it will clear the created dicretory.
fn compile(source_code: &str) -> Result<(TempDir, PathBuf)> {
    let tmp_dir = tempfile::tempdir().context("Error making temp dir")?;
    let source = tmp_dir.path().join("source.c");
    std::fs::write(&source, source_code).context("Writing bpf program failed")?;
    Command::new("clang")
        .current_dir(&tmp_dir)
        .args(["-c", "-g", "-O2", "-target", "bpf"])
        .arg(&source)
        .status()
        .context("Failed to run clang")?
        .success()
        .then_some(())
        .context("Failed to compile eBPF source")?;
    Ok((tmp_dir, source.with_extension("o")))
}

struct RelocationTestRunner {
    ebpf: Vec<u8>,
    btf: Btf,
}

impl RelocationTestRunner {
    /// Run test and return the output value
    fn run(&self) -> Result<u64> {
        self.run_internal(true).context("Error running with BTF")
    }

    /// Run without loading btf
    fn run_no_btf(&self) -> Result<u64> {
        self.run_internal(false)
            .context("Error running without BTF")
    }

    fn run_internal(&self, with_relocations: bool) -> Result<u64> {
        let mut loader = BpfLoader::new();
        if with_relocations {
            loader.btf(Some(&self.btf));
        } else {
            loader.btf(None);
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

        let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
        let key = 0;
        output_map.get(&key, 0).context("Getting key 0 failed")
    }
}
