use std::path::{Path, PathBuf};

use anyhow::anyhow;
use aya_tool::{bindgen, write_to_file};

use crate::codegen::{Architecture, SysrootOptions};

pub fn codegen(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<(), anyhow::Error> {
    codegen_internal_btf_bindings(libbpf_dir)?;
    codegen_bindings(opts, libbpf_dir)
}

fn codegen_internal_btf_bindings(libbpf_dir: &Path) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("aya-obj");
    let generated = dir.join("src/generated");

    let mut bindgen = bindgen::user_builder()
        .clang_arg(format!(
            "-I{}",
            libbpf_dir
                .join("include/uapi")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        ))
        .clang_arg(format!(
            "-I{}",
            libbpf_dir
                .join("include")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        ))
        .header(libbpf_dir.join("src/libbpf_internal.h").to_string_lossy())
        .constified_enum_module("bpf_core_relo_kind");

    let types = ["bpf_core_relo", "btf_ext_header"];

    for x in &types {
        bindgen = bindgen.allowlist_type(x);
    }

    let bindings = bindgen
        .generate()
        .map_err(|op| anyhow!("bindgen failed - {op}"))?
        .to_string();

    // write the bindings, with the original helpers removed
    write_to_file(generated.join("btf_internal_bindings.rs"), &bindings)?;

    Ok(())
}

fn codegen_bindings(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<(), anyhow::Error> {
    let SysrootOptions {
        x86_64_sysroot,
        aarch64_sysroot,
        armv7_sysroot,
        riscv64_sysroot,
        powerpc64_sysroot,
        s390x_sysroot,
    } = opts;
    let types = [
        // BPF
        "BPF_TYPES",
        "bpf_cmd",
        "bpf_insn",
        "bpf_attr",
        "bpf_map_type",
        "bpf_prog_type",
        "bpf_attach_type",
        "bpf_prog_info",
        "bpf_map_info",
        "bpf_link_info",
        "bpf_link_type",
        "bpf_btf_info",
        "bpf_func_info",
        "bpf_line_info",
        "bpf_lpm_trie_key",
        "bpf_cpumap_val",
        "bpf_devmap_val",
        // BTF
        "btf_header",
        "btf_ext_info",
        "btf_ext_info_sec",
        "btf_type",
        "btf_enum",
        "btf_array",
        "btf_member",
        "btf_param",
        "btf_var",
        "btf_var_secinfo",
        "btf_func_linkage",
        "btf_decl_tag",
        // PERF
        "perf_event_attr",
        "perf_sw_ids",
        "perf_hw_id",
        "perf_hw_cache_id",
        "perf_hw_cache_op_id",
        "perf_hw_cache_op_result_id",
        "perf_event_sample_format",
        "perf_event_mmap_page",
        "perf_event_header",
        "perf_type_id",
        "perf_event_type",
        // NETLINK
        "ifinfomsg",
        "tcmsg",
    ];

    let vars = [
        // BPF
        "BPF_PSEUDO_.*",
        "BPF_ALU",
        "BPF_ALU64",
        "BPF_LDX",
        "BPF_ST",
        "BPF_STX",
        "BPF_LD",
        "BPF_K",
        "BPF_DW",
        "BPF_W",
        "BPF_H",
        "BPF_B",
        "BPF_F_.*",
        "BPF_JMP",
        "BPF_CALL",
        "SO_ATTACH_BPF",
        "SO_DETACH_BPF",
        // BTF
        "BTF_INT_.*",
        "BTF_KIND_.*",
        "BTF_VAR_.*",
        // PERF
        "PERF_FLAG_.*",
        "PERF_EVENT_.*",
        "PERF_MAX_.*",
        // see linux_wrapper.h, these are to workaround the IOC macros
        "AYA_PERF_EVENT_.*",
        // NETLINK
        "NLMSG_ALIGNTO",
        "IFLA_XDP_FD",
        "TCA_KIND",
        "TCA_OPTIONS",
        "TCA_BPF_FD",
        "TCA_BPF_NAME",
        "TCA_BPF_FLAGS",
        "TCA_BPF_FLAG_ACT_DIRECT",
        "XDP_FLAGS_.*",
        "TC_H_MAJ_MASK",
        "TC_H_MIN_MASK",
        "TC_H_UNSPEC",
        "TC_H_ROOT",
        "TC_H_INGRESS",
        "TC_H_CLSACT",
        "TC_H_MIN_PRIORITY",
        "TC_H_MIN_INGRESS",
        "TC_H_MIN_EGRESS",
        // Ringbuf
        "BPF_RINGBUF_.*",
    ];

    let dir = PathBuf::from("aya-obj");
    let generated = dir.join("src/generated");

    let builder = || {
        bindgen::user_builder()
            .header(dir.join("include/linux_wrapper.h").to_string_lossy())
            .clang_args(&["-I", &*libbpf_dir.join("include/uapi").to_string_lossy()])
            .clang_args(&["-I", &*libbpf_dir.join("include").to_string_lossy()])
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        // Set target triple. This will set the right flags (which you can see
        // running clang -target=X  -E - -dM </dev/null)
        let target = match arch {
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
            Architecture::ARMv7 => "armv7-unknown-linux-gnu",
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
            Architecture::RISCV64 => "riscv64-unknown-linux-gnu",
            Architecture::PowerPC64 => "powerpc64le-unknown-linux-gnu",
            Architecture::S390X => "s390x-unknown-linux-gnu",
        };
        bindgen = bindgen.clang_args(&["-target", target]);

        // Set the sysroot. This is needed to ensure that the correct arch
        // specific headers are imported.
        let sysroot = match arch {
            Architecture::X86_64 => x86_64_sysroot,
            Architecture::ARMv7 => armv7_sysroot,
            Architecture::AArch64 => aarch64_sysroot,
            Architecture::RISCV64 => riscv64_sysroot,
            Architecture::PowerPC64 => powerpc64_sysroot,
            Architecture::S390X => s390x_sysroot,
        };
        bindgen = bindgen.clang_args(&["-I", &*sysroot.to_string_lossy()]);

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }
        for x in &vars {
            bindgen = bindgen
                .allowlist_var(x)
                .constified_enum("BPF_F_.*")
                .constified_enum("BTF_KIND_.*")
                .constified_enum("BTF_VAR_.*")
                .constified_enum("IFLA_.*")
                .constified_enum("TCA_.*")
                .constified_enum("BPF_RINGBUF_.*");
        }

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        let bindings = bindgen
            .generate()
            .map_err(|op| anyhow!("bindgen failed - {op}"))?
            .to_string();

        // write the bindings, with the original helpers removed
        write_to_file(
            generated.join(format!("linux_bindings_{arch}.rs")),
            &bindings.to_string(),
        )?;
    }

    Ok(())
}
