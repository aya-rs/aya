use anyhow::anyhow;
use std::path::PathBuf;

use aya_gen::{bindgen, write_to_file};

use crate::codegen::{Architecture, Options};

pub fn codegen(opts: &Options) -> Result<(), anyhow::Error> {
    codegen_internal_btf_bindings(opts)?;
    codegen_bindings(opts)
}

fn codegen_internal_btf_bindings(opts: &Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("aya");
    let generated = dir.join("src/generated");
    let mut bindgen = bindgen::user_builder()
        .clang_arg(format!(
            "-I{}",
            opts.libbpf_dir
                .join("include/uapi")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        ))
        .clang_arg(format!(
            "-I{}",
            opts.libbpf_dir
                .join("include")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        ))
        .header(
            opts.libbpf_dir
                .join("src/libbpf_internal.h")
                .to_string_lossy(),
        )
        .constified_enum_module("bpf_core_relo_kind");

    let types = ["bpf_core_relo", "btf_ext_header"];

    for x in &types {
        bindgen = bindgen.whitelist_type(x);
    }

    let bindings = bindgen
        .generate()
        .map_err(|_| anyhow!("bindgen failed"))?
        .to_string();

    // write the bindings, with the original helpers removed
    write_to_file(
        &generated.join("btf_internal_bindings.rs"),
        &bindings.to_string(),
    )?;

    Ok(())
}

fn codegen_bindings(opts: &Options) -> Result<(), anyhow::Error> {
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
        // PERF
        "perf_event_attr",
        "perf_sw_ids",
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
        "BPF_JMP",
        "BPF_CALL",
        "SO_ATTACH_BPF",
        "SO_DETACH_BPF",
        // BTF
        "BTF_KIND_.*",
        "BTF_INT_.*",
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
    ];

    let dir = PathBuf::from("aya");
    let generated = dir.join("src/generated");

    let builder = || {
        bindgen::user_builder()
            .header(dir.join("include/linux_wrapper.h").to_string_lossy())
            .clang_args(&[
                "-I",
                &*opts.libbpf_dir.join("include/uapi").to_string_lossy(),
            ])
            .clang_args(&["-I", &*opts.libbpf_dir.join("include").to_string_lossy()])
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        for x in &types {
            bindgen = bindgen.whitelist_type(x);
        }
        for x in &vars {
            bindgen = bindgen.whitelist_var(x);
        }

        // FIXME: this stuff is probably debian/ubuntu specific
        match arch {
            Architecture::X86_64 => {
                bindgen = bindgen.clang_args(&["-I", "/usr/include/x86_64-linux-gnu"]);
            }
            Architecture::ARMv7 => {
                bindgen = bindgen.clang_args(&["-I", "/usr/arm-linux-gnueabi/include"]);
            }
            Architecture::AArch64 => {
                bindgen = bindgen.clang_args(&["-I", "/usr/aarch64-linux-gnu/include"]);
            }
        };

        for x in &types {
            bindgen = bindgen.whitelist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.whitelist_var(x);
        }

        let bindings = bindgen
            .generate()
            .map_err(|_| anyhow!("bindgen failed"))?
            .to_string();

        // write the bindings, with the original helpers removed
        write_to_file(
            &generated.join(format!("linux_bindings_{}.rs", arch)),
            &bindings.to_string(),
        )?;
    }

    Ok(())
}
