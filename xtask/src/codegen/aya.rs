use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use aya_tool::bindgen;

use crate::codegen::{Architecture, SysrootOptions};

pub fn codegen(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<()> {
    codegen_internal_btf_bindings(libbpf_dir)?;
    codegen_bindings(opts, libbpf_dir)
}

fn codegen_internal_btf_bindings(libbpf_dir: &Path) -> Result<()> {
    let dir = PathBuf::from("aya-obj");
    let generated = dir.join("src/generated");

    let mut bindgen = bindgen::user_builder()
        .clang_args(["-I", libbpf_dir.join("include/uapi").to_str().unwrap()])
        .clang_args(["-I", libbpf_dir.join("include").to_str().unwrap()])
        .header(libbpf_dir.join("src/libbpf_internal.h").to_str().unwrap())
        .constified_enum_module("bpf_core_relo_kind");

    let types = ["bpf_core_relo", "btf_ext_header"];

    for x in &types {
        bindgen = bindgen.allowlist_type(x);
    }

    let bindings = bindgen.generate().context("bindgen failed")?;

    // write the bindings, with the original helpers removed
    bindings.write_to_file(generated.join("btf_internal_bindings.rs"))?;

    Ok(())
}

fn codegen_bindings(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<()> {
    let SysrootOptions {
        aarch64_sysroot,
        armv7_sysroot,
        loongarch64_sysroot,
        mips_sysroot,
        powerpc64_sysroot,
        riscv64_sysroot,
        s390x_sysroot,
        x86_64_sysroot,
    } = opts;
    let dir = PathBuf::from("aya-obj");
    let generated = dir.join("src/generated");
    create_dir_all(&generated)?;

    let builder = || {
        let mut bindgen = bindgen::user_builder()
            .header(dir.join("include/linux_wrapper.h").to_str().unwrap())
            .clang_args(["-I", libbpf_dir.join("include/uapi").to_str().unwrap()])
            .clang_args(["-I", libbpf_dir.join("include").to_str().unwrap()])
            // BPF_F_LINK is defined twice. Once in an anonymous enum
            // which bindgen will constify, and once via #define macro
            // which generates a duplicate const.
            .blocklist_var("BPF_F_LINK")
            .constified_enum("BPF_F_.*")
            .constified_enum("BTF_KIND_.*")
            .constified_enum("BTF_VAR_.*")
            .constified_enum("IFLA_.*")
            .constified_enum("TCA_.*")
            .constified_enum("BPF_RINGBUF_.*")
            // NETFILTER
            .constified_enum("NFPROTO_.*");

        let types = [
            // BPF
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
            "bpf_func_id",
            "bpf_func_info",
            "bpf_line_info",
            "bpf_lpm_trie_key",
            "bpf_cpumap_val",
            "bpf_devmap_val",
            "bpf_stats_type",
            "bpf_perf_event_type",
            "bpf_task_fd_type",
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
            "nlmsgerr_attrs",
            // ITER
            "bpf_cgroup_iter_order",
            // NETFILTER
            "nf_inet_hooks",
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
            "BPF_X",
            "BPF_DW",
            "BPF_W",
            "BPF_H",
            "BPF_B",
            "BPF_IMM",
            "BPF_MEM",
            "BPF_SUB",
            "BPF_MOV",
            "BPF_F_.*",
            "BPF_JMP",
            "BPF_CALL",
            "BPF_EXIT",
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
            // NETFILTER
            "NFPROTO_.*",
        ];

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        bindgen
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        // Set target triple. This will set the right flags (which you can see
        // running clang -target=X  -E - -dM </dev/null)
        let target = match arch {
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
            Architecture::ARMv7 => "armv7-unknown-linux-gnu",
            Architecture::LoongArch64 => "loongarch64-unknown-linux-gnu",
            Architecture::Mips => "mips-unknown-linux-gnu",
            Architecture::PowerPC64 => "powerpc64le-unknown-linux-gnu",
            Architecture::RISCV64 => "riscv64-unknown-linux-gnu",
            Architecture::S390X => "s390x-unknown-linux-gnu",
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
        };
        bindgen = bindgen.clang_args(&["-target", target]);

        // Set the sysroot. This is needed to ensure that the correct arch
        // specific headers are imported.
        let sysroot = match arch {
            Architecture::AArch64 => aarch64_sysroot,
            Architecture::ARMv7 => armv7_sysroot,
            Architecture::LoongArch64 => loongarch64_sysroot,
            Architecture::Mips => mips_sysroot,
            Architecture::PowerPC64 => powerpc64_sysroot,
            Architecture::RISCV64 => riscv64_sysroot,
            Architecture::S390X => s390x_sysroot,
            Architecture::X86_64 => x86_64_sysroot,
        };
        bindgen = bindgen.clang_args(["-I", sysroot.to_str().unwrap()]);

        let bindings = bindgen.generate().context("bindgen failed")?;

        // write the bindings, with the original helpers removed
        bindings.write_to_file(generated.join(format!("linux_bindings_{arch}.rs")))?;
    }

    Ok(())
}
