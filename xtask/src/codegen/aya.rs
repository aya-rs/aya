use std::path::Path;

use anyhow::{Context as _, Result};
use aya_tool::bindgen;

use crate::Options;

pub(crate) fn codegen(opts: &Options, scratch: &Path) -> Result<()> {
    if let Some(output) = &opts.btf_output {
        codegen_internal_btf_bindings(opts, scratch, output)?;
    }
    codegen_bindings(opts, scratch)
}

fn codegen_internal_btf_bindings(opts: &Options, scratch: &Path, output: &Path) -> Result<()> {
    let mut bindgen = opts
        .builder(bindgen::user_builder(), scratch)
        .header(
            opts.libbpf_dir
                .join("src/libbpf_internal.h")
                .to_str()
                .unwrap(),
        )
        .constified_enum_module("bpf_core_relo_kind");

    let types = ["bpf_core_relo", "btf_ext_header"];

    for x in &types {
        bindgen = bindgen.allowlist_type(x);
    }

    let bindings = bindgen.generate().context("bindgen failed")?;

    // write the bindings, with the original helpers removed
    bindings.write_to_file(output)?;

    Ok(())
}

fn codegen_bindings(opts: &Options, scratch: &Path) -> Result<()> {
    let mut bindgen = opts
        .builder(bindgen::user_builder(), scratch)
        .header(opts.aya_header.to_str().unwrap())
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
        // PERF
        .constified_enum("HW_BREAKPOINT_.*")
        // NETFILTER
        .constified_enum("NFPROTO_.*");

    let types = [
        // BPF
        "bpf_cmd",
        "bpf_insn",
        "bpf_insn_array_value",
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
        "bpf_cgroup_storage_key",
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
        "perf_event_read_format",
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
        "BPF_.*",
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
        "HW_BREAKPOINT_.*",
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

    let bindings = bindgen.generate().context("bindgen failed")?;
    bindings.write_to_file(&opts.aya_output)?;

    Ok(())
}
