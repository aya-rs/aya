#![expect(unused_crate_dependencies, reason = "used in lib")]

use std::path::PathBuf;

use aya::token::{FilesystemPermissionsBuilder, create_bpf_filesystem};
use aya_obj::cmd::BpfCommand;
use aya_tool::generate::{InputFile, generate};
use clap::Parser;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Generate Rust bindings to Kernel types using bpftool
    #[clap(name = "generate", action)]
    Generate {
        #[clap(long, default_value = "/sys/kernel/btf/vmlinux", action)]
        btf: PathBuf,
        #[clap(long, conflicts_with = "btf", action)]
        header: Option<PathBuf>,
        #[clap(action)]
        names: Vec<String>,
        #[clap(last = true, action)]
        bindgen_args: Vec<String>,
    },
    /// Create a BPF filesystem with token delegation options
    #[clap(name = "create-fs", action)]
    CreateFs {
        /// Path to mount the BPF filesystem
        #[clap(long, action)]
        path: PathBuf,
        /// Allowed program types (unused, reserved for future use)
        #[clap(long, action, num_args(0..))]
        prog: Vec<String>,
        /// Allowed map types (unused, reserved for future use)
        #[clap(long, action, num_args(0..))]
        map: Vec<String>,
        /// Allowed attach types (unused, reserved for future use)
        #[clap(long, action, num_args(0..))]
        attach: Vec<String>,
        /// Owner UID
        #[clap(long, action)]
        uid: Option<u32>,
        /// Owner GID
        #[clap(long, action)]
        gid: Option<u32>,
    },
}

fn main() -> Result<(), anyhow::Error> {
    use std::io::Write as _;

    let Options { command } = Parser::parse();
    match command {
        Command::Generate {
            btf,
            header,
            names,
            bindgen_args,
        } => {
            let bindings = if let Some(header) = header {
                generate(InputFile::Header(header), &names, &bindgen_args)
            } else {
                generate(InputFile::Btf(btf), &names, &bindgen_args)
            }?;
            std::io::stdout().write_all(bindings.as_bytes())?;
        }
        Command::CreateFs {
            path,
            prog: _,
            map: _,
            attach: _,
            uid,
            gid,
        } => {
            // Build permissions with common defaults for token usage.
            let mut builder = FilesystemPermissionsBuilder::default()
                .allow_cmd(BpfCommand::MapCreate)
                .allow_cmd(BpfCommand::ProgLoad)
                .allow_cmd(BpfCommand::BtfLoad)
                .allow_cmd(BpfCommand::MapGetNextId)
                .allow_cmd(BpfCommand::ProgGetNextId)
                .allow_cmd(BpfCommand::ObjGetInfoByFd)
                .allow_cmd(BpfCommand::ProgGetFdById)
                .allow_cmd(BpfCommand::MapGetFdById)
                .allow_cmd(BpfCommand::ObjPin)
                .allow_cmd(BpfCommand::ObjGet)
                .allow_cmd(BpfCommand::TokenCreate);

            if let Some(uid) = uid {
                builder = builder.uid(uid);
            }
            if let Some(gid) = gid {
                builder = builder.gid(gid);
            }

            create_bpf_filesystem(path, builder.build())?;
        }
    };

    Ok(())
}
