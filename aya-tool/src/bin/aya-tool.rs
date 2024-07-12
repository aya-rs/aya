use std::{path::PathBuf, process::exit};

use aya::{create_bpf_filesystem, FilesystemPermissionsBuilder};
use aya_tool::generate::{generate, InputFile};
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
    #[clap(name = "create-fs", action)]
    CreateFs {
        #[clap(long, action)]
        path: PathBuf,
        #[clap(long, action, num_args(0..))]
        prog: Vec<String>,
        #[clap(long, action, num_args(0..))]
        map: Vec<String>,
        #[clap(long, action, num_args(0..))]
        attach: Vec<String>,
        #[clap(long, action)]
        uid: Option<u32>,
        #[clap(long, action)]
        gid: Option<u32>,
    },
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{e:#}");
        exit(1);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();
    match opts.command {
        Command::Generate {
            btf,
            header,
            names,
            bindgen_args,
        } => {
            let bindings: String = if let Some(header) = header {
                generate(InputFile::Header(header), &names, &bindgen_args)?
            } else {
                generate(InputFile::Btf(btf), &names, &bindgen_args)?
            };
            println!("{bindings}");
        }
        Command::CreateFs {
            path,
            prog: _,
            map: _,
            attach: _,
            uid,
            gid,
        } => {
            let mut perms = FilesystemPermissionsBuilder::default();
            if let Some(uid) = uid {
                perms.uid(uid);
            }
            if let Some(gid) = gid {
                perms.gid(gid);
            }
            let perms = perms.build();

            create_bpf_filesystem(path, perms)?;
        }
    };

    Ok(())
}
