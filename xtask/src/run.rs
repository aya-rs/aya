#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::print_stderr, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fmt::{Debug, Write as _},
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    ops::Deref as _,
    path::{self, Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context as _, Result, anyhow, bail};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;
use walkdir::WalkDir;
use xtask::{AYA_BUILD_INTEGRATION_BPF, Errors, libbpf_sys_env};

const GEN_INIT_CPIO_PATCH: &str = include_str!("../patches/gen_init_cpio.c.macos.diff");

#[derive(Parser)]
enum Environment {
    /// Runs the integration tests locally.
    Local {
        /// The command used to wrap your application.
        #[clap(short, long, default_value = "sudo -E")]
        runner: String,
    },
    /// Runs the integration tests in a VM.
    VM {
        /// The cache directory in which to store intermediate artifacts.
        #[clap(long)]
        cache_dir: PathBuf,

        /// The Github API token to use if network requests to Github are made.
        ///
        /// This may be required if Github rate limits are exceeded.
        #[clap(long)]
        github_api_token: Option<String>,

        /// Integration-test kernel modules to build and inject into the VM.
        ///
        /// The module source is resolved from test/integration-test/kmod/<name>.
        #[clap(long = "kmod")]
        kmods: Vec<String>,

        /// Kernel archives to boot in the VM.
        #[clap(required = true)]
        kernel_archives: Vec<PathBuf>,
    },
}

const INTEGRATION_TEST_PACKAGE: &str = "integration-test";

#[derive(Parser)]
pub(crate) struct Options {
    #[clap(subcommand)]
    environment: Environment,

    /// The package whose tests to build and run.
    #[clap(short = 'p', long, global = true, default_value = INTEGRATION_TEST_PACKAGE)]
    package: String,

    /// Arguments to pass to your application.
    #[clap(global = true, last = true)]
    run_args: Vec<OsString>,
}

pub(crate) fn build<F>(target: Option<&str>, f: F) -> Result<Vec<(String, PathBuf)>>
where
    F: FnOnce(&mut Command) -> &mut Command,
{
    // Always use rust-lld in case we're cross-compiling.
    let mut cargo = Command::new("cargo");
    cargo.args(["build", "--message-format=json"]);
    if let Some(target) = target {
        cargo.args(["--target", target]);
    }
    f(&mut cargo);

    let mut cargo_child = cargo
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cargo:?}"))?;
    let Child { stdout, .. } = &mut cargo_child;

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[expect(clippy::collapsible_match, reason = "better captures intent")]
        match message.context("valid JSON")? {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                if let Some(rendered) = message.rendered {
                    print!("{rendered}");
                }
            }
            Message::TextLine(line) => {
                println!("{line}");
            }
            _ => {}
        }
    }

    let status = cargo_child
        .wait()
        .with_context(|| format!("failed to wait for {cargo:?}"))?;
    if status.code() != Some(0) {
        bail!("{cargo:?} failed: {status:?}")
    }
    Ok(executables)
}

enum Disposition<T> {
    Skip,
    Unpack(T),
}

enum ControlFlow {
    Continue,
    Break,
}

fn with_deb<S, F>(archive: &Path, dest: &Path, mut state: S, mut select: F) -> Result<S>
where
    F: for<'state> FnMut(
        &'state mut S,
        &Path,
        tar::EntryType,
    ) -> Disposition<(Option<&'state mut Vec<PathBuf>>, ControlFlow)>,
{
    fs::create_dir_all(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    let archive_reader = File::open(archive)
        .with_context(|| format!("failed to open the deb package {}", archive.display()))?;
    let mut archive_reader = ar::Archive::new(archive_reader);
    // `ar` entries are borrowed from the reader, so the reader
    // cannot implement `Iterator` (because `Iterator::Item` is not
    // a GAT).
    //
    // https://github.com/mdsteele/rust-ar/issues/15
    let mut data_tar_xz_entries = 0;
    let start = std::time::Instant::now();
    while let Some(entry) = archive_reader.next_entry() {
        let entry = entry.with_context(|| format!("({}).next_entry()", archive.display()))?;
        const DATA_TAR_XZ: &str = "data.tar.xz";
        if entry.header().identifier() != DATA_TAR_XZ.as_bytes() {
            continue;
        }
        data_tar_xz_entries += 1;
        let entry_reader = xz2::read::XzDecoder::new(entry);
        let mut entry_reader = tar::Archive::new(entry_reader);
        let entries = entry_reader
            .entries()
            .with_context(|| format!("({}/{DATA_TAR_XZ}).entries()", archive.display()))?;
        for (i, entry) in entries.enumerate() {
            let mut entry = entry
                .with_context(|| format!("({}/{DATA_TAR_XZ}).entries()[{i}]", archive.display()))?;
            let path = entry.path().with_context(|| {
                format!(
                    "({}/{DATA_TAR_XZ}).entries()[{i}].path()",
                    archive.display()
                )
            })?;
            let entry_type = entry.header().entry_type();
            let (selected, control_flow) = match select(&mut state, path.as_ref(), entry_type) {
                Disposition::Skip => continue,
                Disposition::Unpack(unpack) => unpack,
            };
            if let Some(selected) = selected {
                println!(
                    "{}[{}] in {:?}",
                    archive.display(),
                    path.display(),
                    start.elapsed()
                );
                selected.push(dest.join(path));
            }
            let unpacked = entry.unpack_in(dest).with_context(|| {
                format!(
                    "({}/{DATA_TAR_XZ})[{i}].unpack_in({})",
                    archive.display(),
                    dest.display(),
                )
            })?;
            assert!(
                unpacked,
                "({}/{DATA_TAR_XZ})[{i}].unpack_in({})",
                archive.display(),
                dest.display(),
            );
            match control_flow {
                ControlFlow::Continue => {}
                ControlFlow::Break => break,
            }
        }
    }
    println!("{} in {:?}", archive.display(), start.elapsed());
    assert_eq!(data_tar_xz_entries, 1);
    Ok(state)
}

fn one<T: Debug>(slice: &[T]) -> Result<&T> {
    if let [item] = slice {
        Ok(item)
    } else {
        bail!("expected [{}], got {slice:?}", std::any::type_name::<T>())
    }
}

fn resolve_extracted_path(root: &Path, link: &Path) -> Result<PathBuf> {
    let target = fs::read_link(link).with_context(|| format!("read_link({})", link.display()))?;
    if target.is_absolute() {
        Ok(root.join(
            target
                .strip_prefix("/")
                .with_context(|| format!("strip absolute prefix from {}", target.display()))?,
        ))
    } else {
        Ok(link
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent", link.display()))?
            .join(target))
    }
}

struct KernelArtifacts {
    image_root: PathBuf,
    kernel_image: PathBuf,
    config: PathBuf,
    modules_dir: PathBuf,
    system_map: PathBuf,
    module_copy: ModuleCopy,
}

enum ModuleCopy {
    FullTree,
    TestDependencies,
}

const TEST_INITRAMFS_MODULES: &[&str] = &["cls_bpf", "sch_ingress"];

fn module_release(modules_dir: &Path) -> Result<String> {
    modules_dir
        .file_name()
        .ok_or_else(|| anyhow!("modules directory missing name: {}", modules_dir.display()))?
        .to_str()
        .ok_or_else(|| anyhow!("modules directory is not UTF-8: {}", modules_dir.display()))
        .map(ToOwned::to_owned)
}

fn module_build_dir(image_root: &Path, modules_dir: &Path) -> Result<PathBuf> {
    let build = modules_dir.join("build");
    match fs::symlink_metadata(&build) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            resolve_extracted_path(image_root, &build)
        }
        Ok(_) => Ok(build),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let release = module_release(modules_dir)?;
            for usr_src in [image_root.join("usr/src"), image_root.join("image/usr/src")] {
                let build_dir = usr_src.join(format!("linux-{release}"));
                if build_dir.exists() {
                    return Ok(build_dir);
                }
            }
            Err(err).with_context(|| format!("metadata({})", build.display()))
        }
        Err(err) => Err(err).with_context(|| format!("metadata({})", build.display())),
    }
}

fn is_gentoo_gpkg(archive: &Path) -> bool {
    archive
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.ends_with(".gpkg.tar"))
}

fn exists_nonempty(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len() != 0),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("metadata({})", path.display())),
    }
}

fn gentoo_kernel_image(image_root: &Path, build_dir: &Path) -> Result<PathBuf> {
    let arm64_image = build_dir.join("arch/arm64/boot/Image");
    if exists_nonempty(&arm64_image)? {
        return Ok(arm64_image);
    }

    let vmlinux = build_dir.join("vmlinux");
    if build_dir.join("arch/arm64").exists() {
        let image = image_root.join("gentoo-kernel-Image");
        // Gentoo's arm64 package has a complete vmlinux, but not always a
        // populated boot Image. QEMU needs the raw Image form.
        let mut objcopy = Command::new("llvm-objcopy");
        objcopy
            .args(["-O", "binary"])
            .args(["-R", ".note"])
            .args(["-R", ".note.gnu.build-id"])
            .args(["-R", ".comment"])
            .arg("-S")
            .arg(&vmlinux)
            .arg(&image);
        run_command(&mut objcopy)?;
        return Ok(image);
    }

    let x86_image = build_dir.join("arch/x86/boot/bzImage");
    if exists_nonempty(&x86_image)? {
        return Ok(x86_image);
    }

    Ok(vmlinux)
}

fn extract_gentoo_gpkg(archive: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    let archive_reader = File::open(archive)
        .with_context(|| format!("failed to open the gentoo package {}", archive.display()))?;
    let mut archive_reader = tar::Archive::new(archive_reader);
    let mut image_tar_xz_entries = 0;
    let start = std::time::Instant::now();

    for (outer_index, entry) in archive_reader.entries()?.enumerate() {
        let entry =
            entry.with_context(|| format!("({}).entries()[{outer_index}]", archive.display()))?;
        let path = entry
            .path()
            .with_context(|| format!("({}).entries()[{outer_index}].path()", archive.display()))?;
        if path.file_name() != Some(OsStr::new("image.tar.xz")) {
            continue;
        }

        image_tar_xz_entries += 1;
        let entry_reader = xz2::read::XzDecoder::new(entry);
        let mut entry_reader = tar::Archive::new(entry_reader);
        let entries = entry_reader
            .entries()
            .with_context(|| format!("({}/image.tar.xz).entries()", archive.display()))?;
        for (i, entry) in entries.enumerate() {
            let mut entry = entry
                .with_context(|| format!("({}/image.tar.xz).entries()[{i}]", archive.display()))?;
            let path = entry.path().with_context(|| {
                format!("({}/image.tar.xz).entries()[{i}].path()", archive.display())
            })?;
            let path = path.into_owned();
            if !path.starts_with("image/lib/modules") && !path.starts_with("image/usr/src") {
                continue;
            }

            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() && path.starts_with("image/lib/modules") {
                continue;
            }

            let out_path = dest.join(&path);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create_dir_all({})", parent.display()))?;
            }
            entry.unpack(&out_path).with_context(|| {
                format!(
                    "({}/image.tar.xz)[{i}].unpack({})",
                    archive.display(),
                    out_path.display(),
                )
            })?;
        }
    }

    println!("{} in {:?}", archive.display(), start.elapsed());
    anyhow::ensure!(
        image_tar_xz_entries == 1,
        "expected exactly one image.tar.xz in {}, found {image_tar_xz_entries}",
        archive.display()
    );
    Ok(())
}

fn gentoo_kernel_artifacts(archive: &Path, image_root: PathBuf) -> Result<KernelArtifacts> {
    extract_gentoo_gpkg(archive, &image_root)?;

    let modules_root = image_root.join("image/lib/modules");
    let modules_dirs = fs::read_dir(&modules_root)
        .with_context(|| format!("read_dir({})", modules_root.display()))?
        .map(|entry| {
            let entry = entry.with_context(|| format!("read_dir({})", modules_root.display()))?;
            let file_type = entry
                .file_type()
                .with_context(|| format!("file_type({})", entry.path().display()))?;
            Ok(file_type.is_dir().then_some(entry.path()))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let modules_dir = one(modules_dirs.as_slice())
        .with_context(|| format!("modules directory in {}", archive.display()))?
        .to_owned();
    let build_dir = module_build_dir(&image_root, &modules_dir)?;

    let kernel_image = gentoo_kernel_image(&image_root, &build_dir)?;
    let config = build_dir.join(".config");
    let system_map = build_dir.join("System.map");
    for path in [&kernel_image, &config, &system_map] {
        anyhow::ensure!(path.exists(), "{} does not exist", path.display());
    }

    Ok(KernelArtifacts {
        image_root,
        kernel_image,
        config,
        modules_dir,
        system_map,
        module_copy: ModuleCopy::TestDependencies,
    })
}

fn debian_kernel_artifacts(
    kernel_archive: &Path,
    debug_archive: &Path,
    image_root: PathBuf,
    debug_root: &Path,
) -> Result<KernelArtifacts> {
    let (kernel_images, configs, modules_dirs) = with_deb(
        kernel_archive,
        &image_root,
        (Vec::new(), Vec::new(), Vec::new()),
        |(kernel_images, configs, modules_dirs), path, entry_type| {
            if let Some(path) = ["./lib/modules/", "./usr/lib/modules/"]
                .into_iter()
                .find_map(|modules_dir| {
                    #[expect(clippy::manual_ok_err, reason = "type ascription")]
                    match path.strip_prefix(modules_dir) {
                        Ok(path) => Some(path),
                        Err(path::StripPrefixError { .. }) => None,
                    }
                })
            {
                return Disposition::Unpack((
                    (path.iter().count() == 1).then_some(modules_dirs),
                    ControlFlow::Continue,
                ));
            }
            if !entry_type.is_file() {
                return Disposition::Skip;
            }
            let name = match path.strip_prefix("./boot/") {
                Ok(path) => {
                    if let Some(path::Component::Normal(name)) = path.components().next() {
                        name
                    } else {
                        return Disposition::Skip;
                    }
                }
                Err(path::StripPrefixError { .. }) => return Disposition::Skip,
            };
            let name = name.as_encoded_bytes();
            if name.starts_with(b"vmlinuz-") {
                Disposition::Unpack((Some(kernel_images), ControlFlow::Continue))
            } else if name.starts_with(b"config-") {
                Disposition::Unpack((Some(configs), ControlFlow::Continue))
            } else {
                Disposition::Skip
            }
        },
    )?;
    let kernel_image = one(kernel_images.as_slice())
        .with_context(|| format!("kernel image in {}", kernel_archive.display()))?
        .to_owned();
    let config = one(configs.as_slice())
        .with_context(|| format!("config in {}", kernel_archive.display()))?
        .to_owned();
    let modules_dir = one(modules_dirs.as_slice())
        .with_context(|| format!("modules directory in {}", kernel_archive.display()))?
        .to_owned();

    let system_maps = with_deb(
        debug_archive,
        debug_root,
        Vec::new(),
        |system_maps: &mut Vec<PathBuf>, path, entry_type| {
            if entry_type != tar::EntryType::Regular {
                return Disposition::Skip;
            }
            let name = match path.strip_prefix("./usr/lib/debug/boot/") {
                Ok(path) => {
                    if let Some(path::Component::Normal(name)) = path.components().next() {
                        name
                    } else {
                        return Disposition::Skip;
                    }
                }
                Err(path::StripPrefixError { .. }) => return Disposition::Skip,
            };
            if name.as_encoded_bytes().starts_with(b"System.map-") {
                Disposition::Unpack((Some(system_maps), ControlFlow::Break))
            } else {
                Disposition::Skip
            }
        },
    )?;
    let system_map = one(system_maps.as_slice())
        .with_context(|| format!("System.map in {}", debug_archive.display()))?
        .to_owned();

    Ok(KernelArtifacts {
        image_root,
        kernel_image,
        config,
        modules_dir,
        system_map,
        module_copy: ModuleCopy::FullTree,
    })
}

fn run_command(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if status.code() == Some(0) {
        Ok(())
    } else {
        bail!("{cmd:?} failed: {status:?}")
    }
}

fn verify_ko_has_btf(ko: &Path) -> Result<()> {
    let output = Command::new("llvm-readelf")
        .arg("-S")
        .arg(ko)
        .output()
        .with_context(|| format!("failed to run llvm-readelf -S {}", ko.display()))?;
    if output.status.code() != Some(0) {
        bail!("llvm-readelf -S {} failed: {output:?}", ko.display());
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("invalid UTF-8 from llvm-readelf -S {}", ko.display()))?;
    anyhow::ensure!(
        stdout.contains(".BTF"),
        "{} does not contain a .BTF section",
        ko.display()
    );
    Ok(())
}

fn find_kernel_module(modules_dir: &Path, name: &str) -> Result<Option<PathBuf>> {
    let kernel_modules = modules_dir.join("kernel");
    if !kernel_modules.exists() {
        return Ok(None);
    }

    let module = format!("{name}.ko");
    let compressed_module = format!("{module}.xz");
    for entry in WalkDir::new(kernel_modules) {
        let entry = entry.context("read_dir failed")?;
        #[expect(
            clippy::filetype_is_file,
            reason = "we only want to match regular kernel module files"
        )]
        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if file_name == OsStr::new(&module) || file_name == OsStr::new(&compressed_module) {
            return Ok(Some(entry.into_path()));
        }
    }

    Ok(None)
}

fn module_initramfs_inputs(
    modules_dir: &Path,
    module_copy: ModuleCopy,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    match module_copy {
        ModuleCopy::FullTree => Ok((vec![modules_dir.to_owned()], Vec::new())),
        ModuleCopy::TestDependencies => {
            let mut module_roots = Vec::new();
            let extra_modules = modules_dir.join("kernel/extra");
            if extra_modules.exists() {
                module_roots.push(extra_modules);
            }

            let mut module_files = Vec::new();
            for module in TEST_INITRAMFS_MODULES {
                let module_file = find_kernel_module(modules_dir, module)?.ok_or_else(|| {
                    anyhow!(
                        "kernel module {module}.ko not found under {}",
                        modules_dir.display()
                    )
                })?;
                module_files.push(module_file);
            }

            let modules_alias = modules_dir.join("modules.alias");
            if modules_alias.exists() {
                module_files.push(modules_alias);
            }

            Ok((module_roots, module_files))
        }
    }
}

fn build_test_kmod(
    workspace_root: &Path,
    image_root: &Path,
    modules_dir: &Path,
    name: &str,
) -> Result<()> {
    let build_dir = module_build_dir(image_root, modules_dir)?;
    let build_vmlinux = build_dir.join("vmlinux");
    anyhow::ensure!(
        build_vmlinux.exists(),
        "--kmod requires {} to generate module BTF",
        build_vmlinux.display()
    );

    let work_dir = tempfile::tempdir().context("tempdir failed")?;
    let src_dir = workspace_root.join("test/integration-test/kmod").join(name);
    for entry in
        fs::read_dir(&src_dir).with_context(|| format!("read_dir({})", src_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read_dir({})", src_dir.display()))?;
        let metadata = entry
            .metadata()
            .with_context(|| format!("metadata({})", entry.path().display()))?;
        if metadata.is_file() {
            let dst = work_dir.path().join(entry.file_name());
            fs::copy(entry.path(), &dst)
                .with_context(|| format!("copy({}, {})", entry.path().display(), dst.display()))?;
        }
    }

    let mut make = Command::new("make");
    make.arg("-C")
        .arg(&build_dir)
        .arg(format!("M={}", work_dir.path().display()))
        .arg("PAHOLE_FLAGS=--btf_gen_all --btf_encode_force")
        // Gentoo's prebuilt kernel tree can carry newer module pahole flags or
        // compiler feature toggles than the local toolchain supports. Keep the
        // build portable, then verify .BTF exists before using the module.
        .arg("MODULE_PAHOLE_FLAGS=")
        .arg("CONFIG_CC_HAS_MIN_FUNCTION_ALIGNMENT=")
        .arg("modules");
    run_command(&mut make)?;

    let ko = work_dir.path().join(format!("{name}.ko"));
    verify_ko_has_btf(&ko)?;

    let dst_dir = modules_dir.join("kernel/extra");
    fs::create_dir_all(&dst_dir)
        .with_context(|| format!("create_dir_all({})", dst_dir.display()))?;
    let dst = dst_dir.join(format!("{name}.ko"));
    fs::copy(&ko, &dst).with_context(|| format!("copy({}, {})", ko.display(), dst.display()))?;

    Ok(())
}

fn build_test_kmods(
    workspace_root: &Path,
    image_root: &Path,
    modules_dir: &Path,
    guest_arch: &str,
    kmods: &[String],
) -> Result<()> {
    if kmods.is_empty() {
        return Ok(());
    }

    let host_arch = env::consts::ARCH;
    anyhow::ensure!(
        guest_arch == host_arch,
        "cannot build test kernel modules for guest architecture {guest_arch} on host architecture {host_arch}"
    );

    for kmod in kmods {
        let name = kmod.replace('-', "_");
        build_test_kmod(workspace_root, image_root, modules_dir, &name)
            .with_context(|| format!("failed to build test kernel module {name}"))?;
    }

    Ok(())
}

/// Build and run the project.
pub(crate) fn run(opts: Options, workspace_root: &Path) -> Result<()> {
    let Options {
        environment,
        package,
        run_args,
    } = opts;

    type Binary = (String, PathBuf);

    let binaries = |package: &str,
                    target: Option<&str>,
                    envs: &[(&OsStr, &OsStr)]|
     -> Result<Vec<(&'static str, Vec<Binary>)>> {
        ["dev", "release"]
            .into_iter()
            .map(|profile| {
                let binaries = build(target, |cmd| {
                    if package == INTEGRATION_TEST_PACKAGE {
                        cmd.env(AYA_BUILD_INTEGRATION_BPF, "true");
                        libbpf_sys_env(workspace_root, cmd);
                    }
                    cmd.envs(envs.iter().copied()).args([
                        "--package",
                        package,
                        "--tests",
                        "--profile",
                        profile,
                    ])
                })?;
                anyhow::Ok((profile, binaries))
            })
            .collect()
    };

    // Use --test-threads=1 to prevent tests from interacting with shared
    // kernel state due to the lack of inter-test isolation.
    let default_args = ["--test-threads=1"];
    let run_args = default_args
        .iter()
        .map(OsStr::new)
        .chain(run_args.iter().map(OsString::as_os_str));

    match environment {
        Environment::Local { runner } => {
            let mut args = runner.trim().split_terminator(' ');
            let runner = args.next().ok_or_else(|| anyhow!("no first argument"))?;

            let binaries = binaries(&package, None, &[])?;

            let mut failures = String::new();
            for (profile, binaries) in binaries {
                for (name, binary) in binaries {
                    let mut cmd = Command::new(runner);
                    cmd.args(args.clone())
                        .arg(binary)
                        .args(run_args.clone())
                        .env("RUST_BACKTRACE", "1")
                        .env("RUST_LOG", "debug");

                    println!("{profile}:{name} running {cmd:?}");

                    let status = cmd
                        .status()
                        .with_context(|| format!("failed to run {cmd:?}"))?;
                    if status.code() != Some(0) {
                        writeln!(&mut failures, "{profile}:{name} failed: {status:?}")
                            .context("String write failed")?
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(anyhow!("failures:\n{failures}"))
            }
        }
        Environment::VM {
            cache_dir,
            github_api_token,
            kmods,
            kernel_archives,
        } => {
            // The user has asked us to run the tests on a VM. This is involved; strap in.
            //
            // We need tools to build the initramfs; we use gen_init_cpio from the Linux repository,
            // taking care to cache it.
            //
            // We iterate the kernel images, using the `file` program to guess the target
            // architecture. We then build the init program and our test binaries for that
            // architecture, and use gen_init_cpio to build an initramfs containing the test
            // binaries. We're ready to run the VM.
            //
            // We start QEMU with the provided kernel image and the initramfs we built.
            //
            // We consume the output of QEMU, looking for the output of our init program. This is
            // the only way to distinguish success from failure. We batch up the errors across all
            // VM images and report to the user.
            //
            // The end.

            fs::create_dir_all(&cache_dir).context("failed to create cache dir")?;

            let gen_init_cpio = cache_dir.join("gen_init_cpio");
            {
                let dest_path = cache_dir.join("gen_init_cpio.c");
                let etag_path = cache_dir.join("gen_init_cpio.etag");
                let dest_path_exists = dest_path.try_exists().with_context(|| {
                    format!("failed to check existence of {}", dest_path.display())
                })?;
                let etag_path_exists = etag_path.try_exists().with_context(|| {
                    format!("failed to check existence of {}", etag_path.display())
                })?;
                if dest_path_exists != etag_path_exists {
                    println!(
                        "({}).exists()={} != ({})={} (mismatch)",
                        dest_path.display(),
                        dest_path_exists,
                        etag_path.display(),
                        etag_path_exists,
                    )
                }

                // Currently unused. Can be used for authenticated requests if needed in the future.
                drop(github_api_token);

                let mut curl = Command::new("curl");
                curl.args([
                    "-sfSL",
                    "https://raw.githubusercontent.com/torvalds/linux/master/usr/gen_init_cpio.c",
                    "--output",
                ])
                .arg(&dest_path);
                for arg in ["--etag-compare", "--etag-save"] {
                    curl.arg(arg).arg(&etag_path);
                }

                let output = curl
                    .output()
                    .with_context(|| format!("failed to run {curl:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    if dest_path_exists {
                        println!(
                            "{curl:?} failed ({status:?}); using cached {}",
                            dest_path.display()
                        );
                    } else {
                        bail!("{curl:?} failed: {output:?}")
                    }
                }

                let mut patch = Command::new("patch");
                patch
                    .current_dir(&cache_dir)
                    .args(["--quiet", "--forward", "--output", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped());
                let mut patch_child = patch
                    .spawn()
                    .with_context(|| format!("failed to spawn {patch:?}"))?;

                let Child { stdin, stdout, .. } = &mut patch_child;
                let mut stdin = stdin.take().unwrap();
                stdin
                    .write_all(GEN_INIT_CPIO_PATCH.as_bytes())
                    .with_context(|| format!("failed to write to {patch:?} stdin"))?;
                drop(stdin); // Must explicitly close to signal EOF.
                let stdout = stdout.take().unwrap();

                let mut clang = Command::new("clang");
                clang
                    .args(["-g", "-O2", "-x", "c", "-", "-o"])
                    .arg(&gen_init_cpio)
                    .stdin(stdout);
                let clang_child = clang
                    .spawn()
                    .with_context(|| format!("failed to spawn {clang:?}"))?;

                let output = patch_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {patch:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{patch:?} failed: {output:?}")
                }

                let output = clang_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {clang:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{clang:?} failed: {output:?}")
                }
            }

            let extraction_root = tempfile::tempdir().context("tempdir failed")?;

            #[derive(Eq, PartialEq, Ord, PartialOrd)]
            struct KernelPackageKey<'a> {
                base: &'a [u8],
            }

            #[derive(Default)]
            struct KernelPackageGroup<'a> {
                kernel: Vec<&'a Path>,
                debug: Vec<&'a Path>,
            }

            enum KernelPackage<'a> {
                Debian {
                    base: &'a OsStr,
                    kernel: &'a Path,
                    debug: &'a Path,
                },
                Gentoo {
                    archive: &'a Path,
                },
            }

            impl KernelPackage<'_> {
                fn artifacts(
                    self,
                    index: usize,
                    extraction_root: &Path,
                ) -> Result<KernelArtifacts> {
                    let image_root = extraction_root.join(format!("kernel-archive-{index}-image"));
                    match self {
                        KernelPackage::Debian {
                            base,
                            kernel,
                            debug,
                        } => debian_kernel_artifacts(
                            kernel,
                            debug,
                            image_root,
                            &extraction_root.join(format!("kernel-archive-{index}-debug")),
                        )
                        .with_context(|| {
                            format!("extracting Debian kernel package {}", base.display())
                        }),
                        KernelPackage::Gentoo { archive } => {
                            gentoo_kernel_artifacts(archive, image_root).with_context(|| {
                                format!("extracting Gentoo kernel package {}", archive.display())
                            })
                        }
                    }
                }
            }

            let mut package_groups = BTreeMap::new();
            let mut gentoo_archives = Vec::new();
            for archive in &kernel_archives {
                if is_gentoo_gpkg(archive) {
                    gentoo_archives.push(archive.as_path());
                    continue;
                }

                let file_name = archive.file_name().ok_or_else(|| {
                    anyhow!("archive path missing filename: {}", archive.display())
                })?;
                let file_name = file_name.as_encoded_bytes();
                // TODO(https://github.com/rust-lang/rust/issues/112811): use split_once when stable.
                let package_name = file_name
                    .split(|&byte| byte == b'_')
                    .next()
                    .ok_or_else(|| anyhow!("unexpected archive filename: {}", archive.display()))?;
                let (base, is_debug) = if let Some(base) = package_name.strip_suffix(b"-dbg") {
                    (base, true)
                } else if let Some(base) = package_name.strip_suffix(b"-dbgsym") {
                    (base, true)
                } else if let Some(base) = package_name.strip_suffix(b"-unsigned") {
                    (base, false)
                } else {
                    bail!("unexpected archive filename: {}", archive.display())
                };
                let KernelPackageGroup { kernel, debug } =
                    package_groups.entry(KernelPackageKey { base }).or_default();
                let dst = if is_debug { debug } else { kernel };
                dst.push(archive.as_path());
            }

            let mut kernel_packages = Vec::new();
            for (KernelPackageKey { base }, KernelPackageGroup { kernel, debug }) in package_groups
            {
                let base = {
                    use std::os::unix::ffi::OsStrExt as _;
                    OsStr::from_bytes(base)
                };
                kernel_packages.push(KernelPackage::Debian {
                    base,
                    kernel: one(kernel.as_slice())
                        .with_context(|| format!("kernel archive for {}", base.display()))?,
                    debug: one(debug.as_slice())
                        .with_context(|| format!("debug archive for {}", base.display()))?,
                });
            }
            kernel_packages.extend(
                gentoo_archives
                    .into_iter()
                    .map(|archive| KernelPackage::Gentoo { archive }),
            );

            let mut errors = Vec::new();
            for (index, kernel_package) in kernel_packages.into_iter().enumerate() {
                let KernelArtifacts {
                    image_root,
                    kernel_image,
                    config,
                    modules_dir,
                    system_map,
                    module_copy,
                } = kernel_package.artifacts(index, extraction_root.path())?;

                // Guess the guest architecture.
                let mut file = Command::new("file");
                let output = file
                    .arg("--brief")
                    .arg(&kernel_image)
                    .output()
                    .with_context(|| format!("failed to run {file:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{file:?} failed: {output:?}")
                }
                let Output { stdout, .. } = output;

                // Now parse the output of the file command, which looks something like
                //
                // - Linux kernel ARM64 boot executable Image, little-endian, 4K pages
                //
                // - Linux kernel x86 boot executable bzImage, version 6.1.0-10-cloud-amd64 [..]
                //
                // Gentoo packages provide vmlinux directly, which file(1) reports as an ELF.

                let stdout = String::from_utf8(stdout)
                    .with_context(|| format!("invalid UTF-8 in {file:?} stdout"))?;
                let guest_arch = if let Some((_, stdout)) = stdout.split_once("Linux kernel") {
                    let (guest_arch, _) = stdout
                        .split_once("boot executable")
                        .ok_or_else(|| anyhow!("failed to parse {file:?} stdout: {stdout}"))?;
                    guest_arch.trim()
                } else if stdout.contains("ARM aarch64") {
                    "ARM64"
                } else if stdout.contains("x86-64") {
                    "x86"
                } else {
                    bail!("failed to parse {file:?} stdout: {stdout}")
                };

                let (guest_arch, machine, cpu, console) = match guest_arch {
                    "ARM64" => (
                        "aarch64",
                        Some("virt"),
                        // NB: we'd prefer to write:
                        //
                        // ```
                        // Some(if cfg!(target_arch = "aarch64") {
                        //   "host"
                        // } else {
                        //   "neoverse-n1"
                        // }))
                        // ```
                        //
                        // but that only works in the presence of KVM or HVF and
                        // Github arm64 runners do not support nested
                        // virtualization. Since we aren't doing our own KVM/HVF
                        // detection (we let QEMU pick the best accelerator), we
                        // hardcode the emulated cpu.
                        //
                        // We use neoverse-n1 since it's relatively new but not
                        // too new. We used to use "max" and let QEMU pick the
                        // newest available cpu, until one day that triggered a
                        // QEMU bug that broke CI.
                        Some("neoverse-n1"),
                        "ttyAMA0",
                    ),
                    "x86" => (
                        "x86_64",
                        None,
                        cfg!(target_arch = "x86_64").then_some("host"),
                        "ttyS0",
                    ),
                    guest_arch => (guest_arch, None, None, "ttyS0"),
                };

                let target = format!("{guest_arch}-unknown-linux-musl");

                let test_distro_args =
                    ["--package", "test-distro", "--release", "--features", "xz2"];
                let test_distro: Vec<(String, PathBuf)> =
                    build(Some(&target), |cmd| cmd.args(test_distro_args))
                        .context("building test-distro package failed")?;

                // Set up cross compilation.
                //
                // See https://github.com/libbpf/libbpf-sys/issues/137.
                let mut extra;
                let envs: &[_] = if package == INTEGRATION_TEST_PACKAGE {
                    const LIBBPF_SYS_EXTRA_CFLAGS: &str = "LIBBPF_SYS_EXTRA_CFLAGS";
                    extra = OsString::new();
                    extra.push(format!(
                        "-idirafter /usr/include/{guest_arch}-linux-gnu -idirafter /usr/include",
                    ));
                    if guest_arch == "aarch64" {
                        extra.push(" -mno-outline-atomics");
                    }
                    if let Some(existing) = env::var_os(LIBBPF_SYS_EXTRA_CFLAGS) {
                        extra.push(" ");
                        extra.push(existing);
                    }
                    &[(OsStr::new(LIBBPF_SYS_EXTRA_CFLAGS), extra.as_os_str())]
                } else {
                    &[]
                };

                let binaries = binaries(&package, Some(&target), envs)?;

                let tmp_dir = tempfile::tempdir().context("tempdir failed")?;

                let initrd_image = tmp_dir.path().join("qemu-initramfs.img");
                let initrd_image_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&initrd_image)
                    .with_context(|| {
                        format!("failed to create {} for writing", initrd_image.display())
                    })?;

                let mut gen_init_cpio = Command::new(&gen_init_cpio);
                let mut gen_init_cpio_child = gen_init_cpio
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stdout(initrd_image_file)
                    .spawn()
                    .with_context(|| format!("failed to spawn {gen_init_cpio:?}"))?;
                let Child { stdin, .. } = &mut gen_init_cpio_child;
                let stdin = Arc::new(stdin.take().unwrap());
                use std::os::unix::ffi::OsStrExt as _;

                // Send input into gen_init_cpio for directories
                //
                // dir  /bin                  755 0 0
                let write_dir = |out_path: &Path| {
                    for bytes in [b"dir ", out_path.as_os_str().as_bytes(), b" ", b"755 0 0\n"] {
                        stdin.deref().write_all(bytes).expect("write");
                    }
                };

                // Send input into gen_init_cpio for files
                //
                // file /init    path-to-init 755 0 0
                let write_file = |out_path: &Path, in_path: &Path, mode: &str| {
                    for bytes in [
                        b"file ",
                        out_path.as_os_str().as_bytes(),
                        b" ",
                        in_path.as_os_str().as_bytes(),
                        b" ",
                        mode.as_bytes(),
                        b"\n",
                    ] {
                        stdin.deref().write_all(bytes).expect("write");
                    }
                };

                write_dir(Path::new("/bin"));
                write_dir(Path::new("/sbin"));
                write_dir(Path::new("/boot"));
                write_dir(Path::new("/lib"));
                write_dir(Path::new("/lib/modules"));

                write_file(Path::new("/boot/config"), &config, "644 0 0");
                if let Some(name) = config.file_name() {
                    write_file(&Path::new("/boot").join(name), &config, "644 0 0");
                }

                write_file(Path::new("/boot/System.map"), &system_map, "644 0 0");
                if let Some(name) = system_map.file_name() {
                    write_file(&Path::new("/boot").join(name), &system_map, "644 0 0");
                }

                for (name, path) in &test_distro {
                    if name == "init" {
                        write_file(Path::new("/init"), path, "755 0 0");
                    } else {
                        write_file(&Path::new("/sbin").join(name), path, "755 0 0");
                    }
                }

                build_test_kmods(
                    workspace_root,
                    &image_root,
                    &modules_dir,
                    guest_arch,
                    &kmods,
                )?;

                // At this point we need to make a slight detour!
                // Preparing the `modules.alias` file inside the VM as part of
                // `/init` is slow. It's faster to prepare it here.
                let mut cargo = Command::new("cargo");
                let output = cargo
                    .arg("run")
                    .args(test_distro_args)
                    .args(["--bin", "depmod", "--", "-b"])
                    .arg(&modules_dir)
                    .output()
                    .with_context(|| format!("failed to run {cargo:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{cargo:?} failed: {output:?}")
                }

                // Now our modules.alias file is built, we can recursively
                // walk the modules directory and add all the files to the initramfs.
                let (module_roots, module_files) =
                    module_initramfs_inputs(&modules_dir, module_copy)?;

                for module_root in module_roots {
                    for entry in WalkDir::new(&module_root) {
                        let entry = entry.context("read_dir failed")?;
                        let path = entry.path();
                        let metadata = entry.metadata().context("metadata failed")?;
                        let out_path = Path::new("/lib/modules").join(
                            path.strip_prefix(&modules_dir).with_context(|| {
                                format!(
                                    "strip prefix {} failed for {}",
                                    path.display(),
                                    modules_dir.display()
                                )
                            })?,
                        );
                        #[expect(
                            clippy::filetype_is_file,
                            reason = "we only want to copy regular files"
                        )]
                        if metadata.file_type().is_dir() {
                            write_dir(&out_path);
                        } else if metadata.file_type().is_file() {
                            write_file(&out_path, path, "644 0 0");
                        }
                    }
                }

                for module_file in module_files {
                    let out_path = Path::new("/lib/modules").join(
                        module_file.strip_prefix(&modules_dir).with_context(|| {
                            format!(
                                "strip prefix {} failed for {}",
                                modules_dir.display(),
                                module_file.display()
                            )
                        })?,
                    );
                    let mut parents = out_path.ancestors().skip(1).collect::<Vec<_>>();
                    parents.reverse();
                    for parent in parents {
                        if parent != Path::new("/") {
                            write_dir(parent);
                        }
                    }
                    write_file(&out_path, &module_file, "644 0 0");
                }

                for (profile, binaries) in binaries {
                    for (name, binary) in binaries {
                        let name = format!("{profile}-{name}");
                        let path = tmp_dir.path().join(&name);
                        fs::copy(&binary, &path).with_context(|| {
                            format!("copy({}, {}) failed", binary.display(), path.display())
                        })?;
                        let out_path = Path::new("/bin").join(&name);
                        write_file(&out_path, &path, "755 0 0");
                    }
                }

                // Must explicitly close to signal EOF.
                drop(stdin);

                let output = gen_init_cpio_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {gen_init_cpio:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{gen_init_cpio:?} failed: {output:?}")
                }

                let mut qemu = Command::new(format!("qemu-system-{guest_arch}"));
                if let Some(machine) = machine {
                    qemu.args(["-machine", machine]);
                }
                if let Some(cpu) = cpu {
                    qemu.args(["-cpu", cpu]);
                }
                for accel in ["kvm", "hvf", "tcg"] {
                    qemu.args(["-accel", accel]);
                }
                let console = OsStr::new(console);
                let mut kernel_args = std::iter::once(("console", console))
                    .chain(run_args.clone().map(|run_arg| ("init.arg", run_arg)))
                    .enumerate()
                    .fold(OsString::new(), |mut acc, (i, (k, v))| {
                        if i != 0 {
                            acc.push(" ");
                        }
                        acc.push(k);
                        acc.push("=");
                        acc.push(v);
                        acc
                    });
                // We sometimes see kernel panics containing:
                //
                // [    0.064000] Kernel panic - not syncing: IO-APIC + timer doesn't work!  Boot with apic=debug and send a report.  Then try booting with the 'noapic' option.
                //
                // Heed the advice and boot with noapic. We don't know why this happens.
                kernel_args.push(" noapic");
                // Activate BPF LSM so `#[lsm]` programs actually run their hooks.
                // Without this, `CONFIG_BPF_LSM=y` kernels still leave `bpf`
                // out of `/sys/kernel/security/lsm` and LSM tests exercise
                // only load/attach, missing runtime regressions.
                kernel_args.push(" lsm=bpf");
                qemu.args(["-no-reboot", "-nographic", "-m", "1024M", "-smp", "2"])
                    .arg("-append")
                    .arg(kernel_args)
                    .arg("-kernel")
                    .arg(&kernel_image)
                    .arg("-initrd")
                    .arg(&initrd_image);
                let mut qemu_child = qemu
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("failed to spawn {qemu:?}"))?;
                let Child {
                    stdin,
                    stdout,
                    stderr,
                    ..
                } = &mut qemu_child;
                let stdin = stdin.take().unwrap();
                let stdin = Arc::new(Mutex::new(stdin));
                let stdout = stdout.take().unwrap();
                let stdout = BufReader::new(stdout);
                let stderr = stderr.take().unwrap();
                let stderr = BufReader::new(stderr);

                const TERMINATE_AFTER_COUNT: &[(&str, usize)] = &[
                    ("end Kernel panic", 0),
                    ("rcu: RCU grace-period kthread stack dump:", 0),
                    ("watchdog: BUG: soft lockup", 1),
                ];
                let mut counts = [0; TERMINATE_AFTER_COUNT.len()];

                let mut terminate_if_kernel_hang =
                    move |line: &str, stdin: &Arc<Mutex<ChildStdin>>| -> Result<()> {
                        if let Some(i) = TERMINATE_AFTER_COUNT
                            .iter()
                            .position(|(marker, _)| line.contains(marker))
                        {
                            counts[i] += 1;

                            let (marker, max) = TERMINATE_AFTER_COUNT[i];
                            if counts[i] > max {
                                println!("{marker} detected > {max} times; terminating QEMU");
                                let mut stdin = stdin.lock().unwrap();
                                stdin
                                    .write_all(&[0x01, b'x'])
                                    .context("failed to write to stdin")?;
                                drop(stdin);
                                println!("waiting for QEMU to terminate");
                            }
                        }
                        Ok(())
                    };

                let stderr = {
                    let stdin = Arc::clone(&stdin);
                    thread::Builder::new()
                        .spawn(move || {
                            for line in stderr.lines() {
                                let line = line.context("failed to read line from stderr")?;
                                eprintln!("{line}");
                                terminate_if_kernel_hang(&line, &stdin)?;
                            }
                            anyhow::Ok(())
                        })
                        .unwrap()
                };

                let mut outcome = None;
                for line in stdout.lines() {
                    let line = line.context("failed to read line from stdout")?;
                    println!("{line}");
                    terminate_if_kernel_hang(&line, &stdin)?;
                    // The init program will print "init: success" or "init: failure" to indicate
                    // the outcome of running the binaries it found in /bin.
                    if let Some(line) = line.strip_prefix("init: ") {
                        let previous = match line {
                            "success" => outcome.replace(Ok(())),
                            "failure" => outcome.replace(Err(())),
                            line => bail!("unexpected init output: {line}"),
                        };
                        if let Some(previous) = previous {
                            bail!("multiple exit status: previous={previous:?}, current={line}");
                        }
                    }
                }

                let output = qemu_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {qemu:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{qemu:?} failed: {output:?}")
                }

                stderr.join().unwrap()?;

                let outcome = outcome.ok_or_else(|| anyhow!("init did not exit"))?;
                match outcome {
                    Ok(()) => {}
                    Err(()) => {
                        errors.push(anyhow!("VM binaries failed on {}", kernel_image.display()))
                    }
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Errors::new(errors).into())
            }
        }
    }
}
