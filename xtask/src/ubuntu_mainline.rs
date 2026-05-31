#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    borrow::Cow,
    collections::HashSet,
    ffi::{OsStr, OsString},
    fmt::Debug,
    fs::{self, File},
    io::{self, Read as _, Seek as _, SeekFrom},
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::{self, Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::ValueEnum;

use crate::http::{HttpClient, url_file_name};

// Ubuntu documents the Mainline archive as per-tag release directories
// containing generic/lowlatency kernel .deb packages.
// https://wiki.ubuntu.com/Kernel/MainlineBuilds
const UBUNTU_MAINLINE_URL: &str = "https://kernel.ubuntu.com/mainline/";
const UBUNTU_MAINLINE_IMAGE_PACKAGE_PREFIX: &str = "linux-image-unsigned-";
const UBUNTU_MAINLINE_MODULES_PACKAGE_PREFIX: &str = "linux-modules-";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum KernelArchitecture {
    Amd64,
    Arm64,
}

impl KernelArchitecture {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }
}

fn join_url<'a>(base_url: &'a str, href: &'a str) -> Cow<'a, str> {
    if href.starts_with('/') {
        if let Some(scheme_end) = base_url.find("://") {
            let host_start = scheme_end + "://".len();
            let origin_end = base_url[host_start..]
                .find('/')
                .map_or(base_url.len(), |index| host_start + index);
            return Cow::Owned(format!("{}{}", &base_url[..origin_end], href));
        }
    }

    match href.split_once("://") {
        Some(("http" | "https", _)) => Cow::Borrowed(href),
        _ => Cow::Owned(format!("{}/{}", base_url.trim_end_matches('/'), href)),
    }
}

fn html_tag_href(tag: &str) -> Option<&str> {
    let tag = tag.trim_start();
    let mut chars = tag.chars();
    if !chars.next()?.eq_ignore_ascii_case(&'a') {
        return None;
    }
    let mut rest = chars.as_str();
    if !rest
        .chars()
        .next()
        .is_none_or(|char| char.is_ascii_whitespace() || char == '>' || char == '/')
    {
        return None;
    }

    loop {
        rest = rest.trim_start();
        if rest.starts_with('>') || rest.starts_with('/') {
            return None;
        }

        let (name, after_name) = rest.split_once('=')?;
        let after_equals = after_name.trim_start();
        let quote = after_equals
            .chars()
            .next()
            .filter(|quote| *quote == '"' || *quote == '\'')?;
        let value = after_equals.strip_prefix(quote)?;
        let value_end = value.find(quote)?;
        if name.trim_end().eq_ignore_ascii_case("href") {
            return Some(&value[..value_end]);
        }
        rest = &value[value_end + quote.len_utf8()..];
    }
}

struct DirectoryListingUrls<'a> {
    html: String,
    url: &'a str,
}

impl<'a> DirectoryListingUrls<'a> {
    fn new(client: &HttpClient, url: &'a str) -> Result<Self> {
        let html = client.get_text(url)?;
        Ok(Self { html, url })
    }

    fn iter(&'a self) -> impl Iterator<Item = Cow<'a, str>> {
        let Self { html, url } = self;
        // The directory listings only need quoted hrefs, so avoid adding a full
        // HTML parser dependency to xtask for this narrow path.
        html.split('<')
            .filter_map(html_tag_href)
            .map(|href| join_url(url, href))
    }
}

struct UbuntuMainlineKernelUrls {
    base: String,
    image: String,
    modules: String,
}

fn ubuntu_mainline_kernel_urls(
    client: &HttpClient,
    version: &str,
    architecture: KernelArchitecture,
) -> Result<UbuntuMainlineKernelUrls> {
    const MAX_MAINLINE_BUILD_CANDIDATES: usize = 10;

    // For a line such as 6.6, select the newest v6.6.y build that has
    // packages for the requested architecture. Ubuntu may publish newer
    // release directories while architecture artifacts are still missing.
    // Check only a bounded number of recent builds so an unavailable LTS line
    // fails instead of degrading indefinitely.
    let mut mainline_versions = DirectoryListingUrls::new(client, UBUNTU_MAINLINE_URL)
        .context("failed to list Ubuntu Mainline releases")?
        .iter()
        .filter_map(|url| {
            let name = url_file_name(url.as_ref()).ok()?;
            let patch = name.strip_prefix(&format!("v{version}."))?;
            if !patch.chars().all(|char| char.is_ascii_digit()) {
                return None;
            }
            Some((patch.parse::<u64>().ok()?, name.to_owned()))
        })
        .collect::<Vec<_>>();
    mainline_versions.sort_by_key(|(patch, _)| *patch);

    let architecture = architecture.as_str();
    let mut skipped = Vec::new();
    for (_, mainline_version) in mainline_versions
        .into_iter()
        .rev()
        .take(MAX_MAINLINE_BUILD_CANDIDATES)
    {
        let release_url = format!("{UBUNTU_MAINLINE_URL}{mainline_version}/");
        let release_urls = DirectoryListingUrls::new(client, &release_url)
            .with_context(|| format!("failed to list Ubuntu Mainline release at {release_url}"))?;

        // Ubuntu stores each release under an architecture directory, for
        // example https://kernel.ubuntu.com/mainline/v6.6.100/amd64/.
        let base_url = format!("{release_url}{architecture}/");
        if !release_urls.iter().any(|url| url.as_ref() == base_url) {
            skipped.push(format!("{mainline_version} missing {architecture}/"));
            continue;
        }

        let urls = DirectoryListingUrls::new(client, &base_url)
            .with_context(|| format!("failed to list Ubuntu Mainline packages at {base_url}"))?;

        // The VM needs the unsigned image to boot and the matching modules
        // package for config, System.map, and the module tree. Keep both on
        // the generic flavor for the same release.
        let image_prefix = format!(
            "{UBUNTU_MAINLINE_IMAGE_PACKAGE_PREFIX}{}-",
            mainline_version.trim_start_matches('v')
        );
        let modules_prefix = format!(
            "{UBUNTU_MAINLINE_MODULES_PACKAGE_PREFIX}{}-",
            mainline_version.trim_start_matches('v')
        );

        let mut image_matches = Vec::new();
        let mut modules_matches = Vec::new();
        let package_suffix = format!("_{architecture}.deb");
        for url in urls.iter() {
            let Ok(file_name) = url_file_name(url.as_ref()) else {
                continue;
            };
            let Some((package_name, _)) = file_name.split_once('_') else {
                continue;
            };
            // Ubuntu Mainline documents generic and lowlatency kernel packages.
            // The VM runner uses generic packages, and the unsigned image package
            // must be paired with the matching generic modules package.
            // https://wiki.ubuntu.com/Kernel/MainlineBuilds
            if !package_name.ends_with("-generic") || !file_name.ends_with(&package_suffix) {
                continue;
            }

            if package_name.starts_with(&image_prefix) {
                image_matches.push(url);
            } else if package_name.starts_with(&modules_prefix) {
                modules_matches.push(url);
            }
        }

        let image = match image_matches.as_slice() {
            [url] => url.clone().into_owned(),
            [] => {
                skipped.push(format!("{mainline_version} missing generic image package"));
                continue;
            }
            urls => bail!("ambiguous Ubuntu Mainline packages matching {image_prefix}: {urls:?}"),
        };
        let modules = match modules_matches.as_slice() {
            [url] => url.clone().into_owned(),
            [] => {
                skipped.push(format!(
                    "{mainline_version} missing generic modules package"
                ));
                continue;
            }
            urls => bail!("ambiguous Ubuntu Mainline packages matching {modules_prefix}: {urls:?}"),
        };

        let image_file_name = url_file_name(&image)?;
        let (image_package_name, _) = image_file_name
            .split_once('_')
            .ok_or_else(|| anyhow!("unexpected Ubuntu Mainline image package URL: {image}"))?;
        let base = image_package_name
            .strip_prefix(UBUNTU_MAINLINE_IMAGE_PACKAGE_PREFIX)
            .ok_or_else(|| anyhow!("unexpected Ubuntu Mainline image package URL: {image}"))?
            .to_owned();

        if !skipped.is_empty() {
            println!(
                "selected Ubuntu Mainline {mainline_version} for {version} {architecture}; skipped newer incomplete builds: {}",
                skipped.join(", ")
            );
        }

        return Ok(UbuntuMainlineKernelUrls {
            base,
            image,
            modules,
        });
    }

    bail!(
        "failed to find Ubuntu Mainline build for {version} {architecture}; skipped candidates: {}",
        skipped.join(", ")
    )
}

struct UbuntuMainlineKernelArchives {
    base: String,
    image: PathBuf,
    modules: PathBuf,
}

fn download_ubuntu_mainline_kernel_archives(
    client: &HttpClient,
    cache_dir: &Path,
    architecture: KernelArchitecture,
    versions: &[String],
) -> Result<Vec<UbuntuMainlineKernelArchives>> {
    let output_dir = cache_dir
        .join("ubuntu-mainline-kernels")
        .join(architecture.as_str());
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let mut archives = Vec::new();
    let mut keep = HashSet::new();
    for version in versions {
        let urls = ubuntu_mainline_kernel_urls(client, version, architecture)
            .with_context(|| format!("failed to resolve Ubuntu Mainline kernel {version}"))?;
        let mut keep_archive = |archive: &Path| -> Result<()> {
            let file_name = archive
                .file_name()
                .ok_or_else(|| anyhow!("{} missing filename", archive.display()))?;
            let mut etag_file_name = OsString::from(file_name);
            etag_file_name.push(".etag");
            keep.insert(archive.with_file_name(etag_file_name));
            keep.insert(archive.to_path_buf());
            Ok(())
        };

        // ETag caching still revalidates each package over the network, so
        // VM runs require network access even when these files already exist.
        let image = client.download_to_dir(&urls.image, &output_dir)?;
        keep_archive(&image)?;
        let modules = client.download_to_dir(&urls.modules, &output_dir)?;
        keep_archive(&modules)?;
        archives.push(UbuntuMainlineKernelArchives {
            base: urls.base,
            image,
            modules,
        });
    }

    // Keep each CI cache key from accumulating old Mainline packages as
    // versions move forward. Locally, this means reusing the same cache dir for
    // separate runs of the same architecture only keeps the most recent run.
    for entry in fs::read_dir(&output_dir)
        .with_context(|| format!("failed to read {}", output_dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read {}", output_dir.display()))?;
        let path = entry.path();
        if path.is_file() && !keep.contains(&path) {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }

    Ok(archives)
}

enum Disposition<T> {
    Skip,
    Unpack(T),
}

fn with_deb<S, F>(archive: &Path, dest: &Path, mut state: S, mut select: F) -> Result<S>
where
    F: for<'state> FnMut(
        &'state mut S,
        &Path,
        tar::EntryType,
    ) -> Disposition<Option<&'state mut Vec<PathBuf>>>,
{
    fs::create_dir_all(dest).with_context(|| format!("failed to create {}", dest.display()))?;

    // deb(5): .deb files are ar archives, with installable files in data.tar.*.
    // https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html
    let archive_reader = File::open(archive)
        .with_context(|| format!("failed to open the deb package {}", archive.display()))?;
    let mut archive_reader = ar::Archive::new(archive_reader);
    // `ar` entries are borrowed from the reader, so the reader cannot
    // implement `Iterator` until iterator associated types can borrow `self`.
    // https://github.com/mdsteele/rust-ar/issues/15
    let mut data_tar_entries = 0;
    let start = std::time::Instant::now();
    while let Some(entry) = archive_reader.next_entry() {
        let entry = entry.with_context(|| format!("({}).next_entry()", archive.display()))?;
        let data_archive = match std::str::from_utf8(entry.header().identifier()) {
            Ok(data_archive) => data_archive.to_string(),
            Err(std::str::Utf8Error { .. }) => continue,
        };
        let entry_reader: Box<dyn io::Read> = match data_archive.as_str() {
            "data.tar" => Box::new(entry),
            "data.tar.xz" => Box::new(xz2::read::XzDecoder::new(entry)),
            "data.tar.zst" => Box::new(
                zstd::stream::read::Decoder::new(entry)
                    .with_context(|| format!("zstd decoder for {}", archive.display()))?,
            ),
            _ => continue,
        };
        data_tar_entries += 1;
        let mut entry_reader = tar::Archive::new(entry_reader);
        let entries = entry_reader
            .entries()
            .with_context(|| format!("({}/{data_archive}).entries()", archive.display()))?;
        for (i, entry) in entries.enumerate() {
            let mut entry = entry.with_context(|| {
                format!("({}/{data_archive}).entries()[{i}]", archive.display())
            })?;
            let path = entry.path().with_context(|| {
                format!(
                    "({}/{data_archive}).entries()[{i}].path()",
                    archive.display()
                )
            })?;
            let entry_type = entry.header().entry_type();
            let selected = match select(&mut state, path.as_ref(), entry_type) {
                Disposition::Skip => continue,
                Disposition::Unpack(selected) => selected,
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
                    "({}/{data_archive})[{i}].unpack_in({})",
                    archive.display(),
                    dest.display(),
                )
            })?;
            if !unpacked {
                bail!(
                    "({}/{data_archive})[{i}].unpack_in({}) extracted outside destination",
                    archive.display(),
                    dest.display(),
                );
            }
        }
    }
    println!("{} in {:?}", archive.display(), start.elapsed());
    if data_tar_entries != 1 {
        bail!(
            "{} has {data_tar_entries} data.tar entries, expected exactly one",
            archive.display()
        );
    }
    Ok(state)
}

// Require exactly one match; zero or multiple matches mean the package layout
// or filename rules are not precise enough.
fn one<T: Debug>(slice: &[T]) -> Result<&T> {
    if let [item] = slice {
        Ok(item)
    } else {
        bail!("expected [{}], got {slice:?}", std::any::type_name::<T>())
    }
}

#[derive(Default)]
struct KernelPackageContents {
    kernel_images: Vec<PathBuf>,
    configs: Vec<PathBuf>,
    modules_dirs: Vec<PathBuf>,
    system_maps: Vec<PathBuf>,
}

fn first_component_after<'a>(path: &'a Path, prefix: &str) -> Option<&'a OsStr> {
    let path = path.strip_prefix(prefix).ok()?;
    match path.components().next()? {
        path::Component::Normal(name) => Some(name),
        _ => None,
    }
}

// PE/COFF stores the PE header file offset at 0x3c, and the COFF
// header after the PE signature contains the machine type.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const PE_HEADER_OFFSET_OFFSET: u64 = 0x3c;
const PE_HEADER_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE_MACHINE_AARCH64: u16 = 0xaa64;
// EFI zboot is present in the current Ubuntu Mainline 6.1/6.6/6.12/6.18 LTS
// arm64 kernels we cover, and these fields have the same layout across those
// lines. Older 5.10/5.15 arm64 kernels do not carry this header; those fail the
// zimg check below and continue using the original kernel image.
// https://github.com/torvalds/linux/blob/v6.18/drivers/firmware/efi/libstub/zboot-header.S#L14-L30
const EFI_ZBOOT_MAGIC_OFFSET: usize = 0x04;
const EFI_ZBOOT_MAGIC: &[u8; 4] = b"zimg";
const EFI_ZBOOT_PAYLOAD_OFFSET_OFFSET: usize = 0x08;
const EFI_ZBOOT_PAYLOAD_SIZE_OFFSET: usize = 0x0c;
const EFI_ZBOOT_COMPRESSION_OFFSET: usize = 0x18;
const EFI_ZBOOT_COMPRESSION_LEN: usize = 0x20;
// arm64 Image header magic:
// https://github.com/torvalds/linux/blob/v6.18/arch/arm64/include/asm/image.h#L6-L43
const ARM64_IMAGE_MAGIC_OFFSET: usize = 0x38;
const ARM64_IMAGE_MAGIC: &[u8; 4] = b"ARMd";

fn read_exact_or_eof(file: &mut File, buf: &mut [u8]) -> Result<bool> {
    match file.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error).context("failed to read kernel image header"),
    }
}

#[expect(
    clippy::little_endian_bytes,
    reason = "PE/COFF header fields are defined as little-endian"
)]
fn is_aarch64_pe_image(path: &Path) -> Result<bool> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut mz = [0; 2];
    if !read_exact_or_eof(&mut file, &mut mz)? || mz != *b"MZ" {
        return Ok(false);
    }

    file.seek(SeekFrom::Start(PE_HEADER_OFFSET_OFFSET))?;
    let mut pe_offset = [0; 4];
    if !read_exact_or_eof(&mut file, &mut pe_offset)? {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(pe_offset);

    file.seek(SeekFrom::Start(u64::from(pe_offset)))?;
    let mut pe_header = [0; 6];
    if !read_exact_or_eof(&mut file, &mut pe_header)? {
        return Ok(false);
    }

    Ok(
        &pe_header[..PE_HEADER_SIGNATURE.len()] == PE_HEADER_SIGNATURE
            && u16::from_le_bytes([pe_header[4], pe_header[5]]) == PE_MACHINE_AARCH64,
    )
}

// Parsed subset of the EFI zboot header fields we need.
// https://github.com/torvalds/linux/blob/v6.18/drivers/firmware/efi/libstub/zboot-header.S#L14-L30
struct EfiZbootHeader<'a> {
    compression: &'a str,
    payload_offset: usize,
    payload: &'a [u8],
}

#[expect(
    clippy::little_endian_bytes,
    reason = "EFI zboot header fields are defined as little-endian"
)]
fn read_le_u32(image: &[u8], offset: usize, field: &str) -> Result<u32> {
    let bytes = image
        .get(offset..offset + size_of::<u32>())
        .with_context(|| format!("EFI zboot header missing {field}"))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("slice length was checked above"),
    ))
}

fn parse_efi_zboot_header(image: &[u8]) -> Result<Option<EfiZbootHeader<'_>>> {
    if image.get(EFI_ZBOOT_MAGIC_OFFSET..EFI_ZBOOT_MAGIC_OFFSET + EFI_ZBOOT_MAGIC.len())
        != Some(EFI_ZBOOT_MAGIC.as_slice())
    {
        return Ok(None);
    }

    let payload_offset = read_le_u32(image, EFI_ZBOOT_PAYLOAD_OFFSET_OFFSET, "payload offset")?;
    let payload_size = read_le_u32(image, EFI_ZBOOT_PAYLOAD_SIZE_OFFSET, "payload size")?;
    let payload_offset =
        usize::try_from(payload_offset).context("payload offset overflows usize")?;
    let payload_size = usize::try_from(payload_size).context("payload size overflows usize")?;
    let payload_end = payload_offset
        .checked_add(payload_size)
        .context("EFI zboot payload range overflows usize")?;
    let payload = image
        .get(payload_offset..payload_end)
        .with_context(|| format!("EFI zboot payload range {payload_offset}..{payload_end}"))?;

    let compression_bytes = image
        .get(EFI_ZBOOT_COMPRESSION_OFFSET..EFI_ZBOOT_COMPRESSION_OFFSET + EFI_ZBOOT_COMPRESSION_LEN)
        .context("EFI zboot header missing compression type")?;
    let compression_len = compression_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(compression_bytes.len());
    let compression = std::str::from_utf8(&compression_bytes[..compression_len])
        .context("EFI zboot compression type is not valid UTF-8")?;

    Ok(Some(EfiZbootHeader {
        compression,
        payload_offset,
        payload,
    }))
}

fn maybe_extract_qemu_arm64_image(kernel_image: &Path) -> Result<PathBuf> {
    // Keep this workaround narrow: QEMU -kernel handles x86/amd64 PE/COFF
    // bzImage files, but not the arm64 EFI zboot form handled below.
    if !is_aarch64_pe_image(kernel_image)? {
        return Ok(kernel_image.to_path_buf());
    }

    // Recent Ubuntu Mainline arm64 packages may ship /boot/vmlinuz-* as an
    // EFI zboot PE/COFF image. QEMU's -kernel path is not a full EFI boot
    // path, and the QEMU versions used by CI fail before the kernel starts
    // when that EFI zboot image uses zstd compression:
    //
    //   unable to handle EFI zboot image with "zstd" compression
    //
    // The VM runner still wants to use the simple -kernel path, so extract the
    // embedded raw arm64 Image and pass that to QEMU instead.
    let image = fs::read(kernel_image)
        .with_context(|| format!("failed to read {}", kernel_image.display()))?;
    let Some(zboot_header) = parse_efi_zboot_header(&image)? else {
        return Ok(kernel_image.to_path_buf());
    };
    if zboot_header.compression != "zstd" {
        bail!(
            "unsupported EFI zboot compression {:?} in {}",
            zboot_header.compression,
            kernel_image.display()
        );
    }

    let mut decoder = zstd::stream::read::Decoder::new(io::Cursor::new(zboot_header.payload))
        .context("failed to create zstd decoder for EFI zboot payload")?
        .single_frame();
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).with_context(|| {
        format!(
            "failed to decompress EFI zboot payload from {}",
            kernel_image.display()
        )
    })?;
    if decompressed
        .get(ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + ARM64_IMAGE_MAGIC.len())
        != Some(ARM64_IMAGE_MAGIC.as_slice())
    {
        bail!(
            "decompressed EFI zboot payload from {} is not a raw arm64 Image",
            kernel_image.display()
        );
    }

    let file_name = kernel_image.file_name().ok_or_else(|| {
        anyhow!(
            "kernel image path missing filename: {}",
            kernel_image.display()
        )
    })?;
    let file_name = file_name.as_encoded_bytes();
    let image_name = if let Some(version) = file_name.strip_prefix(b"vmlinuz-") {
        let mut image_name = b"Image-".to_vec();
        image_name.extend_from_slice(version);
        OsString::from_vec(image_name)
    } else {
        let mut image_name = OsString::from("Image-");
        image_name.push(OsStr::from_bytes(file_name));
        image_name
    };
    let output = kernel_image.with_file_name(image_name);
    fs::write(&output, decompressed)
        .with_context(|| format!("failed to write extracted arm64 Image {}", output.display()))?;
    println!(
        "extracted {} from {} EFI zboot zstd payload at offset {}",
        output.display(),
        kernel_image.display(),
        zboot_header.payload_offset
    );
    Ok(output)
}

fn unpack_ubuntu_mainline_image_package(
    archive: &Path,
    dest: &Path,
    contents: KernelPackageContents,
) -> Result<KernelPackageContents> {
    with_deb(archive, dest, contents, |contents, path, entry_type| {
        if !entry_type.is_file() {
            return Disposition::Skip;
        }

        if let Some(name) = first_component_after(path, "./boot/") {
            let name = name.as_encoded_bytes();
            if name.starts_with(b"vmlinuz-") {
                return Disposition::Unpack(Some(&mut contents.kernel_images));
            }
        }

        Disposition::Skip
    })
}

fn unpack_ubuntu_mainline_modules_package(
    archive: &Path,
    dest: &Path,
    contents: KernelPackageContents,
) -> Result<KernelPackageContents> {
    // Ubuntu Mainline linux-modules packages carry config, System.map, and
    // the module tree. Newer packages moved modules from /lib/modules to
    // /usr/lib/modules, so support both package layouts.
    // https://wiki.ubuntu.com/Kernel/MainlineBuilds
    with_deb(archive, dest, contents, |contents, path, entry_type| {
        for modules_dir in ["./lib/modules/", "./usr/lib/modules/"] {
            if let Ok(path) = path.strip_prefix(modules_dir) {
                return Disposition::Unpack(
                    (path.iter().count() == 1).then_some(&mut contents.modules_dirs),
                );
            }
        }

        if !entry_type.is_file() {
            return Disposition::Skip;
        }

        if let Some(name) = first_component_after(path, "./boot/") {
            let name = name.as_encoded_bytes();
            if name.starts_with(b"config-") {
                return Disposition::Unpack(Some(&mut contents.configs));
            } else if name.starts_with(b"System.map-") {
                return Disposition::Unpack(Some(&mut contents.system_maps));
            }
        }

        Disposition::Skip
    })
}

pub(crate) struct KernelPackage {
    pub(crate) base: PathBuf,
    pub(crate) kernel_image: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) modules_dir: PathBuf,
    pub(crate) system_map: PathBuf,
}

fn unpack_ubuntu_mainline_kernel_package(
    archives: &UbuntuMainlineKernelArchives,
    extraction_root: &Path,
    index: usize,
) -> Result<KernelPackage> {
    let base = PathBuf::from(&archives.base);

    // Ubuntu Mainline generic kernels are assembled from two packages:
    // linux-image-unsigned provides vmlinuz, while linux-modules provides
    // config, System.map, and modules.
    let contents = unpack_ubuntu_mainline_image_package(
        &archives.image,
        &extraction_root.join(format!("kernel-archive-{index}-image")),
        KernelPackageContents::default(),
    )
    .with_context(|| format!("failed to unpack image package for {}", base.display()))?;
    let contents = unpack_ubuntu_mainline_modules_package(
        &archives.modules,
        &extraction_root.join(format!("kernel-archive-{index}-modules")),
        contents,
    )
    .with_context(|| format!("failed to unpack modules package for {}", base.display()))?;

    let kernel_image = maybe_extract_qemu_arm64_image(
        one(contents.kernel_images.as_slice())
            .with_context(|| format!("kernel image for {}", base.display()))?,
    )?;

    Ok(KernelPackage {
        kernel_image,
        config: one(contents.configs.as_slice())
            .with_context(|| format!("config for {}", base.display()))?
            .clone(),
        modules_dir: one(contents.modules_dirs.as_slice())
            .with_context(|| format!("modules directory for {}", base.display()))?
            .clone(),
        system_map: one(contents.system_maps.as_slice())
            .with_context(|| format!("System.map for {}", base.display()))?
            .clone(),
        base,
    })
}

pub(crate) fn download_ubuntu_mainline_kernel_packages(
    client: &HttpClient,
    cache_dir: &Path,
    extraction_root: &Path,
    architecture: KernelArchitecture,
    versions: &[String],
) -> Result<Vec<KernelPackage>> {
    download_ubuntu_mainline_kernel_archives(client, cache_dir, architecture, versions)?
        .iter()
        .enumerate()
        .map(|(index, archives)| {
            unpack_ubuntu_mainline_kernel_package(archives, extraction_root, index)
        })
        .collect()
}
