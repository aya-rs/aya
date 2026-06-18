//! Download kernel images and debug packages from the Debian mirror.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use regex::Regex;

/// Options for the `download-kernel-images` subcommand.
#[derive(Debug, clap::Args)]
#[command(about = "Download kernel images and debug packages from the Debian mirror")]
pub(crate) struct Options {
    /// Output directory for downloaded files.
    pub output_dir: PathBuf,
    /// Target architecture (e.g. "x86_64", "arm64").
    pub architecture: String,
    /// Kernel versions to download (e.g. "6.1", "6.6").
    pub versions: Vec<String>,
}

/// URL of the Debian mirror directory listing.
const MIRROR_URL: &str = "http://ftp.hk.debian.org/debian/pool/main/l/linux/";

/// Run the download kernel images command.
pub(crate) fn run(opts: Options) -> Result<()> {
    let Options {
        output_dir,
        architecture,
        versions,
    } = opts;

    if versions.is_empty() {
        bail!("at least one kernel version is required");
    }

    // Fetch the directory listing from the mirror.
    let text = ureq::get(MIRROR_URL)
        .call()
        .with_context(|| format!("failed to fetch {MIRROR_URL}"))?
        .into_string()
        .with_context(|| format!("failed to read response from {MIRROR_URL}"))?;

    // Extract URLs from <a href="..."> tags in the HTML directory listing.
    let re = Regex::new(r#"<a href="([^"]+)">"#)?;
    let urls: Vec<_> = re
        .captures_iter(&text)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();

    // Ensure the output directory exists.
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create output directory {output_dir:?}"))?;

    // Find the latest revision of each kernel version.
    for version in &versions {
        let image_regex = format!(
            r"linux-image-{version}\.[0-9]+(-[0-9]+)?(\+bpo|\+deb[0-9]+)?-cloud-{architecture}-unsigned_.*\.deb"
        );
        let image_match = find_latest(&urls, &image_regex)
            .with_context(|| format!("failed to find image package for version {version}"))?;

        // The debug package contains the actual System.map. Debian has transitioned
        // between -dbg and -dbgsym suffixes, so match either for the specific kernel
        // we just selected.
        let kernel_basename = image_match.rsplit('/').next().unwrap();
        let kernel_prefix = kernel_basename.split('_').next().unwrap();
        let kernel_suffix = kernel_basename
            .strip_prefix(&format!("{kernel_prefix}_"))
            .unwrap_or(kernel_basename);
        let base_prefix = kernel_prefix
            .strip_suffix("-unsigned")
            .unwrap_or(kernel_prefix);

        let debug_regex = format!(r"{base_prefix}-dbg(sym)?_{kernel_suffix}");
        let debug_match = find_latest(&urls, &debug_regex).with_context(|| {
            format!("failed to locate debug package matching {kernel_basename}")
        })?;

        for file_name in [image_match, debug_match] {
            let etag_name = format!("{file_name}.etag");

            let etag_path = output_dir.join(&etag_name);
            let etag = fs::read_to_string(&etag_path).ok();

            let file_url = format!("{MIRROR_URL}/{file_name}");

            let mut builder = ureq::get(&file_url);
            if let Some(ref etag) = etag {
                builder = builder.set("If-None-Match", etag);
            }
            let response = builder.call().ok();

            if let Some(ref resp) = response {
                if resp.status() == 304 {
                    // Not modified — keep existing file.
                    continue;
                }
            }

            // 200 OK or no previous etag — download the file.
            let response = response.ok_or_else(|| anyhow::anyhow!("failed to fetch {file_url}"))?;

            let etag = response.header("ETag").map(|e| e.to_string());

            let mut body = Vec::new();
            response
                .into_reader()
                .read_to_end(&mut body)
                .with_context(|| format!("failed to read response body for {file_name}"))?;
            fs::write(output_dir.join(&file_name), &body)
                .with_context(|| format!("failed to write {file_name}"))?;

            if let Some(etag) = etag {
                fs::write(&etag_path, etag)
                    .with_context(|| format!("failed to write etag for {file_name}"))?;
            }
        }
    }

    Ok(())
}

/// Find the latest matching file in the listing using regex.
fn find_latest(urls: &[String], regex: &str) -> Option<String> {
    let re = Regex::new(regex).ok()?;
    let matches: Vec<&str> = urls
        .iter()
        .filter_map(|url| {
            let trimmed = url.trim();
            if re.is_match(trimmed) {
                Some(trimmed)
            } else {
                None
            }
        })
        .collect();

    if matches.is_empty() {
        return None;
    }

    // Sort by version string and take the last (latest) match.
    let mut sorted = matches;
    sorted.sort_by(|a, b| {
        let a_name = a.rsplit('/').next().unwrap();
        let b_name = b.rsplit('/').next().unwrap();
        version_compare(a_name, b_name)
    });
    sorted.last().map(|s| s.to_string())
}

/// Compare two version strings (e.g., "6.1.0-1" vs "6.1.0-2").
/// Uses lexical comparison on the version portion.
fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    // Extract the version part (after the last underscore, before the dash or end).
    let a_ver = a.rsplit('-').next().unwrap_or(a).to_string();
    let b_ver = b.rsplit('-').next().unwrap_or(b).to_string();

    // Try numeric comparison first for each segment.
    let a_parts: Vec<&str> = a_ver.split('.').collect();
    let b_parts: Vec<&str> = b_ver.split('.').collect();
    let max_len = a_parts.len().max(b_parts.len());

    for i in 0..max_len {
        let a_num = a_parts.get(i).and_then(|s| s.parse::<u64>().ok());
        let b_num = b_parts.get(i).and_then(|s| s.parse::<u64>().ok());

        match (a_num, b_num) {
            (Some(a_n), Some(b_n)) => {
                if a_n != b_n {
                    return a_n.cmp(&b_n);
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => {}
        }
    }

    // Fall back to lexical comparison.
    a_ver.cmp(&b_ver)
}
