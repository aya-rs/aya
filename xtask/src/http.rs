#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use ureq::http::StatusCode;

const USER_AGENT: &str = "aya-xtask";

pub(crate) struct HttpClient {
    agent: ureq::Agent,
}

impl HttpClient {
    pub(crate) fn new() -> Self {
        const REQUEST_PHASE_TIMEOUT: Duration = Duration::from_secs(30);
        const REQUEST_GLOBAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

        // Fail fast when request phases stall, but allow kernel module
        // packages enough end-to-end time to download on a cold cache.
        let config = ureq::Agent::config_builder()
            .timeout_resolve(Some(REQUEST_PHASE_TIMEOUT))
            .timeout_connect(Some(REQUEST_PHASE_TIMEOUT))
            .timeout_recv_response(Some(REQUEST_PHASE_TIMEOUT))
            // This is a body read/progress timeout, not a full download cap.
            .timeout_recv_body(Some(REQUEST_PHASE_TIMEOUT))
            .timeout_global(Some(REQUEST_GLOBAL_TIMEOUT))
            .build();
        Self {
            agent: config.into(),
        }
    }

    pub(crate) fn get_text(&self, url: &str) -> Result<String> {
        let mut response = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .with_context(|| format!("GET {url} failed"))?;
        response
            .body_mut()
            .read_to_string()
            .with_context(|| format!("read response body from {url} failed"))
    }

    pub(crate) fn download_to_dir(&self, url: &str, output_dir: &Path) -> Result<PathBuf> {
        let file_name = url_file_name(url)?;
        let dest_path = output_dir.join(file_name);
        let etag_path = output_dir.join(format!("{file_name}.etag"));
        self.download_to_path(url, &dest_path, &etag_path)?;
        Ok(dest_path)
    }

    pub(crate) fn download_to_path(
        &self,
        url: &str,
        dest_path: &Path,
        etag_path: &Path,
    ) -> Result<()> {
        let dest_path_exists = dest_path
            .try_exists()
            .with_context(|| format!("failed to check existence of {}", dest_path.display()))?;
        let etag_path_exists = etag_path
            .try_exists()
            .with_context(|| format!("failed to check existence of {}", etag_path.display()))?;
        // Treat cache/ETag mismatches as recoverable. A cached artifact without
        // an ETag can still be useful when the network is temporarily
        // unavailable, while a stale ETag without the artifact is ignored and
        // replaced by the next successful download. If a later successful
        // response omits ETag, the old ETag is removed below.
        if dest_path_exists != etag_path_exists {
            println!(
                "({}).exists()={} != ({})={} (mismatch)",
                dest_path.display(),
                dest_path_exists,
                etag_path.display(),
                etag_path_exists,
            )
        }

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut request = self.agent.get(url).header("User-Agent", USER_AGENT);
        if dest_path_exists {
            let etag = fs::read_to_string(etag_path).ok();
            if let Some(etag) = etag
                .as_deref()
                .map(str::trim)
                .filter(|etag| !etag.is_empty())
            {
                request = request.header("If-None-Match", etag);
            }
        }

        let mut response = match request.call() {
            Ok(response) => response,
            Err(error) => {
                if dest_path_exists {
                    // Keep cached artifacts usable when a later ETag
                    // revalidation hits a transient network failure.
                    println!(
                        "GET {url} failed ({error:?}); using cached {}",
                        dest_path.display()
                    );
                    return Ok(());
                }
                return Err(error).with_context(|| format!("GET {url} failed"));
            }
        };

        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            if dest_path_exists {
                println!(
                    "GET {url} returned 304; using cached {}",
                    dest_path.display()
                );
                return Ok(());
            }
            bail!(
                "GET {url} returned 304 but {} is missing",
                dest_path.display()
            );
        }
        if !status.is_success() {
            bail!("GET {url} returned HTTP status {status}");
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|etag| etag.to_str().ok())
            .map(ToOwned::to_owned);
        let tmp_path = {
            let file_name = dest_path.file_name().ok_or_else(|| {
                anyhow!(
                    "destination path {} is missing filename",
                    dest_path.display()
                )
            })?;
            let mut tmp_file_name = OsString::from(file_name);
            tmp_file_name.push(format!(".tmp-{}", std::process::id()));
            dest_path.with_file_name(tmp_file_name)
        };
        {
            let tmp = File::create(&tmp_path)
                .with_context(|| format!("failed to create {}", tmp_path.display()))?;
            let mut tmp = io::BufWriter::new(tmp);
            let mut body = response.body_mut().as_reader();
            io::copy(&mut body, &mut tmp)
                .with_context(|| format!("failed to download {url} to {}", tmp_path.display()))?;
            tmp.flush()
                .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
        }
        fs::rename(&tmp_path, dest_path).with_context(|| {
            format!(
                "failed to rename {} to {}",
                tmp_path.display(),
                dest_path.display()
            )
        })?;
        if let Some(etag) = etag {
            fs::write(etag_path, etag)
                .with_context(|| format!("failed to write {}", etag_path.display()))?;
        } else if let Err(error) = fs::remove_file(etag_path) {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error)
                    .with_context(|| format!("failed to remove {}", etag_path.display()));
            }
        }

        Ok(())
    }
}

pub(crate) fn url_file_name(url: &str) -> Result<&str> {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|file_name| !file_name.is_empty())
        .ok_or_else(|| anyhow!("URL has no filename: {url}"))
}
