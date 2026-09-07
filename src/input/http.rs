use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::extract::writer::write_all_at;
use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;
use crate::payload::header::{HEADER_SIZE, MAGIC, PayloadHeader};
use crate::proto::DeltaArchiveManifest;
use crate::style;

use super::ZIP_MAGIC;
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CD_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];

/// Default User-Agent
const DEFAULT_USER_AGENT: &str =
    "Dalvik/2.1.0 (Linux; V; Android 16; Android Build/BP2A.250605.015)";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DownloadState {
    url: String,
    meta_hash: String,
    total_size: u64,
    ranges: Vec<RangeState>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RangeState {
    remote_offset: u64,
    file_base: u64,
    length: u64,
    downloaded: u64,
}

struct TempDownloadGuard {
    partial_path: PathBuf,
    state_path: PathBuf,
    success: Arc<AtomicBool>,
}

impl Drop for TempDownloadGuard {
    fn drop(&mut self) {
        if self.success.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&self.partial_path);
            let _ = std::fs::remove_file(&self.state_path);
        }
    }
}

fn compute_cache_key(url: &str, partition_names: &[String]) -> String {
    let mut sorted_parts = partition_names.to_vec();
    sorted_parts.sort();
    let key = format!("{url}:{}", sorted_parts.join(","));
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(&digest[..8])
}

fn save_download_state(state_path: &Path, state: &DownloadState) -> Result<()> {
    let json = serde_json::to_string(state).context("failed to serialize download state")?;
    let tmp_path = state_path.with_extension("state.tmp");
    std::fs::write(&tmp_path, json.as_bytes()).context("failed to write temp download state")?;
    std::fs::rename(&tmp_path, state_path).context("failed to commit download state")?;
    Ok(())
}

fn load_download_state(state_path: &Path) -> Result<Option<DownloadState>> {
    if !state_path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(state_path).context("failed to read download state")?;
    match serde_json::from_str::<DownloadState>(&data) {
        Ok(state) => Ok(Some(state)),
        Err(_) => Ok(None),
    }
}

fn build_client(insecure: bool, user_agent: Option<&str>) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .user_agent(user_agent.unwrap_or(DEFAULT_USER_AGENT))
        .timeout(Duration::from_secs(3600))
        .connect_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(4)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .context("failed to build HTTP client")
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().context("failed to create tokio runtime")
}

/// Download a byte range fully into memory. Used for small reads (header,
/// manifest, ZIP central directory, LFH). Large selective-download ranges go
/// through [`range_download_to_file`] instead, which streams to disk.
async fn range_download(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    use futures::StreamExt;

    let end = offset + length - 1;
    let mut buf = Vec::with_capacity(length as usize);
    let mut consecutive_errors = 0u32;
    const MAX_RETRIES: u32 = 10;

    while (buf.len() as u64) < length {
        let curr_offset = offset + buf.len() as u64;
        let resp_result = client
            .get(url)
            .header("Range", format!("bytes={curr_offset}-{end}"))
            .send()
            .await;

        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors > MAX_RETRIES {
                    return Err(e).context("max retries exceeded");
                }
                let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let mut stream = resp.bytes_stream();
            let mut read_this_attempt = 0;
            let mut stream_err = None;

            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => {
                        let needed = length as usize - buf.len();
                        let take = needed.min(chunk.len());
                        buf.extend_from_slice(&chunk[..take]);
                        read_this_attempt += take;
                        if buf.len() as u64 == length {
                            break;
                        }
                    }
                    Err(e) => {
                        stream_err = Some(e);
                        break;
                    }
                }
            }

            if read_this_attempt > 0 {
                consecutive_errors = 0;
            }

            if buf.len() as u64 == length {
                return Ok(buf);
            }

            consecutive_errors += 1;
            if consecutive_errors > MAX_RETRIES {
                if let Some(e) = stream_err {
                    return Err(e).context("stream error");
                }
                bail!("short read for range {offset}-{end}");
            }
            let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            continue;
        }

        if status.is_success() {
            // 200 fallback: stream only requested bytes to prevent OOM
            let mut stream = resp.bytes_stream();
            let mut to_skip = curr_offset;
            let mut to_read = (length as usize).saturating_sub(buf.len());
            let mut read_this_attempt = 0;
            let mut stream_err = None;

            while to_read > 0 {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let mut chunk = &chunk[..];
                        if to_skip > 0 {
                            let skip = (to_skip as usize).min(chunk.len());
                            to_skip -= skip as u64;
                            chunk = &chunk[skip..];
                        }
                        if !chunk.is_empty() {
                            let take = chunk.len().min(to_read);
                            buf.extend_from_slice(&chunk[..take]);
                            to_read -= take;
                            read_this_attempt += take;
                        }
                    }
                    Some(Err(e)) => {
                        stream_err = Some(e);
                        break;
                    }
                    None => break,
                }
            }

            if read_this_attempt > 0 {
                consecutive_errors = 0;
            }

            if buf.len() as u64 == length {
                return Ok(buf);
            }

            consecutive_errors += 1;
            if consecutive_errors > MAX_RETRIES {
                if let Some(e) = stream_err {
                    return Err(e).context("stream error");
                }
                bail!("short read (HTTP 200) for range {offset}-{end}");
            }
            let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            continue;
        }

        let retry_after_secs = if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
        } else {
            None
        };

        consecutive_errors += 1;
        if consecutive_errors > MAX_RETRIES {
            bail!("HTTP {status} for range {curr_offset}-{end}");
        }
        let backoff = if let Some(secs) = retry_after_secs {
            (secs * 1000).min(60_000)
        } else {
            (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000)
        };
        tokio::time::sleep(Duration::from_millis(backoff)).await;
    }

    Ok(buf)
}

async fn detect_payload_offset(client: &reqwest::Client, url: &str) -> Result<u64> {
    let (total_size, head) = fetch_total_size_and_head(client, url).await?;

    if head.len() >= 4 && &head[..4] == MAGIC {
        return Ok(0);
    }
    if head.len() < 4 || &head[..4] != ZIP_MAGIC {
        bail!(
            "unrecognized format (magic: {:02x?})",
            &head[..4.min(head.len())]
        );
    }

    eprintln!(
        "{} ({})...",
        style::label().apply_to("Parsing remote ZIP"),
        style::format_size(total_size)
    );
    let cd = fetch_zip_cd(client, url, total_size).await?;
    let entry = find_cd_entry(&cd, "payload.bin").context("payload.bin not found in remote ZIP")?;

    let lfh = range_download(client, url, entry.local_off, 30).await?;
    let n = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
    let e = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
    Ok(entry.local_off + 30 + n + e)
}

pub fn open_http_metadata(
    url: &str,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<PayloadView> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure, user_agent)?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len).await?;

        Ok(PayloadView::from_memory(meta, HashMap::new())?)
    })
}

pub fn open_http_extract(
    url: &str,
    partition_names: &[String],
    opts: &super::OpenOptions,
) -> Result<PayloadView> {
    use std::sync::Arc;

    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(opts.insecure, opts.user_agent.as_deref())?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len).await?;

        let manifest = DeltaArchiveManifest::decode(
            &meta[HEADER_SIZE..HEADER_SIZE + header.manifest_size as usize],
        )?;
        let data_offset = header.data_offset();

        let parts: Vec<_> = manifest
            .partitions
            .iter()
            .filter(|p| {
                if !partition_names.is_empty()
                    && !partition_names.iter().any(|n| n == &p.partition_name)
                {
                    return false;
                }
                if opts
                    .exclude
                    .as_ref()
                    .is_some_and(|exc| exc.iter().any(|n| n == &p.partition_name))
                {
                    return false;
                }
                true
            })
            .collect();
        if parts.is_empty() && (!partition_names.is_empty() || opts.exclude.is_some()) {
            bail!("none of the specified partitions found");
        }

        // Validate source partitions for delta OTA BEFORE downloading any data!
        let has_delta_ops = parts
            .iter()
            .any(|p| crate::extract::partition_has_delta_ops(p));
        if has_delta_ops {
            let Some(ref src_dir) = opts.source_dir else {
                bail!(
                    "this is a delta/incremental OTA payload — \
                     source partition directory is required (use --source-dir)"
                );
            };
            crate::extract::validate_source_partitions(&parts, src_dir)?;
        }

        let mut op_ranges: Vec<(u64, u64)> = Vec::new();
        for p in &parts {
            for op in &p.operations {
                let off = op.data_offset.unwrap_or(0);
                let len = op.data_length.unwrap_or(0);
                if len > 0 {
                    op_ranges.push((off, len));
                }
            }
        }

        if op_ranges.is_empty() {
            return Ok(PayloadView::from_memory(meta, HashMap::new())?);
        }

        op_ranges.sort_by_key(|r| r.0);
        op_ranges.dedup();

        let merged = merge_ranges(&op_ranges);
        let total_data: u64 = merged.iter().map(|r| r.1).sum();
        style::log(
            "Selective download",
            format_args!("{} ({} range(s))", style::format_size(total_data), merged.len()),
        );

        // Plan the compact temp-file layout: [meta][range0][range1]…
        let (total_size, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        let cache_key = compute_cache_key(url, partition_names);
        let temp_dir = opts
            .temp_dir
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create temp dir '{}'", temp_dir.display()))?;

        let partial_path = temp_dir.join(format!(".payload_{cache_key}.part"));
        let state_path = temp_dir.join(format!(".payload_{cache_key}.state"));

        let meta_hash = hex::encode(Sha256::digest(&meta));

        let can_resume = if opts.resume && partial_path.exists() {
            if let Ok(Some(saved)) = load_download_state(&state_path) {
                saved.url == url
                    && saved.meta_hash == meta_hash
                    && saved.total_size == total_size
                    && saved.ranges.len() == merged.len()
                    && saved.ranges.iter().enumerate().all(|(i, r)| {
                        r.remote_offset == payload_off + data_offset + merged[i].0
                            && r.file_base == bases[i]
                            && r.length == merged[i].1
                            && r.downloaded <= r.length
                    })
                    && std::fs::metadata(&partial_path)
                        .map(|m| m.len() >= total_size)
                        .unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        };

        let (file, mut state, initial_downloaded) = if can_resume {
            let saved_state = load_download_state(&state_path)?.unwrap();
            let initial_done: u64 = saved_state.ranges.iter().map(|r| r.downloaded).sum();
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&partial_path)
                .context("failed to open existing partial payload file")?;
            (f, saved_state, initial_done)
        } else {
            if partial_path.exists() {
                let _ = std::fs::remove_file(&partial_path);
            }
            if state_path.exists() {
                let _ = std::fs::remove_file(&state_path);
            }
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&partial_path)
                .context("failed to create partial payload file")?;
            f.set_len(total_size)
                .context("failed to size partial payload file")?;

            write_all_at(&f, &meta, 0).context("partial file write metadata failed")?;

            let new_state = DownloadState {
                url: url.to_string(),
                meta_hash,
                total_size,
                ranges: merged
                    .iter()
                    .enumerate()
                    .map(|(i, &(data_region_off, length))| RangeState {
                        remote_offset: payload_off + data_offset + data_region_off,
                        file_base: bases[i],
                        length,
                        downloaded: 0,
                    })
                    .collect(),
            };
            save_download_state(&state_path, &new_state)?;
            (f, new_state, 0u64)
        };
        drop(meta);

        if initial_downloaded > 0 {
            style::log(
                "Resuming download",
                format_args!(
                    "{} already downloaded, {} remaining",
                    style::format_size(initial_downloaded),
                    style::format_size(total_data.saturating_sub(initial_downloaded))
                ),
            );
        }

        let write_file = Arc::new(file);
        let client = Arc::new(client);
        let url: Arc<str> = Arc::from(url);
        let downloaded = Arc::new(AtomicU64::new(initial_downloaded));
        let sem = Arc::new(tokio::sync::Semaphore::new(8));

        let mut range_downloaded = Vec::with_capacity(merged.len());
        for r in &state.ranges {
            range_downloaded.push(Arc::new(AtomicU64::new(r.downloaded)));
        }

        let mut handles = Vec::with_capacity(merged.len());
        for (i, &(data_region_off, length)) in merged.iter().enumerate() {
            let start_written = state.ranges[i].downloaded;
            if start_written >= length {
                continue;
            }
            let client = client.clone();
            let url = url.clone();
            let downloaded = downloaded.clone();
            let sem = sem.clone();
            let write_file = write_file.clone();
            let remote_off = payload_off + data_offset + data_region_off;
            let file_base = bases[i];
            let range_written = range_downloaded[i].clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                range_download_to_file(
                    &client,
                    &url,
                    remote_off,
                    length,
                    &write_file,
                    file_base,
                    start_written,
                    &range_written,
                    &downloaded,
                )
                .await
            }));
        }

        let pb = indicatif::ProgressBar::new(total_data);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{prefix:>20} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) [{elapsed_precise}]",
            )
            .unwrap()
            .progress_chars("=> "),
        );
        pb.set_prefix("Downloading");
        pb.set_position(initial_downloaded);

        let ticker = {
            let pb = pb.clone();
            let downloaded = downloaded.clone();
            let dl_cb = opts.download_progress.clone();
            let state_path = state_path.clone();
            let mut state = state.clone();
            let range_downloaded = range_downloaded.clone();
            tokio::spawn(async move {
                let mut last_save = Instant::now();
                loop {
                    let done = downloaded.load(Ordering::Relaxed);
                    pb.set_position(done);
                    if let Some(cb) = &dl_cb {
                        cb(done, total_data);
                    }
                    if last_save.elapsed() >= Duration::from_secs(1) {
                        for (i, rd) in range_downloaded.iter().enumerate() {
                            state.ranges[i].downloaded = rd.load(Ordering::Relaxed);
                        }
                        let _ = save_download_state(&state_path, &state);
                        last_save = Instant::now();
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };

        for handle in handles {
            handle.await??;
        }
        ticker.abort();
        pb.set_position(total_data);
        pb.finish_and_clear();
        if let Some(cb) = &opts.download_progress {
            cb(total_data, total_data);
        }

        let _ = write_file.sync_data();

        // Update state to 100% completed
        for (i, rd) in range_downloaded.iter().enumerate() {
            state.ranges[i].downloaded = rd.load(Ordering::Relaxed);
        }
        let _ = save_download_state(&state_path, &state);

        drop(write_file);
        style::log(
            "Temp file",
            format_args!(
                "{} (meta {} + data {})",
                style::format_size(total_size),
                style::format_size(meta_len),
                style::format_size(total_data),
            ),
        );

        let read_file = std::fs::File::open(&partial_path)
            .context("failed to open downloaded payload file for mmap")?;
        let mmap = unsafe { memmap2::Mmap::map(&read_file) }
            .context("failed to mmap downloaded payload file")?;

        let success_flag = Arc::new(AtomicBool::new(false));
        let guard = TempDownloadGuard {
            partial_path,
            state_path,
            success: success_flag.clone(),
        };

        let mut view = PayloadView::from_mmap_compact(mmap, remap, Box::new(guard))?;
        view.set_success_flag(success_flag);
        Ok(view)
    })
}

/// Plan the compact temp-file layout for HTTP selective download.
///
/// Returns `(total_size, remap, bases)` where the file is laid out as
/// `[meta][merged[0]][merged[1]]…`: `bases[i]` is the file offset of merged
/// range `i`, and `remap` maps each operation's payload `data_offset` to its
/// `(file_position, length)` within the range that contains it. Pure function
/// of offsets/lengths — no payload data needed — so it is unit-testable.
fn plan_compact_layout(
    meta_len: u64,
    merged: &[(u64, u64)],
    op_ranges: &[(u64, u64)],
) -> (u64, HashMap<u64, (u64, u64)>, Vec<u64>) {
    let mut bases = Vec::with_capacity(merged.len());
    let mut cursor = meta_len;
    for &(_, len) in merged {
        bases.push(cursor);
        cursor += len;
    }
    let total_size = cursor;

    let mut remap: HashMap<u64, (u64, u64)> = HashMap::with_capacity(op_ranges.len());
    for &(op_off, op_len) in op_ranges {
        if remap.contains_key(&op_off) {
            continue;
        }
        for (i, &(merged_off, merged_len)) in merged.iter().enumerate() {
            if op_off >= merged_off && op_off + op_len <= merged_off + merged_len {
                remap.insert(op_off, (bases[i] + (op_off - merged_off), op_len));
                break;
            }
        }
    }

    (total_size, remap, bases)
}

/// Download a byte range and stream it straight to `file` at `file_base` via
/// positional writes — never buffering the whole range in memory. Increments
/// `downloaded` per chunk for progress. Can resume from `start_written` and
/// automatically recovers/resumes on connection errors or premature EOF.
#[allow(clippy::too_many_arguments)]
async fn range_download_to_file(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    file: &std::fs::File,
    file_base: u64,
    start_written: u64,
    range_written: &AtomicU64,
    downloaded: &AtomicU64,
) -> Result<()> {
    use futures::StreamExt;

    let end = offset + length - 1;
    let mut written = start_written;
    const MAX_RETRIES: u32 = 10;
    let mut consecutive_errors = 0u32;

    while written < length {
        let curr_remote_off = offset + written;
        let curr_file_pos = file_base + written;
        let curr_remaining = length - written;

        let resp_result = client
            .get(url)
            .header("Range", format!("bytes={curr_remote_off}-{end}"))
            .send()
            .await;

        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors > MAX_RETRIES {
                    return Err(e).context(format!(
                        "max retries ({MAX_RETRIES}) exceeded for range {offset}-{end} (downloaded {written}/{length} bytes)"
                    ));
                }
                let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let mut stream = resp.bytes_stream();
            let mut chunk_written = 0u64;
            let mut stream_err = None;

            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => {
                        let to_take =
                            (curr_remaining - chunk_written).min(chunk.len() as u64) as usize;
                        if to_take == 0 {
                            break;
                        }
                        if let Err(e) =
                            write_all_at(file, &chunk[..to_take], curr_file_pos + chunk_written)
                        {
                            return Err(e).context("temp file write failed");
                        }
                        chunk_written += to_take as u64;
                        range_written.store(written + chunk_written, Ordering::Relaxed);
                        downloaded.fetch_add(to_take as u64, Ordering::Relaxed);
                        if chunk_written == curr_remaining {
                            break;
                        }
                    }
                    Err(e) => {
                        stream_err = Some(e);
                        break;
                    }
                }
            }

            written += chunk_written;
            if chunk_written > 0 {
                consecutive_errors = 0;
            }

            if written == length {
                return Ok(());
            }

            consecutive_errors += 1;
            if consecutive_errors > MAX_RETRIES {
                if let Some(e) = stream_err {
                    return Err(e).context(format!(
                        "max retries ({MAX_RETRIES}) exceeded while resuming range {offset}-{end} (downloaded {written}/{length} bytes)"
                    ));
                } else {
                    bail!(
                        "max retries ({MAX_RETRIES}) exceeded: short read for range {offset}-{end} (downloaded {written}/{length} bytes)"
                    );
                }
            }
            let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            continue;
        }

        if status.is_success() {
            // 200 fallback: server ignored Range and returns the whole file.
            // Skip `curr_remote_off` bytes, then write up to `curr_remaining` bytes to disk.
            let mut stream = resp.bytes_stream();
            let mut to_skip = curr_remote_off;
            let mut chunk_written = 0u64;
            let mut stream_err = None;

            while chunk_written < curr_remaining {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let mut slice = &chunk[..];
                        if to_skip > 0 {
                            let skip = (to_skip as usize).min(slice.len());
                            to_skip -= skip as u64;
                            slice = &slice[skip..];
                        }
                        if slice.is_empty() {
                            continue;
                        }
                        let take = ((curr_remaining - chunk_written) as usize).min(slice.len());
                        if let Err(e) =
                            write_all_at(file, &slice[..take], curr_file_pos + chunk_written)
                        {
                            return Err(e).context("temp file write failed");
                        }
                        chunk_written += take as u64;
                        range_written.store(written + chunk_written, Ordering::Relaxed);
                        downloaded.fetch_add(take as u64, Ordering::Relaxed);
                    }
                    Some(Err(e)) => {
                        stream_err = Some(e);
                        break;
                    }
                    None => break,
                }
            }

            written += chunk_written;
            if chunk_written > 0 {
                consecutive_errors = 0;
            }

            if written == length {
                return Ok(());
            }

            consecutive_errors += 1;
            if consecutive_errors > MAX_RETRIES {
                if let Some(e) = stream_err {
                    return Err(e).context(format!(
                        "max retries ({MAX_RETRIES}) exceeded (HTTP 200) for range {offset}-{end} (downloaded {written}/{length} bytes)"
                    ));
                } else {
                    bail!(
                        "max retries ({MAX_RETRIES}) exceeded: short read (HTTP 200) for range {offset}-{end} (downloaded {written}/{length} bytes)"
                    );
                }
            }
            let backoff = (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
            continue;
        }

        let retry_after_secs = if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        {
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
        } else {
            None
        };

        consecutive_errors += 1;
        if consecutive_errors > MAX_RETRIES {
            bail!("HTTP {status} for range {curr_remote_off}-{end} after {MAX_RETRIES} retries");
        }

        let backoff = if let Some(secs) = retry_after_secs {
            (secs * 1000).min(60_000)
        } else {
            (1000u64 * 2u64.pow((consecutive_errors - 1).min(5))).min(30_000)
        };
        tokio::time::sleep(Duration::from_millis(backoff)).await;
    }

    Ok(())
}

/// Fetch META-INF/com/android/metadata and metadata.pb from a remote OTA ZIP.
/// The two entries are downloaded concurrently after a single CD fetch.
pub fn read_ota_metadata_http(
    url: &str,
    insecure: bool,
    user_agent: Option<&str>,
) -> Result<OtaMetadataData> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure, user_agent)?;
        let (total_size, head) = fetch_total_size_and_head(&client, url).await?;
        if head.len() < 4 || &head[..4] != ZIP_MAGIC {
            bail!(
                "URL is not an OTA ZIP (magic: {:02x?})",
                &head[..4.min(head.len())]
            );
        }
        let cd = fetch_zip_cd(&client, url, total_size).await?;

        let (text_bytes, pb_bytes) = tokio::try_join!(
            download_stored_zip_entry(&client, url, &cd, ota_metadata::text_entry_name()),
            download_stored_zip_entry(&client, url, &cd, ota_metadata::pb_entry_name()),
        )?;

        let mut data = OtaMetadataData::default();
        if let Some(b) = text_bytes {
            data.text = Some(ota_metadata::parse_text(&String::from_utf8_lossy(&b)));
        }
        if let Some(b) = pb_bytes {
            data.pb = Some(ota_metadata::parse_pb_bytes(&b)?);
        }
        Ok(data)
    })
}

/// One-shot fetch of bytes 0..=3 that returns both the file's total size (from
/// Content-Range or Content-Length) and the first four bytes for magic detection.
async fn fetch_total_size_and_head(client: &reqwest::Client, url: &str) -> Result<(u64, Vec<u8>)> {
    let resp = client
        .get(url)
        .header("Range", "bytes=0-3")
        .send()
        .await?
        .error_for_status()?;

    let total_size = if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit('/').next())
            .and_then(|s| s.parse::<u64>().ok())
            .context("cannot determine file size from Content-Range")?
    } else {
        resp.content_length()
            .context("server returned no Content-Length")?
    };

    let head = resp.bytes().await?.to_vec();
    let head = if head.len() >= 4 {
        head
    } else {
        range_download(client, url, 0, 4).await?
    };
    Ok((total_size, head))
}

/// Locate the EOCD (and optional ZIP64 record) and return the central directory bytes.
async fn fetch_zip_cd(client: &reqwest::Client, url: &str, total_size: u64) -> Result<Vec<u8>> {
    let tail_size = (256 * 1024u64).min(total_size);
    let tail_offset = total_size - tail_size;
    let tail = range_download(client, url, tail_offset, tail_size).await?;

    let eocd_pos = tail
        .windows(4)
        .rposition(|w| w == ZIP_EOCD_SIG)
        .context("EOCD not found")?;

    let is_zip64 = eocd_pos >= 20 && tail[eocd_pos - 20..eocd_pos - 16] == ZIP64_LOCATOR_SIG;

    let (cd_offset, cd_size) = if is_zip64 {
        let locator = &tail[eocd_pos - 20..eocd_pos];
        let z64_off = u64::from_le_bytes(locator[8..16].try_into().unwrap());
        let rec = if z64_off >= tail_offset {
            let i = (z64_off - tail_offset) as usize;
            tail[i..i + 56].to_vec()
        } else {
            range_download(client, url, z64_off, 56).await?
        };
        (
            u64::from_le_bytes(rec[48..56].try_into().unwrap()),
            u64::from_le_bytes(rec[40..48].try_into().unwrap()),
        )
    } else {
        let eocd = &tail[eocd_pos..];
        (
            u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as u64,
            u32::from_le_bytes(eocd[12..16].try_into().unwrap()) as u64,
        )
    };

    let cd = if cd_offset >= tail_offset {
        let i = (cd_offset - tail_offset) as usize;
        tail[i..i + cd_size as usize].to_vec()
    } else {
        range_download(client, url, cd_offset, cd_size).await?
    };
    Ok(cd)
}

#[derive(Debug)]
struct CdEntry {
    local_off: u64,
    compressed_size: u64,
    compression: u16,
    name_len: u16,
}

/// Linear scan of the central directory for an entry by name.
/// Resolves ZIP64 sentinel fields from the per-entry extra block.
fn find_cd_entry(cd: &[u8], target: &str) -> Option<CdEntry> {
    let mut pos = 0usize;
    while pos + 46 <= cd.len() {
        if cd[pos..pos + 4] != ZIP_CD_SIG {
            break;
        }
        let comp_method = u16::from_le_bytes(cd[pos + 10..pos + 12].try_into().unwrap());
        let csize_field = u32::from_le_bytes(cd[pos + 20..pos + 24].try_into().unwrap());
        let usize_field = u32::from_le_bytes(cd[pos + 24..pos + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes(cd[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(cd[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(cd[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_off_field = u32::from_le_bytes(cd[pos + 42..pos + 46].try_into().unwrap());

        if pos + 46 + name_len > cd.len() {
            break;
        }
        let name = std::str::from_utf8(&cd[pos + 46..pos + 46 + name_len]).unwrap_or("");

        if name == target {
            let extra = &cd[pos + 46 + name_len..pos + 46 + name_len + extra_len];
            let (local_off, csize, _usize) =
                resolve_zip64_fields(local_off_field, csize_field, usize_field, extra);
            return Some(CdEntry {
                local_off,
                compressed_size: csize,
                compression: comp_method,
                name_len: name_len as u16,
            });
        }
        pos += 46 + name_len + extra_len + comment_len;
    }
    None
}

/// Download a STORED CD entry's raw bytes. A single optimistic range request
/// covers LFH + name + extra + payload; a fallback request handles the rare
/// case where the LFH extra field exceeds `LFH_EXTRA_HEADROOM`.
async fn download_stored_zip_entry(
    client: &reqwest::Client,
    url: &str,
    cd: &[u8],
    target: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(entry) = find_cd_entry(cd, target) else {
        return Ok(None);
    };
    if entry.compression != 0 {
        bail!(
            "{target} entry is compressed (method {}); only STORED is supported",
            entry.compression
        );
    }

    const LFH_EXTRA_HEADROOM: u64 = 1024;
    let optimistic = 30 + entry.name_len as u64 + LFH_EXTRA_HEADROOM + entry.compressed_size;
    let buf = range_download(client, url, entry.local_off, optimistic).await?;
    if buf.len() < 30 {
        bail!("LFH truncated for {target}");
    }
    let n = u16::from_le_bytes(buf[26..28].try_into().unwrap()) as usize;
    let e = u16::from_le_bytes(buf[28..30].try_into().unwrap()) as usize;
    let data_off = 30 + n + e;
    let data_end = data_off + entry.compressed_size as usize;

    if data_end <= buf.len() {
        return Ok(Some(buf[data_off..data_end].to_vec()));
    }

    // LFH extra exceeded headroom — fall back to a second range request.
    let abs_data_off = entry.local_off + data_off as u64;
    let data = range_download(client, url, abs_data_off, entry.compressed_size).await?;
    Ok(Some(data))
}

/// Resolve potential ZIP64 sentinel values in a CD entry by reading the extra field.
/// The ZIP64 extended-info (tag 0x0001) packs uncompressed size, compressed size, then
/// local header offset, but only the fields whose 32-bit values are 0xFFFFFFFF are stored.
fn resolve_zip64_fields(
    local_off_field: u32,
    csize_field: u32,
    usize_field: u32,
    extra: &[u8],
) -> (u64, u64, u64) {
    let mut local_off = local_off_field as u64;
    let mut csize = csize_field as u64;
    let mut usize_ = usize_field as u64;

    if usize_field != 0xFFFFFFFF && csize_field != 0xFFFFFFFF && local_off_field != 0xFFFFFFFF {
        return (local_off, csize, usize_);
    }

    let mut p = 0;
    while p + 4 <= extra.len() {
        let tag = u16::from_le_bytes(extra[p..p + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[p + 2..p + 4].try_into().unwrap()) as usize;
        if tag == 0x0001 && p + 4 + sz <= extra.len() {
            let body = &extra[p + 4..p + 4 + sz];
            let mut q = 0usize;
            if usize_field == 0xFFFFFFFF && q + 8 <= body.len() {
                usize_ = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
                q += 8;
            }
            if csize_field == 0xFFFFFFFF && q + 8 <= body.len() {
                csize = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
                q += 8;
            }
            if local_off_field == 0xFFFFFFFF && q + 8 <= body.len() {
                local_off = u64::from_le_bytes(body[q..q + 8].try_into().unwrap());
            }
            break;
        }
        p += 4 + sz;
    }
    (local_off, csize, usize_)
}

fn merge_ranges(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut merged = Vec::new();
    let (mut cs, mut cl) = ranges[0];
    const GAP: u64 = 256 * 1024;
    for &(s, l) in &ranges[1..] {
        let ce = cs + cl;
        if s <= ce + GAP {
            cl = (s + l).max(ce) - cs;
        } else {
            merged.push((cs, cl));
            cs = s;
            cl = l;
        }
    }
    merged.push((cs, cl));
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compact layout packs `[meta][range0][range1]…` and remaps each op's
    /// payload data_offset to its position within the file range that holds it.
    #[test]
    fn plan_compact_layout_maps_ops_into_ranges() {
        let meta_len = 24u64;
        let merged = [(100u64, 50u64), (200u64, 30u64)];
        // Three ops: two inside range0, one filling range1.
        let op_ranges = [(100u64, 10u64), (110u64, 40u64), (200u64, 30u64)];

        let (total, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        assert_eq!(bases, vec![24, 74]); // meta_len, meta_len + 50
        assert_eq!(total, 24 + 50 + 30);
        assert_eq!(remap[&100], (24, 10)); // start of range0
        assert_eq!(remap[&110], (34, 40)); // 10 bytes into range0
        assert_eq!(remap[&200], (74, 30)); // start of range1
    }

    /// remap positions must point at the same bytes that a contiguous on-disk
    /// layout would, for non-adjacent ops within a merged range.
    #[test]
    fn plan_compact_layout_single_range_gap() {
        let meta_len = 0u64;
        let merged = [(0u64, 100u64)];
        // ops at 0 and 60, leaving a gap [10,60) that stays on disk.
        let op_ranges = [(0u64, 10u64), (60u64, 40u64)];

        let (total, remap, bases) = plan_compact_layout(meta_len, &merged, &op_ranges);

        assert_eq!(bases, vec![0]);
        assert_eq!(total, 100);
        assert_eq!(remap[&0], (0, 10));
        assert_eq!(remap[&60], (60, 40)); // offset within the range is preserved
    }

    #[test]
    fn merge_ranges_collapses_within_gap() {
        // Two ranges closer than GAP merge into one spanning both.
        let merged = merge_ranges(&[(0, 100), (100 + 1024, 50)]);
        assert_eq!(merged, vec![(0, 100 + 1024 + 50)]);
        // A range farther than GAP stays separate.
        let merged = merge_ranges(&[(0, 100), (100 + 512 * 1024, 50)]);
        assert_eq!(merged, vec![(0, 100), (100 + 512 * 1024, 50)]);
    }

    #[test]
    fn test_compute_cache_key() {
        let url = "https://example.com/payload.bin";
        let parts1 = vec!["boot".to_string(), "system".to_string()];
        let parts2 = vec!["system".to_string(), "boot".to_string()];
        // Partition order should not affect the cache key
        assert_eq!(
            compute_cache_key(url, &parts1),
            compute_cache_key(url, &parts2)
        );

        // Different URL or partitions should yield different keys
        assert_ne!(
            compute_cache_key("https://example.com/other.bin", &parts1),
            compute_cache_key(url, &parts1)
        );
        let parts3 = vec!["vendor".to_string()];
        assert_ne!(
            compute_cache_key(url, &parts1),
            compute_cache_key(url, &parts3)
        );
    }

    #[test]
    fn test_download_state_serde() {
        let state = DownloadState {
            url: "https://example.com/ota.zip".to_string(),
            meta_hash: "abcd1234ef567890".to_string(),
            total_size: 1048576,
            ranges: vec![
                RangeState {
                    remote_offset: 100,
                    file_base: 500,
                    length: 1000,
                    downloaded: 400,
                },
                RangeState {
                    remote_offset: 2000,
                    file_base: 1500,
                    length: 5000,
                    downloaded: 5000,
                },
            ],
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("test.state");

        save_download_state(&state_file, &state).unwrap();
        let loaded = load_download_state(&state_file).unwrap().unwrap();

        assert_eq!(loaded.url, state.url);
        assert_eq!(loaded.meta_hash, state.meta_hash);
        assert_eq!(loaded.total_size, state.total_size);
        assert_eq!(loaded.ranges.len(), 2);
        assert_eq!(loaded.ranges[0].downloaded, 400);
        assert_eq!(loaded.ranges[1].downloaded, 5000);
    }

    #[tokio::test]
    async fn test_range_download_resumes_on_stream_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"; // 32 bytes
        let total_len = expected_data.len() as u64;

        tokio::spawn(async move {
            // First attempt: accept, send 206 with first 10 bytes, then abruptly drop socket
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{total_len}/{total_len}\r\nContent-Length: {total_len}\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.write_all(&expected_data[..10]).await;
                let _ = socket.shutdown().await;
            }

            // Second attempt: accept resume request from byte 10, send remaining 22 bytes
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("bytes=10-31"));
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-31/{total_len}\r\nContent-Length: 22\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.write_all(&expected_data[10..]).await;
                let _ = socket.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/test");

        let result = range_download(&client, &url, 0, total_len).await.unwrap();
        assert_eq!(&result[..], expected_data);
    }

    #[tokio::test]
    async fn test_range_download_to_file_resumes_on_stream_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"; // 32 bytes
        let total_len = expected_data.len() as u64;

        tokio::spawn(async move {
            // First attempt: accept, send 206 with only 12 bytes, then abruptly drop socket
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{total_len}/{total_len}\r\nContent-Length: {total_len}\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.write_all(&expected_data[..12]).await;
                let _ = socket.shutdown().await;
            }

            // Second attempt: accept resume request from byte 12, send remaining 20 bytes
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("bytes=12-31"));
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 12-31/{total_len}\r\nContent-Length: 20\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.write_all(&expected_data[12..]).await;
                let _ = socket.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/test");

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.as_file().set_len(total_len).unwrap();

        let range_written = AtomicU64::new(0);
        let downloaded = AtomicU64::new(0);

        range_download_to_file(
            &client,
            &url,
            0,
            total_len,
            temp_file.as_file(),
            0,
            0,
            &range_written,
            &downloaded,
        )
        .await
        .unwrap();

        assert_eq!(range_written.load(Ordering::SeqCst), total_len);
        assert_eq!(downloaded.load(Ordering::SeqCst), total_len);

        use std::io::Read;
        let mut f = std::fs::File::open(temp_file.path()).unwrap();
        let mut content = vec![0u8; total_len as usize];
        f.read_exact(&mut content).unwrap();
        assert_eq!(&content[..], expected_data);
    }

    #[tokio::test]
    async fn test_range_download_to_file_starts_from_start_written() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"; // 32 bytes
        let total_len = expected_data.len() as u64;
        let start_written = 16u64;

        tokio::spawn(async move {
            // Server should only see one request starting at byte 16
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.contains("bytes=16-31"));
                let resp = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 16-31/{total_len}\r\nContent-Length: 16\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.write_all(&expected_data[16..]).await;
                let _ = socket.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/test");

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.as_file().set_len(total_len).unwrap();

        // Write the first 16 bytes as if previously downloaded
        write_all_at(temp_file.as_file(), &expected_data[..16], 0).unwrap();

        let range_written = AtomicU64::new(start_written);
        let downloaded = AtomicU64::new(start_written);

        range_download_to_file(
            &client,
            &url,
            0,
            total_len,
            temp_file.as_file(),
            0,
            start_written,
            &range_written,
            &downloaded,
        )
        .await
        .unwrap();

        assert_eq!(range_written.load(Ordering::SeqCst), total_len);
        assert_eq!(downloaded.load(Ordering::SeqCst), total_len);

        use std::io::Read;
        let mut f = std::fs::File::open(temp_file.path()).unwrap();
        let mut content = vec![0u8; total_len as usize];
        f.read_exact(&mut content).unwrap();
        assert_eq!(&content[..], expected_data);
    }
}
