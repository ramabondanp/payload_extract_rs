use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use prost::Message;
use prost::bytes::{Buf, Bytes};

use crate::ota_metadata::{self, OtaMetadataData};
use crate::payload::PayloadView;
use crate::payload::header::{HEADER_SIZE, MAGIC, PayloadHeader};
use crate::proto::DeltaArchiveManifest;
use crate::style;

use super::ZIP_MAGIC;
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CD_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];

fn build_client(insecure: bool) -> Result<reqwest::Client> {
    if insecure {
        eprintln!(
            "{} TLS certificate verification is disabled — connection is vulnerable to man-in-the-middle attacks",
            crate::style::warning().apply_to("WARNING:")
        );
    }
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(3600))
        .connect_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(4)
        .redirect(reqwest::redirect::Policy::limited(10))
        .no_proxy() // disables proxy-based SSRF via env vars
        .build()
        .context("failed to build HTTP client")
}

/// Validate that a URL hostname is not a private, loopback, link-local,
/// or cloud-metadata address. Rejects raw IPs in those ranges regardless
/// of DNS resolution. Doesn't prevent all SSRF vectors but blocks
/// the most common ones.
fn validate_url(url_str: &str) -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr};

    let url = url::Url::parse(url_str).context("invalid URL")?;
    let host = url.host_str().context("URL has no host")?;

    // Reject raw IPs in private/loopback/link-local ranges
    if let Ok(ip) = host.parse::<IpAddr>() {
        let bad = match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_unspecified()
                    || ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 // link-local
                    || ipv4 == Ipv4Addr::new(0, 0, 0, 0)
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_unspecified()
                    || ipv6.to_ipv4().is_some_and(|v4| {
                        v4.is_loopback()
                            || v4.is_private()
                            || v4.is_link_local()
                    })
                    || ipv6.segments()[0] & 0xffc0 == 0xfe80 // link-local
                    || ipv6.segments()[0] == 0x0000 && ipv6.segments()[1] == 0x0000 // IPv4-mapped/embedded
                        && ipv6.segments()[2] == 0x0000 && ipv6.segments()[3] == 0x0000
                        && ipv6.segments()[4] == 0x0000 && ipv6.segments()[5] == 0xffff
            }
        };
        if bad {
            bail!("URL resolves to a private/internal address: {host}");
        }
    } else {
        // Reject bare hostnames that look like they target internal services
        let host_lower = host.to_lowercase();
        if host_lower == "localhost"
            || host_lower.ends_with(".local")
            || host_lower.ends_with(".internal")
        {
            bail!("URL targets a reserved hostname: {host}");
        }
    }
    Ok(())
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().context("failed to create tokio runtime")
}

async fn range_download(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    progress: Option<Arc<AtomicU64>>,
) -> Result<Vec<u8>> {
    let buf = Arc::new(Mutex::new(Vec::with_capacity(length as usize)));
    {
        let buf = buf.clone();
        range_download_internal(
            client,
            url,
            offset,
            length,
            progress,
            move |chunk: Bytes, _| {
                let buf = buf.clone();
                Box::pin(async move {
                    buf.lock().unwrap().extend_from_slice(&chunk);
                    Ok(())
                })
            },
        )
        .await?;
    }
    let res = Arc::try_unwrap(buf).unwrap().into_inner().unwrap();
    Ok(res)
}

async fn range_download_to_file(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    dest: Arc<Mutex<std::fs::File>>,
    dest_offset: u64,
    progress: Option<Arc<AtomicU64>>,
) -> Result<()> {
    range_download_internal(
        client,
        url,
        offset,
        length,
        progress,
        |chunk: Bytes, relative_off| {
            let dest = dest.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    let mut f = dest.lock().unwrap();
                    f.seek(SeekFrom::Start(dest_offset + relative_off))?;
                    f.write_all(&chunk)?;
                    Ok::<(), anyhow::Error>(())
                })
                .await?
            })
        },
    )
    .await
}

async fn range_download_internal<F>(
    client: &reqwest::Client,
    url: &str,
    offset: u64,
    length: u64,
    progress: Option<Arc<AtomicU64>>,
    mut writer: F,
) -> Result<()>
where
    F: FnMut(Bytes, u64) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send>>,
{
    use futures::StreamExt;

    let end = offset + length - 1;
    for attempt in 0..=10u32 {
        let mut downloaded_this_attempt = 0u64;

        let resp = match client
            .get(url)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if attempt == 10 {
                    return Err(e).context("max retries exceeded");
                }
                let backoff = Duration::from_millis(1000 * 2u64.pow(attempt.min(6)));
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        let status = resp.status();
        let res: Result<()> =
            if status == reqwest::StatusCode::PARTIAL_CONTENT || status.is_success() {
                let mut stream = resp.bytes_stream();
                let mut to_skip = if status == reqwest::StatusCode::PARTIAL_CONTENT {
                    0
                } else {
                    offset
                };
                let mut to_read = length as usize;

                while to_read > 0 {
                    match stream.next().await {
                        Some(Ok(chunk)) => {
                            let mut chunk = chunk;
                            if to_skip > 0 {
                                let skip = (to_skip as usize).min(chunk.len());
                                to_skip -= skip as u64;
                                chunk.advance(skip);
                                if !chunk.is_empty() {
                                    let take = chunk.len().min(to_read);
                                    let data = chunk.split_to(take);
                                    writer(data, downloaded_this_attempt).await?;
                                    to_read -= take;
                                    downloaded_this_attempt += take as u64;
                                    if let Some(ref p) = progress {
                                        p.fetch_add(take as u64, Ordering::Relaxed);
                                    }
                                }
                            } else {
                                let take = chunk.len().min(to_read);
                                let data = chunk.split_to(take);
                                writer(data, downloaded_this_attempt).await?;
                                to_read -= take;
                                downloaded_this_attempt += take as u64;
                                if let Some(ref p) = progress {
                                    p.fetch_add(take as u64, Ordering::Relaxed);
                                }
                            }
                        }
                        Some(Err(_e)) => {
                            break; // Trigger retry
                        }
                        None => break,
                    }
                }

                if to_read == 0 {
                    Ok(())
                } else {
                    bail!("stream ended prematurely ({} bytes remaining)", to_read)
                }
            } else {
                bail!("HTTP {status} for range {offset}-{end}")
            };

        match res {
            Ok(_) => return Ok(()),
            Err(e) => {
                if let Some(ref p) = progress {
                    p.fetch_sub(downloaded_this_attempt, Ordering::Relaxed);
                }
                if attempt == 10 {
                    return Err(e).context("max retries exceeded after failure");
                }
                // Use a longer backoff for 503/429 or other server errors
                let base = if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                    5000 // 5s base for 503
                } else {
                    2000 // 2s base otherwise
                };
                let backoff = Duration::from_millis(base * 2u64.pow(attempt.min(5)));
                tokio::time::sleep(backoff).await;
            }
        }
    }
    unreachable!()
}

async fn resolve_final_url(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client
        .head(url)
        .send()
        .await
        .context("failed to resolve final URL")?;
    Ok(resp.url().to_string())
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

    let lfh = range_download(client, url, entry.local_off, 30, None).await?;
    let n = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
    let e = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
    Ok(entry.local_off + 30 + n + e)
}

pub fn open_http_metadata(url: &str, insecure: bool) -> Result<PayloadView> {
    validate_url(url)?;
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure)?;
        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64, None).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len, None).await?;

        Ok(PayloadView::from_memory(meta, HashMap::new())?)
    })
}

pub fn open_http_extract(
    url: &str,
    partition_names: &[String],
    insecure: bool,
) -> Result<PayloadView> {
    validate_url(url)?;
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure)?;
        let final_url = resolve_final_url(&client, url).await?;
        let url = final_url.as_str();

        let payload_off = detect_payload_offset(&client, url).await?;

        eprintln!("{}...", style::label().apply_to("Fetching payload header"));
        let hdr = range_download(&client, url, payload_off, HEADER_SIZE as u64, None).await?;
        let header = PayloadHeader::parse(&hdr)?;

        let meta_len =
            HEADER_SIZE as u64 + header.manifest_size + header.metadata_signature_size as u64;
        eprintln!(
            "{} ({})...",
            style::label().apply_to("Fetching manifest"),
            style::format_size(header.manifest_size)
        );
        let meta = range_download(&client, url, payload_off, meta_len, None).await?;

        let manifest = DeltaArchiveManifest::decode(
            &meta[HEADER_SIZE..HEADER_SIZE + header.manifest_size as usize],
        )?;
        let data_offset = header.data_offset();

        let parts: Vec<_> = if partition_names.is_empty() {
            manifest.partitions.iter().collect()
        } else {
            manifest
                .partitions
                .iter()
                .filter(|p| partition_names.iter().any(|n| n == &p.partition_name))
                .collect()
        };
        if parts.is_empty() && !partition_names.is_empty() {
            bail!("none of the specified partitions found");
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

        struct TempFileGuard {
            path: std::path::PathBuf,
            active: bool,
        }

        impl Drop for TempFileGuard {
            fn drop(&mut self) {
                if self.active {
                    let _ = std::fs::remove_file(&self.path);
                }
            }
        }

        let mut temp_path = std::env::temp_dir();
        temp_path.push(format!(
            "payload-extract-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let mut guard = TempFileGuard {
            path: temp_path.clone(),
            active: true,
        };

        let mut file = std::fs::File::create(&guard.path)
            .with_context(|| format!("failed to create temp file {}", guard.path.display()))?;
        let meta_len_u64 = meta.len() as u64;
        file.set_len(meta_len_u64 + total_data)?;
        file.write_all(&meta)?;

        let file = Arc::new(Mutex::new(file));
        let downloaded = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(tokio::sync::Semaphore::new(5));

        let mut remap: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut current_dest_off = meta_len_u64;

        let client = Arc::new(client);
        let url_arc: Arc<str> = Arc::from(url);
        let mut handles = Vec::new();

        const MAX_RANGE_SIZE: u64 = 32 * 1024 * 1024; // 32 MB chunks

        for &(merged_off, merged_len) in &merged {
            let mut remaining = merged_len;
            let mut sub_off = 0u64;

            while remaining > 0 {
                let chunk_len = remaining.min(MAX_RANGE_SIZE);
                let dest_off = current_dest_off + sub_off;
                let client = client.clone();
                let url = url_arc.clone();
                let downloaded = downloaded.clone();
                let sem = sem.clone();
                let file = file.clone();
                let remote_off = payload_off + data_offset + merged_off + sub_off;

                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    range_download_to_file(
                        &client,
                        &url,
                        remote_off,
                        chunk_len,
                        file,
                        dest_off,
                        Some(downloaded),
                    )
                    .await
                }));

                remaining -= chunk_len;
                sub_off += chunk_len;
                // Stagger requests slightly to avoid hitting rate limits on startup
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // Map all op_ranges that fall within this merged range
            for &(op_off, op_len) in &op_ranges {
                if op_off >= merged_off && op_off + op_len <= merged_off + merged_len {
                    let within = op_off - merged_off;
                    remap.insert(op_off, (current_dest_off + within, op_len));
                }
            }
            current_dest_off += merged_len;
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

        // Spawn progress updater
        let pb_task = {
            let pb = pb.clone();
            let downloaded = downloaded.clone();
            tokio::spawn(async move {
                while !pb.is_finished() {
                    pb.set_position(downloaded.load(Ordering::Relaxed));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };

        for handle in handles {
            handle.await??;
        }
        pb.finish_and_clear();
        pb_task.abort();

        style::log(
            "Buffer",
            format_args!(
                "{} (meta {} + data {}) [MMAP]",
                style::format_size(current_dest_off),
                style::format_size(meta_len_u64),
                style::format_size(total_data),
            ),
        );

        let file = std::fs::File::open(&guard.path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        // Deactivate guard and remove file manually. 
        // On Unix, the mmap keeps the data alive even after remove_file.
        guard.active = false;
        let _ = std::fs::remove_file(&guard.path);

        Ok(PayloadView::from_mmap_with_remap(mmap, 0, remap)?)
    })
}

/// Fetch META-INF/com/android/metadata and metadata.pb from a remote OTA ZIP.
/// The two entries are downloaded concurrently after a single CD fetch.
pub fn read_ota_metadata_http(url: &str, insecure: bool) -> Result<OtaMetadataData> {
    validate_url(url)?;
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure)?;
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
        range_download(client, url, 0, 4, None).await?
    };
    Ok((total_size, head))
}

/// Locate the EOCD (and optional ZIP64 record) and return the central directory bytes.
async fn fetch_zip_cd(client: &reqwest::Client, url: &str, total_size: u64) -> Result<Vec<u8>> {
    let tail_size = (256 * 1024u64).min(total_size);
    let tail_offset = total_size - tail_size;
    let tail = range_download(client, url, tail_offset, tail_size, None).await?;

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
            range_download(client, url, z64_off, 56, None).await?
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
        range_download(client, url, cd_offset, cd_size, None).await?
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
    let buf = range_download(client, url, entry.local_off, optimistic, None).await?;
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
    let data = range_download(client, url, abs_data_off, entry.compressed_size, None).await?;
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
