use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::DeflateDecoder;
use prost::Message;
use prost::bytes::{Buf, Bytes};

use crate::payload::PayloadView;
use crate::payload::header::{HEADER_SIZE, MAGIC, PayloadHeader};
use crate::proto::DeltaArchiveManifest;
use crate::style;

use super::{OTA_METADATA_PATH, OtaMetadata, ZIP_MAGIC};
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const ZIP_CD_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];

fn build_client(insecure: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
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

    let mut pos = 0usize;
    while pos + 46 <= cd.len() {
        if cd[pos..pos + 4] != ZIP_CD_SIG {
            break;
        }
        let name_len = u16::from_le_bytes(cd[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(cd[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(cd[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_off = u32::from_le_bytes(cd[pos + 42..pos + 46].try_into().unwrap());

        if pos + 46 + name_len > cd.len() {
            break;
        }
        let name = std::str::from_utf8(&cd[pos + 46..pos + 46 + name_len]).unwrap_or("");

        if name == "payload.bin" {
            let mut offset = local_off as u64;
            if local_off == 0xFFFFFFFF {
                let extra = &cd[pos + 46 + name_len..pos + 46 + name_len + extra_len];
                offset = parse_zip64_offset(extra, offset);
            }
            let lfh = range_download(client, url, offset, 30, None).await?;
            let n = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
            let e = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
            return Ok(offset + 30 + n + e);
        }
        pos += 46 + name_len + extra_len + comment_len;
    }
    bail!("payload.bin not found in remote ZIP");
}

fn parse_zip64_offset(extra: &[u8], default: u64) -> u64 {
    let mut p = 0;
    while p + 4 <= extra.len() {
        let tag = u16::from_le_bytes(extra[p..p + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[p + 2..p + 4].try_into().unwrap()) as usize;
        if tag == 0x0001 && p + 4 + sz <= extra.len() && sz >= 24 {
            return u64::from_le_bytes(extra[p + 20..p + 28].try_into().unwrap());
        }
        p += 4 + sz;
    }
    default
}

fn parse_zip64_entry_fields(
    extra: &[u8],
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
) -> (u64, u64, u64) {
    let mut p = 0;
    while p + 4 <= extra.len() {
        let tag = u16::from_le_bytes(extra[p..p + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[p + 2..p + 4].try_into().unwrap()) as usize;
        let start = p + 4;
        let end = start + sz;
        if tag == 0x0001 && end <= extra.len() {
            let mut cursor = start;
            let uncompressed_size = if uncompressed_size == 0xFFFF_FFFF {
                let value = u64::from_le_bytes(extra[cursor..cursor + 8].try_into().unwrap());
                cursor += 8;
                value
            } else {
                uncompressed_size
            };
            let compressed_size = if compressed_size == 0xFFFF_FFFF {
                let value = u64::from_le_bytes(extra[cursor..cursor + 8].try_into().unwrap());
                cursor += 8;
                value
            } else {
                compressed_size
            };
            let local_offset = if local_offset == 0xFFFF_FFFF {
                u64::from_le_bytes(extra[cursor..cursor + 8].try_into().unwrap())
            } else {
                local_offset
            };
            return (compressed_size, uncompressed_size, local_offset);
        }
        p += 4 + sz;
    }
    (compressed_size, uncompressed_size, local_offset)
}

async fn inspect_remote_payload_and_ota(
    client: &reqwest::Client,
    url: &str,
) -> Result<(u64, Option<OtaMetadata>)> {
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
    if head.len() >= 4 && &head[..4] == MAGIC {
        return Ok((0, None));
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

    let mut pos = 0usize;
    let mut payload_offset = None;
    let mut ota_metadata = None;
    while pos + 46 <= cd.len() {
        if cd[pos..pos + 4] != ZIP_CD_SIG {
            break;
        }

        let compression = u16::from_le_bytes(cd[pos + 10..pos + 12].try_into().unwrap());
        let compressed_size = u32::from_le_bytes(cd[pos + 20..pos + 24].try_into().unwrap()) as u64;
        let uncompressed_size =
            u32::from_le_bytes(cd[pos + 24..pos + 28].try_into().unwrap()) as u64;
        let name_len = u16::from_le_bytes(cd[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(cd[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(cd[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_offset = u32::from_le_bytes(cd[pos + 42..pos + 46].try_into().unwrap()) as u64;

        if pos + 46 + name_len > cd.len() {
            break;
        }

        let name = std::str::from_utf8(&cd[pos + 46..pos + 46 + name_len]).unwrap_or("");
        if name == "payload.bin" || name == OTA_METADATA_PATH {
            let extra = &cd[pos + 46 + name_len..pos + 46 + name_len + extra_len];
            let (compressed_size, uncompressed_size, local_offset) =
                parse_zip64_entry_fields(extra, compressed_size, uncompressed_size, local_offset);

            let lfh = range_download(client, url, local_offset, 30, None).await?;
            let local_name_len = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
            let local_extra_len = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
            let data_offset = local_offset + 30 + local_name_len + local_extra_len;
            if name == "payload.bin" {
                payload_offset = Some(data_offset);
            } else {
                let data = range_download(client, url, data_offset, compressed_size, None).await?;
                let contents = match compression {
                    0 => data,
                    8 => {
                        let mut decoder = DeflateDecoder::new(&data[..]);
                        let mut out = Vec::with_capacity(uncompressed_size as usize);
                        decoder.read_to_end(&mut out)?;
                        out
                    }
                    method => {
                        bail!("unsupported compression method {method} for '{OTA_METADATA_PATH}'")
                    }
                };

                ota_metadata = String::from_utf8(contents)
                    .ok()
                    .map(|text| super::zip_input::parse_ota_metadata(&text));
            }

            if payload_offset.is_some() && ota_metadata.is_some() {
                break;
            }
            if name == "payload.bin" {
                pos += 46 + name_len + extra_len + comment_len;
                continue;
            }
            if name == OTA_METADATA_PATH {
                pos += 46 + name_len + extra_len + comment_len;
                continue;
            }
        }

        pos += 46 + name_len + extra_len + comment_len;
    }

    let payload_offset = payload_offset.context("payload.bin not found in remote ZIP")?;
    Ok((payload_offset, ota_metadata))
}

pub fn open_http_metadata(url: &str, insecure: bool) -> Result<PayloadView> {
    Ok(open_http_metadata_with_ota(url, insecure)?.0)
}

pub fn open_http_metadata_with_ota(
    url: &str,
    insecure: bool,
) -> Result<(PayloadView, Option<OtaMetadata>)> {
    let rt = build_runtime()?;
    rt.block_on(async {
        let client = build_client(insecure)?;
        let (payload_off, ota_metadata) = inspect_remote_payload_and_ota(&client, url).await?;

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

        Ok((
            PayloadView::from_memory(meta, HashMap::new())?,
            ota_metadata,
        ))
    })
}

pub fn open_http_extract(
    url: &str,
    partition_names: &[String],
    insecure: bool,
) -> Result<PayloadView> {
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
