use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::DeflateDecoder;
use prost::Message;

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
) -> Result<Vec<u8>> {
    use futures::StreamExt;

    let end = offset + length - 1;
    for attempt in 0..=3u32 {
        let resp = match client
            .get(url)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if attempt == 3 {
                    return Err(e).context("max retries exceeded");
                }
                tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
                continue;
            }
        };

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            return Ok(resp.bytes().await?.to_vec());
        }

        if status.is_success() {
            // 200 fallback: stream only requested bytes to prevent OOM
            let mut buf = Vec::with_capacity(length as usize);
            let mut stream = resp.bytes_stream();
            let mut to_skip = offset;
            let mut to_read = length as usize;

            while to_read > 0 {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        let chunk = &chunk[..];
                        if to_skip > 0 {
                            let skip = (to_skip as usize).min(chunk.len());
                            to_skip -= skip as u64;
                            let remaining_chunk = &chunk[skip..];
                            if !remaining_chunk.is_empty() {
                                let take = remaining_chunk.len().min(to_read);
                                buf.extend_from_slice(&remaining_chunk[..take]);
                                to_read -= take;
                            }
                        } else {
                            let take = chunk.len().min(to_read);
                            buf.extend_from_slice(&chunk[..take]);
                            to_read -= take;
                        }
                    }
                    Some(Err(e)) => return Err(e).context("stream error"),
                    None => break,
                }
            }
            return Ok(buf);
        }

        if attempt == 3 {
            bail!("HTTP {status} for range {offset}-{end}");
        }
        tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
    }
    unreachable!()
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
        range_download(client, url, 0, 4).await?
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
            let lfh = range_download(client, url, offset, 30).await?;
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

            let lfh = range_download(client, url, local_offset, 30).await?;
            let local_name_len = u16::from_le_bytes(lfh[26..28].try_into().unwrap()) as u64;
            let local_extra_len = u16::from_le_bytes(lfh[28..30].try_into().unwrap()) as u64;
            let data_offset = local_offset + 30 + local_name_len + local_extra_len;
            if name == "payload.bin" {
                payload_offset = Some(data_offset);
            } else {
                let data = range_download(client, url, data_offset, compressed_size).await?;
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

        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let client = Arc::new(client);
        let url: Arc<str> = Arc::from(url);
        let downloaded = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(tokio::sync::Semaphore::new(8));

        let mut handles = Vec::with_capacity(merged.len());
        for &(data_region_off, length) in &merged {
            let client = client.clone();
            let url = url.clone();
            let downloaded = downloaded.clone();
            let sem = sem.clone();
            let remote_off = payload_off + data_offset + data_region_off;

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let data = range_download(&client, &url, remote_off, length).await?;
                downloaded.fetch_add(data.len() as u64, Ordering::Relaxed);
                Ok::<_, anyhow::Error>((data_region_off, data))
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

        let mut range_data: Vec<(u64, Vec<u8>)> = Vec::with_capacity(merged.len());
        for handle in handles {
            let (off, data) = handle.await??;
            let done = downloaded.load(Ordering::Relaxed);
            pb.set_position(done);
            range_data.push((off, data));
        }
        pb.finish_and_clear();

        let mut buf = meta;
        let mut remap: HashMap<u64, (u64, u64)> = HashMap::new();

        for &(op_off, op_len) in &op_ranges {
            if remap.contains_key(&op_off) {
                continue;
            }
            for (merged_off, merged_data) in &range_data {
                if op_off >= *merged_off
                    && op_off + op_len <= *merged_off + merged_data.len() as u64
                {
                    let within = (op_off - *merged_off) as usize;
                    let compact_pos = buf.len() as u64;
                    buf.extend_from_slice(&merged_data[within..within + op_len as usize]);
                    remap.insert(op_off, (compact_pos, op_len));
                    break;
                }
            }
        }

        style::log(
            "Buffer",
            format_args!(
                "{} (meta {} + data {})",
                style::format_size(buf.len() as u64),
                style::format_size(meta_len),
                style::format_size(buf.len() as u64 - meta_len),
            ),
        );

        Ok(PayloadView::from_memory(buf, remap)?)
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
