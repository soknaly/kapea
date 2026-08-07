//! Safe archive inspection (Phase 4).

use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use flate2::read::GzDecoder;
use serde_json::json;
use tar::Archive;
use tracing::warn;
use zip::ZipArchive;

use super::pe::analyze_pe_bytes;
use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use super::yara::TextYaraEngine;
use crate::hashing::hash_bytes;
use crate::limits::ScanLimits;
use crate::models::ScanFinding;

const MAX_COMPRESSION_RATIO: u64 = 100;

pub struct ArchiveScanner {
    yara: TextYaraEngine,
}

impl ArchiveScanner {
    pub fn new(yara: TextYaraEngine) -> Self {
        Self { yara }
    }
}

#[derive(Debug, Default)]
struct ExtractionBudget {
    extracted_bytes: u64,
    file_count: u32,
    limit_exceeded: bool,
    limit_reason: Option<String>,
}

impl ExtractionBudget {
    fn check_limits(&mut self, limits: &ScanLimits, depth: u32) -> bool {
        if depth > limits.max_depth {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!("max depth {} exceeded", limits.max_depth));
            return false;
        }
        if self.file_count >= limits.max_files {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!("max files {} exceeded", limits.max_files));
            return false;
        }
        if self.extracted_bytes >= limits.max_extracted_bytes {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!(
                "max extracted bytes {} exceeded",
                limits.max_extracted_bytes
            ));
            return false;
        }
        true
    }

    fn record_file(&mut self, uncompressed_size: u64, compressed_size: u64, limits: &ScanLimits) {
        self.file_count += 1;
        self.extracted_bytes += uncompressed_size;

        if compressed_size > 0 && uncompressed_size / compressed_size.max(1) > MAX_COMPRESSION_RATIO
        {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!(
                "compression ratio {}:1 exceeds limit",
                uncompressed_size / compressed_size.max(1)
            ));
        }

        if self.extracted_bytes > limits.max_extracted_bytes {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!(
                "max extracted bytes {} exceeded",
                limits.max_extracted_bytes
            ));
        }
        if self.file_count > limits.max_files {
            self.limit_exceeded = true;
            self.limit_reason = Some(format!("max files {} exceeded", limits.max_files));
        }
    }
}

fn sanitize_member_path(name: &str) -> Option<String> {
    let path = Path::new(name);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if normalized.as_os_str().is_empty() {
        return None;
    }
    Some(normalized.to_string_lossy().replace('\\', "/"))
}

fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..2] == [0x50, 0x4B]
}

fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0..2] == [0x1F, 0x8B]
}

fn is_tar(data: &[u8]) -> bool {
    data.len() >= 262 && &data[257..262] == b"ustar"
}

/// RAR 1.5/4 (`Rar!\x1a\x07\x00`) and RAR 5 (`Rar!\x1a\x07\x01`).
fn is_rar(data: &[u8]) -> bool {
    data.len() >= 7 && data.starts_with(b"Rar!\x1a\x07")
}

/// 7z signature: `'7z'\xBC\xAF\x27\x1C`
fn is_7z(data: &[u8]) -> bool {
    data.len() >= 6 && data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
}

fn unrar_bin() -> String {
    std::env::var("UNRAR_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "unrar".into())
}

fn seven_z_bin() -> String {
    std::env::var("SEVEN_Z_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "7z".into())
}

fn archive_kind(data: &[u8], mime: Option<&str>, filename: &str) -> Option<&'static str> {
    // Prefer magic over extension — samples may use misleading suffixes (e.g. `.z`).
    if is_rar(data)
        || mime == Some("application/vnd.rar")
        || mime == Some("application/x-rar-compressed")
        || filename.to_ascii_lowercase().ends_with(".rar")
    {
        return Some("rar");
    }
    if is_7z(data)
        || mime == Some("application/x-7z-compressed")
        || filename.to_ascii_lowercase().ends_with(".7z")
    {
        return Some("7z");
    }
    if mime == Some("application/zip") || filename.ends_with(".zip") || is_zip(data) {
        return Some("zip");
    }
    if mime == Some("application/gzip")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || is_gzip(data)
    {
        return Some("tar.gz");
    }
    if mime == Some("application/x-tar") || filename.ends_with(".tar") || is_tar(data) {
        return Some("tar");
    }
    None
}

fn limit_finding(reason: &str) -> ScanFinding {
    ScanFinding {
        engine: "ARCHIVE".into(),
        code: "ARCHIVE_LIMIT_EXCEEDED".into(),
        category: "archive".into(),
        severity: 40,
        confidence: 95,
        message: format!("Archive extraction limit exceeded: {reason}"),
        technical_details: Some(json!({ "reason": reason })),
        path_inside_archive: None,
    }
}

fn scan_member_bytes(
    yara: &TextYaraEngine,
    data: &[u8],
    member_path: &str,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    let mime = infer::get(data).map(|k| k.mime_type().to_string());
    if let Some(mime) = &mime {
        findings.push(ScanFinding {
            engine: "FILE_TYPE".into(),
            code: "ARCHIVE_MEMBER_TYPE".into(),
            category: "archive".into(),
            severity: 0,
            confidence: 80,
            message: format!("Archive member {member_path} detected as {mime}"),
            technical_details: Some(json!({
                "detectedMimeType": mime,
                "memberPath": member_path,
            })),
            path_inside_archive: Some(member_path.to_string()),
        });
    }

    let hashes = hash_bytes(data);
    findings.push(ScanFinding {
        engine: "ARCHIVE".into(),
        code: "ARCHIVE_MEMBER_HASH".into(),
        category: "archive".into(),
        severity: 0,
        confidence: 100,
        message: format!("Archive member {member_path} hashed"),
        technical_details: Some(json!({
            "sha256": hashes.sha256,
            "sha1": hashes.sha1,
            "md5": hashes.md5,
            "memberPath": member_path,
        })),
        path_inside_archive: Some(member_path.to_string()),
    });

    for m in yara.scan_bytes(data) {
        let code = if m.rule_name.contains("Eicar") || m.rule_name == "EICAR_BUILTIN" {
            "YARA_EICAR"
        } else {
            "YARA_MATCH"
        };
        let parsed = crate::threat_labels::parse_threat_name(&m.rule_name);
        let category = parsed
            .threat_type
            .clone()
            .filter(|_| m.category == "malware" || m.category.is_empty())
            .unwrap_or_else(|| m.category.clone());
        findings.push(ScanFinding {
            engine: "YARA".into(),
            code: code.into(),
            category,
            severity: m.severity,
            confidence: 95,
            message: format!(
                "YARA rule {} matched in archive member {}",
                m.rule_name, member_path
            ),
            technical_details: Some(json!({
                "rule": m.rule_name,
                "string": m.string_name,
                "memberPath": member_path,
                "threatType": parsed.threat_type,
                "family": parsed.family,
                "label": parsed.label,
            })),
            path_inside_archive: Some(member_path.to_string()),
        });
    }

    if let Some((pe_findings, _)) = analyze_pe_bytes(data) {
        for mut f in pe_findings {
            f.path_inside_archive = Some(member_path.to_string());
            findings.push(f);
        }
    }

    findings
}

fn extract_zip(
    data: &[u8],
    dest: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
) -> Result<()> {
    if !budget.check_limits(limits, depth) {
        return Ok(());
    }

    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(err) => {
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_CORRUPT".into(),
                category: "archive".into(),
                severity: 20,
                confidence: 90,
                message: format!("Corrupt or unreadable ZIP archive: {err}"),
                technical_details: Some(json!({ "error": err.to_string() })),
                path_inside_archive: None,
            });
            return Ok(());
        }
    };

    for i in 0..archive.len() {
        if budget.limit_exceeded {
            break;
        }
        if !budget.check_limits(limits, depth) {
            break;
        }

        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if file.is_dir() {
            continue;
        }

        if file.encrypted() {
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_ENCRYPTED".into(),
                category: "archive".into(),
                severity: 25,
                confidence: 90,
                message: format!("Encrypted archive member skipped: {}", file.name()),
                technical_details: Some(json!({ "member": file.name() })),
                path_inside_archive: Some(file.name().to_string()),
            });
            continue;
        }

        let Some(safe_name) = sanitize_member_path(file.name()) else {
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_PATH_TRAVERSAL".into(),
                category: "archive".into(),
                severity: 50,
                confidence: 95,
                message: format!("Path traversal attempt blocked: {}", file.name()),
                technical_details: Some(json!({ "member": file.name() })),
                path_inside_archive: None,
            });
            continue;
        };

        let compressed = file.compressed_size();
        let uncompressed = file.size();
        budget.record_file(uncompressed, compressed, limits);
        if budget.limit_exceeded {
            break;
        }

        let mut member_data = Vec::with_capacity(uncompressed.min(1024 * 1024) as usize);
        if let Err(err) = file.read_to_end(&mut member_data) {
            warn!(member = %safe_name, %err, "failed to read archive member");
            continue;
        }

        findings.extend(scan_member_bytes(yara, &member_data, &safe_name));

        let member_dest = dest.join(&safe_name);
        if let Some(parent) = member_dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&member_dest, &member_data);

        if archive_kind(&member_data, None, &safe_name).is_some() && depth + 1 <= limits.max_depth {
            extract_nested(
                &member_data,
                &member_dest,
                limits,
                depth + 1,
                yara,
                budget,
                findings,
                &safe_name,
            )?;
        }
    }

    Ok(())
}

fn extract_tar_gz(
    data: &[u8],
    dest: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
) -> Result<()> {
    if !budget.check_limits(limits, depth) {
        return Ok(());
    }

    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = match Archive::new(decoder) {
        a => a,
    };

    for entry in archive.entries().context("read tar entries")? {
        if budget.limit_exceeded {
            break;
        }
        let mut entry = match entry {
            Ok(e) => e,
            Err(err) => {
                findings.push(ScanFinding {
                    engine: "ARCHIVE".into(),
                    code: "ARCHIVE_CORRUPT".into(),
                    category: "archive".into(),
                    severity: 20,
                    confidence: 85,
                    message: format!("Corrupt tar entry: {err}"),
                    technical_details: None,
                    path_inside_archive: None,
                });
                continue;
            }
        };

        let path = entry.path().context("tar entry path")?;
        let path_str = path.to_string_lossy();
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let Some(safe_name) = sanitize_member_path(&path_str) else {
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_PATH_TRAVERSAL".into(),
                category: "archive".into(),
                severity: 50,
                confidence: 95,
                message: format!("Path traversal attempt blocked: {path_str}"),
                technical_details: None,
                path_inside_archive: None,
            });
            continue;
        };

        let size = entry.size();
        budget.record_file(size, size, limits);
        if budget.limit_exceeded {
            break;
        }

        let mut member_data = Vec::new();
        if let Err(err) = entry.read_to_end(&mut member_data) {
            warn!(member = %safe_name, %err, "failed to read tar member");
            continue;
        }

        findings.extend(scan_member_bytes(yara, &member_data, &safe_name));

        let member_dest = dest.join(&safe_name);
        if let Some(parent) = member_dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&member_dest, &member_data);

        if archive_kind(&member_data, None, &safe_name).is_some() && depth + 1 <= limits.max_depth {
            extract_nested(
                &member_data,
                &member_dest,
                limits,
                depth + 1,
                yara,
                budget,
                findings,
                &safe_name,
            )?;
        }
    }

    Ok(())
}

fn extract_rar(
    data: &[u8],
    dest: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
) -> Result<()> {
    let unrar = unrar_bin();
    extract_via_cli(
        data,
        dest,
        limits,
        depth,
        yara,
        budget,
        findings,
        "RAR",
        ".kapea_container.rar",
        &unrar,
        |cmd, archive, dest| {
            cmd.args(["x", "-o+", "-idq", "--"])
                .arg(archive)
                .arg(format!("{}/", dest.display()));
        },
    )
}

fn extract_7z(
    data: &[u8],
    dest: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
) -> Result<()> {
    let seven_z = seven_z_bin();
    extract_via_cli(
        data,
        dest,
        limits,
        depth,
        yara,
        budget,
        findings,
        "7z",
        ".kapea_container.7z",
        &seven_z,
        |cmd, archive, dest| {
            // -o must be glued to the path (no space).
            cmd.arg("x")
                .arg(format!("-o{}", dest.display()))
                .args(["-y", "-bd", "--"])
                .arg(archive);
        },
    )
}

fn extract_via_cli(
    data: &[u8],
    dest: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
    format_label: &str,
    container_filename: &str,
    tool: &str,
    configure: impl FnOnce(&mut Command, &Path, &Path),
) -> Result<()> {
    if !budget.check_limits(limits, depth) {
        return Ok(());
    }

    let _ = std::fs::create_dir_all(dest);
    let archive_path = dest.join(container_filename);
    std::fs::write(&archive_path, data)
        .with_context(|| format!("write {format_label} for extraction"))?;

    let timeout = Duration::from_secs(limits.timeout_seconds.max(1));

    let mut cmd = Command::new(tool);
    configure(&mut cmd, &archive_path, dest);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&archive_path);
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_TOOL_MISSING".into(),
                category: "archive".into(),
                severity: 40,
                confidence: 95,
                message: format!(
                    "{format_label} archive detected but `{tool}` is not available"
                ),
                technical_details: Some(json!({ "tool": tool, "error": err.to_string() })),
                path_inside_archive: None,
            });
            return Ok(());
        }
        Err(err) => {
            let _ = std::fs::remove_file(&archive_path);
            return Err(err).with_context(|| format!("spawn {tool}"));
        }
    };

    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("wait {tool}"))?
        {
            break status;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&archive_path);
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_LIMIT_EXCEEDED".into(),
                category: "archive".into(),
                severity: 40,
                confidence: 95,
                message: format!(
                    "{format_label} extraction exceeded timeout of {} seconds",
                    limits.timeout_seconds
                ),
                technical_details: Some(json!({ "timeoutSeconds": limits.timeout_seconds })),
                path_inside_archive: None,
            });
            budget.limit_exceeded = true;
            budget.limit_reason = Some(format!(
                "{format_label} extraction timeout {}s",
                limits.timeout_seconds
            ));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let stderr = child
        .stderr
        .take()
        .map(|mut s| {
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
        .unwrap_or_default();

    if !status.success() {
        let _ = std::fs::remove_file(&archive_path);
        findings.push(ScanFinding {
            engine: "ARCHIVE".into(),
            code: "EXTRACTION_FAILED".into(),
            category: "archive".into(),
            severity: 40,
            confidence: 90,
            message: format!(
                "{format_label} extraction failed (exit {})",
                status.code().unwrap_or(-1)
            ),
            technical_details: Some(json!({
                "stderr": stderr.chars().take(500).collect::<String>(),
            })),
            path_inside_archive: None,
        });
        return Ok(());
    }

    ingest_extracted_tree(
        dest,
        &archive_path,
        limits,
        depth,
        yara,
        budget,
        findings,
        "",
    )?;

    let _ = std::fs::remove_file(&archive_path);
    Ok(())
}

fn ingest_extracted_tree(
    root: &Path,
    skip: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
    path_prefix: &str,
) -> Result<()> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(err) => {
            warn!(path = %root.display(), %err, "failed to read extract dir");
            return Ok(());
        }
    };

    for entry in entries {
        if budget.limit_exceeded || !budget.check_limits(limits, depth) {
            break;
        }
        let entry = entry.context("read extract dir entry")?;
        let path = entry.path();
        if path == skip {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        let member_rel = if path_prefix.is_empty() {
            name.clone()
        } else {
            format!("{path_prefix}/{name}")
        };

        let Some(safe_name) = sanitize_member_path(&member_rel) else {
            findings.push(ScanFinding {
                engine: "ARCHIVE".into(),
                code: "ARCHIVE_PATH_TRAVERSAL".into(),
                category: "archive".into(),
                severity: 50,
                confidence: 95,
                message: format!("Path traversal attempt blocked: {member_rel}"),
                technical_details: Some(json!({ "member": member_rel })),
                path_inside_archive: None,
            });
            continue;
        };

        let meta = entry.metadata().context("member metadata")?;
        if meta.is_dir() {
            ingest_extracted_tree(
                &path,
                skip,
                limits,
                depth,
                yara,
                budget,
                findings,
                &safe_name,
            )?;
            continue;
        }
        if !meta.is_file() {
            continue;
        }

        let size = meta.len();
        budget.record_file(size, size, limits);
        if budget.limit_exceeded {
            break;
        }

        let member_data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(err) => {
                warn!(member = %safe_name, %err, "failed to read extracted member");
                continue;
            }
        };

        findings.extend(scan_member_bytes(yara, &member_data, &safe_name));

        if archive_kind(&member_data, None, &safe_name).is_some() && depth + 1 <= limits.max_depth {
            extract_nested(
                &member_data,
                &path,
                limits,
                depth + 1,
                yara,
                budget,
                findings,
                &safe_name,
            )?;
        }
    }

    Ok(())
}

fn extract_nested(
    data: &[u8],
    _member_path: &Path,
    limits: &ScanLimits,
    depth: u32,
    yara: &TextYaraEngine,
    budget: &mut ExtractionBudget,
    findings: &mut Vec<ScanFinding>,
    path_prefix: &str,
) -> Result<()> {
    let nested_dest = _member_path.with_extension("nested");
    let _ = std::fs::create_dir_all(&nested_dest);

    let kind = archive_kind(data, None, path_prefix);
    match kind {
        Some("zip") => extract_zip(data, &nested_dest, limits, depth, yara, budget, findings)?,
        Some("tar.gz") | Some("tar") => {
            extract_tar_gz(data, &nested_dest, limits, depth, yara, budget, findings)?
        }
        Some("rar") => extract_rar(data, &nested_dest, limits, depth, yara, budget, findings)?,
        Some("7z") => extract_7z(data, &nested_dest, limits, depth, yara, budget, findings)?,
        _ => {}
    }
    Ok(())
}

pub fn inspect_archive(
    data: &[u8],
    extract_dir: &Path,
    limits: &ScanLimits,
    yara: &TextYaraEngine,
    mime: Option<&str>,
    filename: &str,
) -> (Vec<ScanFinding>, bool) {
    let mut findings = Vec::new();
    let mut budget = ExtractionBudget::default();

    let Some(kind) = archive_kind(data, mime, filename) else {
        return (findings, true);
    };

    let _ = std::fs::create_dir_all(extract_dir);

    let result = match kind {
        "zip" => extract_zip(data, extract_dir, limits, 1, yara, &mut budget, &mut findings),
        "tar.gz" | "tar" => {
            extract_tar_gz(data, extract_dir, limits, 1, yara, &mut budget, &mut findings)
        }
        "rar" => extract_rar(data, extract_dir, limits, 1, yara, &mut budget, &mut findings),
        "7z" => extract_7z(data, extract_dir, limits, 1, yara, &mut budget, &mut findings),
        _ => Ok(()),
    };

    if let Err(err) = result {
        findings.push(ScanFinding {
            engine: "ARCHIVE".into(),
            code: "EXTRACTION_FAILED".into(),
            category: "archive".into(),
            severity: 30,
            confidence: 90,
            message: format!("Archive extraction failed: {err}"),
            technical_details: Some(json!({ "error": err.to_string() })),
            path_inside_archive: None,
        });
    }

    if budget.limit_exceeded {
        if let Some(reason) = budget.limit_reason {
            findings.push(limit_finding(&reason));
        }
    }

    let complete = !budget.limit_exceeded;
    (findings, complete)
}

#[async_trait]
impl FileScanner for ArchiveScanner {
    fn name(&self) -> &'static str {
        "ARCHIVE"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;
        let extract_dir = ctx
            .work_dir
            .join(format!("{}_{}_archive", ctx.scan_id, ctx.file_id));

        let (findings, complete) = inspect_archive(
            &data,
            &extract_dir,
            &ctx.limits,
            &self.yara,
            ctx.detected_mime_type.as_deref(),
            &ctx.original_filename,
        );

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("archive-v1".into()),
            complete,
            findings,
            metadata: Some(json!({
                "extractDir": extract_dir,
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn test_yara() -> TextYaraEngine {
        TextYaraEngine::empty()
    }

    #[test]
    fn zip_member_path_in_findings() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();
            zip.start_file("inner/eicar.txt", options).unwrap();
            zip.write_all(b"hello member").unwrap();
            zip.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let limits = ScanLimits {
            max_extracted_bytes: 1_000_000,
            max_files: 100,
            max_depth: 5,
            timeout_seconds: 60,
        };

        let (findings, complete) =
            inspect_archive(&buf, dir.path(), &limits, &test_yara(), None, "test.zip");

        assert!(complete);
        assert!(
            findings
                .iter()
                .any(|f| f.path_inside_archive.as_deref() == Some("inner/eicar.txt"))
        );
    }

    #[test]
    fn archive_file_limit_enforced() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();
            for i in 0..5 {
                zip.start_file(format!("file{i}.txt"), options)
                    .unwrap();
                zip.write_all(b"x").unwrap();
            }
            zip.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let limits = ScanLimits {
            max_extracted_bytes: 1_000_000,
            max_files: 2,
            max_depth: 5,
            timeout_seconds: 60,
        };

        let (findings, complete) =
            inspect_archive(&buf, dir.path(), &limits, &test_yara(), None, "test.zip");

        assert!(!complete);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "ARCHIVE_LIMIT_EXCEEDED")
        );
    }

    #[test]
    fn blocks_path_traversal() {
        assert!(sanitize_member_path("../etc/passwd").is_none());
        assert!(sanitize_member_path("/etc/passwd").is_none());
        assert_eq!(
            sanitize_member_path("safe/nested.txt").as_deref(),
            Some("safe/nested.txt")
        );
    }

    #[test]
    fn detects_rar_magic_despite_z_extension() {
        let mut data = b"Rar!\x1a\x07\x00".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            archive_kind(&data, None, "virus.z"),
            Some("rar")
        );
    }

    #[test]
    fn detects_7z_magic() {
        let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(archive_kind(&data, None, "payload.bin"), Some("7z"));
        assert_eq!(
            archive_kind(b"not7z", Some("application/x-7z-compressed"), "x.7z"),
            Some("7z")
        );
    }

    #[test]
    fn archive_depth_limit_enforced() {
        let mut inner_buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut inner_buf));
            let options = SimpleFileOptions::default();
            zip.start_file("leaf.txt", options).unwrap();
            zip.write_all(b"nested").unwrap();
            zip.finish().unwrap();
        }

        let mut outer_buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut outer_buf));
            let options = SimpleFileOptions::default();
            zip.start_file("nested.zip", options).unwrap();
            zip.write_all(&inner_buf).unwrap();
            zip.finish().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let limits = ScanLimits {
            max_extracted_bytes: 1_000_000,
            max_files: 100,
            max_depth: 0,
            timeout_seconds: 60,
        };

        let (findings, complete) =
            inspect_archive(&outer_buf, dir.path(), &limits, &test_yara(), None, "test.zip");

        assert!(!complete);
        assert!(
            findings
                .iter()
                .any(|f| f.code == "ARCHIVE_LIMIT_EXCEEDED")
        );
    }
}
