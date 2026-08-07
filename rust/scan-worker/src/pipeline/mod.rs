//! Scan pipeline orchestration for Phases 2–4.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use tokio::fs;
use tracing::{info, warn};

use crate::config::Config;
use crate::hashing::{hash_file, verify_integrity, HashVerificationError};
use crate::limits::ScanLimits;
use crate::messaging;
use crate::models::{
    ExtractedIndicator, FileHashes, ScanCompletedEvent, ScanFinding, ScanLimitsPayload,
    ScanProgressEvent, ScanRequestedEvent, ScanStage, ScanTiming, ScannerOutput, StorageRef,
    Verdict,
};
use crate::progress::ProgressSink;
use crate::risk;
use crate::scanners::archive::ArchiveScanner;
use crate::scanners::clamav::ClamAvScanner;
use crate::scanners::elf::ElfAnalyzer;
use crate::scanners::file_type::FileTypeScanner;
use crate::scanners::indicator::IndicatorExtractor;
use crate::scanners::office::OfficeAnalyzer;
use crate::scanners::pdf::PdfAnalyzer;
use crate::scanners::pe::PeAnalyzer;
use crate::scanners::script::ScriptAnalyzer;
use crate::scanners::trait_def::{FileScanner, ScannerContext};
use crate::scanners::yara::{TextYaraEngine, YaraScanner};
use crate::storage::ObjectStore;

pub struct ScanPipeline {
    config: Config,
    storage: Option<ObjectStore>,
    /// When true (local `--file` mode), unreachable ClamAV is skipped instead of failing open.
    clamav_optional: bool,
    clamav: ClamAvScanner,
    yara: YaraScanner,
    file_type: FileTypeScanner,
    archive: ArchiveScanner,
    pdf: PdfAnalyzer,
    office: OfficeAnalyzer,
    pe: PeAnalyzer,
    elf: ElfAnalyzer,
    script: ScriptAnalyzer,
    indicator: IndicatorExtractor,
}

impl ScanPipeline {
    pub async fn new(config: Config) -> Result<Self> {
        Self::build(config, true).await
    }

    /// Local CLI mode — no object storage / Redis required.
    pub async fn new_local(config: Config) -> Result<Self> {
        Self::build(config, false).await
    }

    async fn build(config: Config, with_storage: bool) -> Result<Self> {
        fs::create_dir_all(&config.work_dir)
            .await
            .with_context(|| format!("create work dir {}", config.work_dir))?;

        let storage = if with_storage {
            Some(ObjectStore::from_env().await?)
        } else {
            None
        };
        let yara_rules_path = Path::new(&config.yara_rules_path);
        let yara = YaraScanner::new(yara_rules_path)?;
        let yara_engine = TextYaraEngine::load_from_dir(yara_rules_path)?;
        let archive = ArchiveScanner::new(yara_engine);
        let clamav = ClamAvScanner::new(config.clamav_host.clone(), config.clamav_port);

        Ok(Self {
            config,
            storage,
            clamav_optional: !with_storage,
            clamav,
            yara,
            file_type: FileTypeScanner,
            archive,
            pdf: PdfAnalyzer,
            office: OfficeAnalyzer,
            pe: PeAnalyzer,
            elf: ElfAnalyzer,
            script: ScriptAnalyzer,
            indicator: IndicatorExtractor,
        })
    }

    pub async fn handle_scan_requested(
        &self,
        job: &mut bullmq::Job,
        event: ScanRequestedEvent,
    ) -> Result<ScanCompletedEvent> {
        let mut progress = ProgressSink::BullMq(job);
        self.run_scan(&mut progress, event, true).await
    }

    /// Scan a local file without queue or object storage.
    pub async fn scan_local_file(&self, path: &Path) -> Result<ScanCompletedEvent> {
        let absolute = fs::canonicalize(path)
            .await
            .with_context(|| format!("resolve local file {}", path.display()))?;
        let filename = absolute
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();

        let hash_result = hash_file(&absolute).await?;
        let defaults = ScanLimits::default();
        let event = ScanRequestedEvent {
            event_id: messaging::new_event_id("evt"),
            event_type: "scan.requested".into(),
            event_version: 1,
            occurred_at: Utc::now(),
            correlation_id: messaging::new_event_id("corr"),
            scan_id: messaging::new_event_id("scan"),
            file_id: messaging::new_event_id("file"),
            trace_id: messaging::new_event_id("trace"),
            storage: StorageRef {
                bucket: "local".into(),
                object_key: absolute.display().to_string(),
            },
            expected_size_bytes: hash_result.size_bytes,
            expected_sha256: Some(hash_result.hashes.sha256.clone()),
            original_filename: filename,
            claimed_mime_type: None,
            limits: ScanLimitsPayload {
                max_extracted_bytes: defaults.max_extracted_bytes,
                max_files: defaults.max_files,
                max_depth: defaults.max_depth,
                timeout_seconds: defaults.timeout_seconds,
            },
        };

        let work_path = self.work_file_path(&event.scan_id, &event.file_id);
        fs::copy(&absolute, &work_path)
            .await
            .with_context(|| format!("copy {} to work dir", absolute.display()))?;

        let mut progress = ProgressSink::Local;
        self.run_scan(&mut progress, event, false).await
    }

    async fn run_scan(
        &self,
        progress: &mut ProgressSink<'_>,
        event: ScanRequestedEvent,
        fetch_from_storage: bool,
    ) -> Result<ScanCompletedEvent> {
        let started_at = Utc::now();
        let work_path = self.work_file_path(&event.scan_id, &event.file_id);
        let archive_dir = self.archive_dir_path(&event.scan_id, &event.file_id);

        if !fetch_from_storage && !work_path.exists() {
            anyhow::bail!("local work file missing at {}", work_path.display());
        }

        match self
            .process_scan(progress, &event, &work_path, started_at, fetch_from_storage)
            .await
        {
            Ok(completed) => {
                self.cleanup_work_artifacts(&work_path, &archive_dir).await;
                Ok(completed)
            }
            Err(err) => {
                warn!(scan_id = %event.scan_id, %err, "scan pipeline failed");
                self.cleanup_work_artifacts(&work_path, &archive_dir).await;
                Ok(self.failed_completion(&event, started_at, err.to_string()))
            }
        }
    }

    async fn process_scan(
        &self,
        progress: &mut ProgressSink<'_>,
        event: &ScanRequestedEvent,
        work_path: &Path,
        started_at: chrono::DateTime<Utc>,
        fetch_from_storage: bool,
    ) -> Result<ScanCompletedEvent> {
        let limits: ScanLimits = event.limits.clone().into();
        let timeout_ms = limits.timeout_seconds * 1000;
        let work_dir = PathBuf::from(&self.config.work_dir);

        if fetch_from_storage {
            self.publish_progress(
                progress,
                event,
                ScanStage::Download,
                10,
                Some("Downloading quarantined object"),
            )
            .await?;

            let storage = self
                .storage
                .as_ref()
                .context("object storage is not configured")?;
            let downloaded = storage
                .download_to_path(&event.storage.object_key, work_path)
                .await
                .context("download quarantined object")?;

            if downloaded != event.expected_size_bytes {
                warn!(
                    downloaded,
                    expected = event.expected_size_bytes,
                    "download byte count differs from expected size"
                );
            }
        } else {
            self.publish_progress(
                progress,
                event,
                ScanStage::Download,
                10,
                Some("Using local file"),
            )
            .await?;
        }

        self.publish_progress(
            progress,
            event,
            ScanStage::HashVerify,
            25,
            Some("Verifying integrity"),
        )
        .await?;

        let hash_result = hash_file(work_path).await?;
        if let Err(err) = verify_integrity(
            hash_result.size_bytes,
            event.expected_size_bytes,
            &hash_result.hashes.sha256,
            event.expected_sha256.as_deref(),
        ) {
            return self.integrity_failure(event, &err, started_at, hash_result.hashes);
        }

        self.publish_progress(
            progress,
            event,
            ScanStage::FileType,
            40,
            Some("Detecting file type"),
        )
        .await?;

        let ctx = ScannerContext {
            scan_id: event.scan_id.clone(),
            file_id: event.file_id.clone(),
            file_path: work_path.to_path_buf(),
            original_filename: event.original_filename.clone(),
            detected_mime_type: None,
            timeout_ms,
            limits: limits.clone(),
            work_dir: work_dir.clone(),
            path_inside_archive: None,
        };

        let file_type_output = self.file_type.scan(&ctx).await?;
        let detected_mime = file_type_output
            .metadata
            .as_ref()
            .and_then(|m| m.get("detectedMimeType"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let mut findings = normalize_findings(vec![file_type_output.clone()]);
        if let Some(mismatch) =
            extension_mismatch_finding(&event.original_filename, detected_mime.as_deref())
        {
            findings.push(mismatch);
        }

        self.publish_progress(
            progress,
            event,
            ScanStage::ClamavScan,
            55,
            Some("Running ClamAV"),
        )
        .await?;

        let scan_ctx = ScannerContext {
            detected_mime_type: detected_mime.clone(),
            ..ctx.clone()
        };

        let clamav_output = self.scan_clamav(&scan_ctx).await?;
        findings.extend(normalize_findings(vec![clamav_output.clone()]));

        self.publish_progress(progress, event, ScanStage::YaraScan, 65, Some("Running YARA"))
            .await?;

        let yara_output = self.yara.scan(&scan_ctx).await?;
        findings.extend(normalize_findings(vec![yara_output.clone()]));

        self.publish_progress(
            progress,
            event,
            ScanStage::ArchiveInspect,
            75,
            Some("Inspecting archives"),
        )
        .await?;

        let archive_output = self.archive.scan(&scan_ctx).await?;
        findings.extend(normalize_findings(vec![archive_output.clone()]));

        self.publish_progress(
            progress,
            event,
            ScanStage::FormatAnalyze,
            85,
            Some("Running format-specific analyzers"),
        )
        .await?;

        let mut format_outputs = Vec::new();
        for analyzer in format_analyzers_for(&detected_mime, &event.original_filename) {
            let output = match analyzer {
                FormatAnalyzerKind::Pdf => self.pdf.scan(&scan_ctx).await?,
                FormatAnalyzerKind::Office => self.office.scan(&scan_ctx).await?,
                FormatAnalyzerKind::Pe => self.pe.scan(&scan_ctx).await?,
                FormatAnalyzerKind::Elf => self.elf.scan(&scan_ctx).await?,
                FormatAnalyzerKind::Script => self.script.scan(&scan_ctx).await?,
            };
            findings.extend(normalize_findings(vec![output.clone()]));
            format_outputs.push(output);
        }

        self.publish_progress(
            progress,
            event,
            ScanStage::IndicatorExtract,
            92,
            Some("Extracting indicators"),
        )
        .await?;

        let indicator_output = self.indicator.scan(&scan_ctx).await?;
        findings.extend(normalize_findings(vec![indicator_output.clone()]));
        let extracted_indicators = indicator_output
            .metadata
            .as_ref()
            .and_then(|m| m.get("extractedIndicators"))
            .and_then(|v| serde_json::from_value::<Vec<ExtractedIndicator>>(v.clone()).ok());

        self.publish_progress(
            progress,
            event,
            ScanStage::RiskScore,
            95,
            Some("Calculating risk score"),
        )
        .await?;

        let mut scanner_outputs =
            vec![file_type_output, clamav_output, yara_output, archive_output];
        scanner_outputs.extend(format_outputs);
        scanner_outputs.push(indicator_output);

        let mut scan_complete = true;
        for output in &scanner_outputs {
            if !output.complete {
                scan_complete = false;
            }
        }

        let assessment = risk::assess(&findings, &scanner_outputs, false);
        let scan_complete = scan_complete && assessment.scan_complete;
        let threat_labels = {
            let labels = crate::threat_labels::aggregate(&findings);
            if labels.is_empty() {
                None
            } else {
                Some(labels)
            }
        };

        let mut scanner_versions = HashMap::new();
        for output in &scanner_outputs {
            if let Some(version) = &output.version {
                scanner_versions.insert(output.engine.clone(), version.clone());
            }
        }

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0) as u64;

        let completed = ScanCompletedEvent {
            event_id: messaging::new_event_id("evt"),
            event_type: "scan.completed".into(),
            event_version: 1,
            occurred_at: completed_at,
            correlation_id: event.correlation_id.clone(),
            scan_id: event.scan_id.clone(),
            file_id: event.file_id.clone(),
            trace_id: event.trace_id.clone(),
            scan_complete,
            detected_file_type: detected_mime,
            hashes: hash_result.hashes,
            findings,
            risk_score: assessment.risk_score,
            automated_verdict: assessment.verdict,
            summary: assessment.summary,
            scanner_versions,
            timing: ScanTiming {
                started_at,
                completed_at,
                duration_ms,
            },
            worker_id: self.config.worker_id.clone(),
            extracted_indicators,
            threat_labels,
        };

        self.publish_progress(progress, event, ScanStage::Complete, 100, Some("Scan complete"))
            .await?;

        info!(
            scan_id = %event.scan_id,
            verdict = %completed.automated_verdict.as_str(),
            risk_score = completed.risk_score,
            "scan completed"
        );

        Ok(completed)
    }

    async fn scan_clamav(&self, ctx: &ScannerContext) -> Result<ScannerOutput> {
        if self.clamav_optional {
            match self.clamav.ping().await {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    info!(
                        host = %self.config.clamav_host,
                        port = self.config.clamav_port,
                        "ClamAV not reachable — skipping (start clamav via docker compose to enable)"
                    );
                    return Ok(ScannerOutput {
                        engine: "CLAMAV".into(),
                        version: None,
                        complete: true,
                        findings: vec![],
                        metadata: Some(json!({
                            "skipped": true,
                            "reason": "unreachable",
                        })),
                    });
                }
            }
        }

        self.clamav.scan(ctx).await
    }

    fn integrity_failure(
        &self,
        event: &ScanRequestedEvent,
        err: &HashVerificationError,
        started_at: chrono::DateTime<Utc>,
        hashes: FileHashes,
    ) -> Result<ScanCompletedEvent> {
        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0) as u64;

        let completed = ScanCompletedEvent {
            event_id: messaging::new_event_id("evt"),
            event_type: "scan.completed".into(),
            event_version: 1,
            occurred_at: completed_at,
            correlation_id: event.correlation_id.clone(),
            scan_id: event.scan_id.clone(),
            file_id: event.file_id.clone(),
            trace_id: event.trace_id.clone(),
            scan_complete: false,
            detected_file_type: None,
            hashes,
            findings: vec![],
            risk_score: 0,
            automated_verdict: Verdict::ScanFailed,
            summary: format!("Integrity verification failed: {}", err.message),
            scanner_versions: HashMap::new(),
            timing: ScanTiming {
                started_at,
                completed_at,
                duration_ms,
            },
            worker_id: self.config.worker_id.clone(),
            extracted_indicators: None,
            threat_labels: None,
        };

        Ok(completed)
    }

    fn failed_completion(
        &self,
        event: &ScanRequestedEvent,
        started_at: chrono::DateTime<Utc>,
        error_message: String,
    ) -> ScanCompletedEvent {
        let completed_at = Utc::now();
        ScanCompletedEvent {
            event_id: messaging::new_event_id("evt"),
            event_type: "scan.completed".into(),
            event_version: 1,
            occurred_at: completed_at,
            correlation_id: event.correlation_id.clone(),
            scan_id: event.scan_id.clone(),
            file_id: event.file_id.clone(),
            trace_id: event.trace_id.clone(),
            scan_complete: false,
            detected_file_type: None,
            hashes: FileHashes {
                sha256: "0".repeat(64),
                sha1: "0".repeat(40),
                md5: "0".repeat(32),
            },
            findings: vec![],
            risk_score: 0,
            automated_verdict: Verdict::ScanFailed,
            summary: format!("Scan pipeline failed: {error_message}"),
            scanner_versions: HashMap::new(),
            timing: ScanTiming {
                started_at,
                completed_at,
                duration_ms: (completed_at - started_at).num_milliseconds().max(0) as u64,
            },
            worker_id: self.config.worker_id.clone(),
            extracted_indicators: None,
            threat_labels: None,
        }
    }

    async fn publish_progress(
        &self,
        progress: &mut ProgressSink<'_>,
        event: &ScanRequestedEvent,
        stage: ScanStage,
        pct: u8,
        message: Option<&str>,
    ) -> Result<()> {
        let progress_event = ScanProgressEvent {
            event_id: messaging::new_event_id("evt"),
            event_type: "scan.progress".into(),
            event_version: 1,
            occurred_at: Utc::now(),
            correlation_id: event.correlation_id.clone(),
            scan_id: event.scan_id.clone(),
            file_id: event.file_id.clone(),
            trace_id: event.trace_id.clone(),
            status: "SCANNING".into(),
            progress: pct,
            current_stage: stage,
            worker_id: self.config.worker_id.clone(),
            message: message.map(str::to_string),
        };
        progress.report(&progress_event).await
    }

    fn work_file_path(&self, scan_id: &str, file_id: &str) -> PathBuf {
        PathBuf::from(&self.config.work_dir).join(format!("{scan_id}_{file_id}"))
    }

    fn archive_dir_path(&self, scan_id: &str, file_id: &str) -> PathBuf {
        PathBuf::from(&self.config.work_dir).join(format!("{scan_id}_{file_id}_archive"))
    }

    async fn cleanup_work_artifacts(&self, path: &Path, archive_dir: &Path) {
        if path.exists() {
            if let Err(err) = fs::remove_file(path).await {
                warn!(path = %path.display(), %err, "failed to remove temp scan file");
            }
        }
        if archive_dir.exists() {
            if let Err(err) = fs::remove_dir_all(archive_dir).await {
                warn!(path = %archive_dir.display(), %err, "failed to remove archive extract dir");
            }
        }
    }
}

enum FormatAnalyzerKind {
    Pdf,
    Office,
    Pe,
    Elf,
    Script,
}

fn format_analyzers_for(mime: &Option<String>, filename: &str) -> Vec<FormatAnalyzerKind> {
    let mut analyzers = Vec::new();
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    let mime_str = mime.as_deref().unwrap_or("");
    let is_pdf = mime_str == "application/pdf" || ext.as_deref() == Some("pdf");
    let is_office = mime_str.contains("officedocument")
        || mime_str.contains("msword")
        || mime_str.contains("ms-excel")
        || mime_str.contains("ms-powerpoint")
        || matches!(
            ext.as_deref(),
            Some("doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf")
        );
    let is_pe = mime_str.contains("msdownload")
        || mime_str.contains("portable-executable")
        || mime_str.contains("dosexec")
        || matches!(ext.as_deref(), Some("exe" | "dll" | "sys"));
    let is_elf = mime_str == "application/x-executable"
        || mime_str == "application/x-sharedlib"
        || mime_str == "application/x-pie-executable"
        || ext.as_deref() == Some("so");
    let is_script = mime_str.starts_with("text/")
        || matches!(
            ext.as_deref(),
            Some("js" | "ps1" | "bat" | "cmd" | "sh" | "bash" | "py" | "vbs")
        );

    if is_pdf {
        analyzers.push(FormatAnalyzerKind::Pdf);
    }
    if is_office {
        analyzers.push(FormatAnalyzerKind::Office);
    }
    if is_pe {
        analyzers.push(FormatAnalyzerKind::Pe);
    }
    if is_elf {
        analyzers.push(FormatAnalyzerKind::Elf);
    }
    if is_script {
        analyzers.push(FormatAnalyzerKind::Script);
    }

    analyzers
}

fn normalize_findings(outputs: Vec<ScannerOutput>) -> Vec<ScanFinding> {
    outputs.into_iter().flat_map(|o| o.findings).collect()
}

fn extension_mismatch_finding(filename: &str, detected_mime: Option<&str>) -> Option<ScanFinding> {
    let detected = detected_mime?;
    let extension = Path::new(filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)?;

    let expected = extension_expected_mime(&extension)?;
    if mime_compatible(expected, detected) {
        return None;
    }

    Some(ScanFinding {
        engine: "FILE_TYPE".into(),
        code: "EXTENSION_MISMATCH".into(),
        category: "integrity".into(),
        severity: 25,
        confidence: 80,
        message: format!(
            "Filename extension .{extension} suggests {expected}, detected {detected}"
        ),
        technical_details: Some(json!({
            "extension": extension,
            "expectedMime": expected,
            "detectedMime": detected,
        })),
        path_inside_archive: None,
    })
}

fn extension_expected_mime(ext: &str) -> Option<&'static str> {
    match ext {
        "pdf" => Some("application/pdf"),
        "zip" => Some("application/zip"),
        "exe" | "dll" => Some("application/x-msdownload"),
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "txt" => Some("text/plain"),
        "html" | "htm" => Some("text/html"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xls" => Some("application/vnd.ms-excel"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        _ => None,
    }
}

fn mime_compatible(expected: &str, detected: &str) -> bool {
    if expected == detected {
        return true;
    }

    let pe_mimes = [
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
        "application/x-dosexec",
    ];
    if pe_mimes.contains(&expected) && pe_mimes.contains(&detected) {
        return true;
    }

    if expected.starts_with("text/") && detected.starts_with("text/") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_mismatch_detected_for_pdf_named_txt() {
        let finding = extension_mismatch_finding("report.txt", Some("application/pdf"));
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().code, "EXTENSION_MISMATCH");
    }

    #[test]
    fn matching_extension_no_finding() {
        assert!(extension_mismatch_finding("report.pdf", Some("application/pdf")).is_none());
    }

    #[test]
    fn format_analyzers_include_pdf_and_script() {
        let analyzers = format_analyzers_for(&Some("application/pdf".into()), "doc.pdf");
        assert!(analyzers
            .iter()
            .any(|a| matches!(a, FormatAnalyzerKind::Pdf)));

        let script = format_analyzers_for(&Some("text/plain".into()), "run.ps1");
        assert!(script
            .iter()
            .any(|a| matches!(a, FormatAnalyzerKind::Script)));
    }
}
