//! Shared scan models aligned with `@kapea/contracts`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::limits::ScanLimits;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFinding {
    pub engine: String,
    pub code: String,
    pub category: String,
    pub severity: u8,
    pub confidence: u8,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_inside_archive: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerOutput {
    pub engine: String,
    pub version: Option<String>,
    pub complete: bool,
    pub findings: Vec<ScanFinding>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
    ScanFailed,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Suspicious => "SUSPICIOUS",
            Self::Malicious => "MALICIOUS",
            Self::Unknown => "UNKNOWN",
            Self::ScanFailed => "SCAN_FAILED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStage {
    Queued,
    Download,
    HashVerify,
    FileType,
    ClamavScan,
    YaraScan,
    ArchiveInspect,
    FormatAnalyze,
    IndicatorExtract,
    RiskScore,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRef {
    pub bucket: String,
    pub object_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequestedEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub occurred_at: DateTime<Utc>,
    pub correlation_id: String,
    pub scan_id: String,
    pub file_id: String,
    pub trace_id: String,
    pub storage: StorageRef,
    pub expected_size_bytes: u64,
    pub expected_sha256: Option<String>,
    pub original_filename: String,
    pub claimed_mime_type: Option<String>,
    pub limits: ScanLimitsPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLimitsPayload {
    pub max_extracted_bytes: u64,
    pub max_files: u32,
    pub max_depth: u32,
    pub timeout_seconds: u64,
}

impl From<ScanLimitsPayload> for ScanLimits {
    fn from(value: ScanLimitsPayload) -> Self {
        Self {
            max_extracted_bytes: value.max_extracted_bytes,
            max_files: value.max_files,
            max_depth: value.max_depth,
            timeout_seconds: value.timeout_seconds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub occurred_at: DateTime<Utc>,
    pub correlation_id: String,
    pub scan_id: String,
    pub file_id: String,
    pub trace_id: String,
    pub status: String,
    pub progress: u8,
    pub current_stage: ScanStage,
    pub worker_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTiming {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompletedEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub occurred_at: DateTime<Utc>,
    pub correlation_id: String,
    pub scan_id: String,
    pub file_id: String,
    pub trace_id: String,
    pub scan_complete: bool,
    pub detected_file_type: Option<String>,
    pub hashes: FileHashes,
    pub findings: Vec<ScanFinding>,
    pub risk_score: u8,
    pub automated_verdict: Verdict,
    pub summary: String,
    pub scanner_versions: std::collections::HashMap<String, String>,
    pub timing: ScanTiming,
    pub worker_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_indicators: Option<Vec<ExtractedIndicator>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_labels: Option<crate::threat_labels::ThreatLabels>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedIndicator {
    #[serde(alias = "kind")]
    pub indicator_type: String,
    #[serde(alias = "value")]
    pub indicator_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pathInsideArchive")]
    pub source_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFailedEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_version: u32,
    pub occurred_at: DateTime<Utc>,
    pub correlation_id: String,
    pub scan_id: String,
    pub file_id: String,
    pub trace_id: String,
    pub error_code: String,
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default)]
    pub retryable: bool,
}

impl ScanRequestedEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.event_type != "scan.requested" {
            return Err(format!("unexpected eventType: {}", self.event_type));
        }
        if self.event_version != 1 {
            return Err(format!("unsupported eventVersion: {}", self.event_version));
        }
        if self.event_id.is_empty() {
            return Err("eventId is required".into());
        }
        if self.scan_id.is_empty() {
            return Err("scanId is required".into());
        }
        if self.file_id.is_empty() {
            return Err("fileId is required".into());
        }
        if self.storage.bucket.is_empty() || self.storage.object_key.is_empty() {
            return Err("storage bucket and objectKey are required".into());
        }
        if self.original_filename.is_empty() {
            return Err("originalFilename is required".into());
        }
        Ok(())
    }
}
