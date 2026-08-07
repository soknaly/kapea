use async_trait::async_trait;
use std::path::PathBuf;

pub use crate::models::ScannerOutput;
use crate::limits::ScanLimits;

#[derive(Debug, Clone)]
pub struct ScannerContext {
    pub scan_id: String,
    pub file_id: String,
    pub file_path: PathBuf,
    pub original_filename: String,
    pub detected_mime_type: Option<String>,
    pub timeout_ms: u64,
    pub limits: ScanLimits,
    pub work_dir: PathBuf,
    pub path_inside_archive: Option<String>,
}

#[async_trait]
pub trait FileScanner: Send + Sync {
    fn name(&self) -> &'static str;

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput>;
}
