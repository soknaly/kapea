//! Resource limits for archive expansion and scan timeouts.

#[derive(Debug, Clone)]
pub struct ScanLimits {
    pub max_extracted_bytes: u64,
    pub max_files: u32,
    pub max_depth: u32,
    pub timeout_seconds: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_extracted_bytes: 524_288_000,
            max_files: 1000,
            max_depth: 5,
            timeout_seconds: 60,
        }
    }
}
