//! Magic-byte file-type detection.

use async_trait::async_trait;
use serde_json::json;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};

pub struct FileTypeScanner;

#[async_trait]
impl FileScanner for FileTypeScanner {
    fn name(&self) -> &'static str {
        "FILE_TYPE"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let kind = infer::get_from_path(&ctx.file_path)?;
        let mime = kind.map(|k| k.mime_type().to_string());

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("infer".into()),
            complete: true,
            findings: vec![],
            metadata: Some(json!({ "detectedMimeType": mime })),
        })
    }
}
