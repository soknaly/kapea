//! PDF static analysis (Phase 4).

use async_trait::async_trait;
use serde_json::json;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

const PDF_PATTERNS: &[(&str, &str, &str, u8)] = &[
    ("/JavaScript", "PDF_JAVASCRIPT", "Embedded JavaScript action", 25),
    ("/JS", "PDF_JAVASCRIPT", "JavaScript (/JS) action", 25),
    ("/OpenAction", "PDF_OPEN_ACTION", "OpenAction on document open", 30),
    ("/Launch", "PDF_LAUNCH_ACTION", "Launch action (external program)", 40),
    ("/EmbeddedFile", "PDF_EMBEDDED_FILE", "Embedded file object", 35),
    ("/AA", "PDF_OPEN_ACTION", "Additional-actions dictionary", 20),
];

pub struct PdfAnalyzer;

fn analyze_pdf_bytes(data: &[u8]) -> Vec<ScanFinding> {
    let text = String::from_utf8_lossy(data);
    let mut findings = Vec::new();
    let mut seen_codes = std::collections::HashSet::new();

    for (pattern, code, message, severity) in PDF_PATTERNS {
        if text.contains(pattern) && seen_codes.insert(*code) {
            findings.push(ScanFinding {
                engine: "PDF_ANALYZER".into(),
                code: (*code).into(),
                category: "document".into(),
                severity: *severity,
                confidence: 80,
                message: (*message).into(),
                technical_details: Some(json!({ "pattern": pattern })),
                path_inside_archive: None,
            });
        }
    }

    if text.contains("/Encrypt") && seen_codes.insert("PDF_ENCRYPTED") {
        findings.push(ScanFinding {
            engine: "PDF_ANALYZER".into(),
            code: "PDF_ENCRYPTED".into(),
            category: "document".into(),
            severity: 15,
            confidence: 85,
            message: "PDF appears encrypted; full static inspection may be limited".into(),
            technical_details: None,
            path_inside_archive: None,
        });
    }

    if text.contains("http://") || text.contains("https://") {
        if seen_codes.insert("PDF_EXTERNAL_URL") {
            findings.push(ScanFinding {
                engine: "PDF_ANALYZER".into(),
                code: "PDF_EXTERNAL_URL".into(),
                category: "document".into(),
                severity: 15,
                confidence: 70,
                message: "PDF contains external URL references".into(),
                technical_details: None,
                path_inside_archive: None,
            });
        }
    }

    findings
}

#[async_trait]
impl FileScanner for PdfAnalyzer {
    fn name(&self) -> &'static str {
        "PDF_ANALYZER"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;
        let mut findings = analyze_pdf_bytes(&data);
        for f in &mut findings {
            f.path_inside_archive = ctx.path_inside_archive.clone();
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("pdf-static-v1".into()),
            complete: true,
            findings,
            metadata: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pdf_javascript() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /JavaScript >>";
        let findings = analyze_pdf_bytes(data);
        assert!(findings.iter().any(|f| f.code == "PDF_JAVASCRIPT"));
        assert_eq!(findings[0].engine, "PDF_ANALYZER");
    }
}
