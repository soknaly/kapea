//! Office document analysis (Phase 4).

use std::io::Cursor;
use std::path::Path;

use async_trait::async_trait;
use serde_json::json;
use zip::ZipArchive;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

const OLE_MAGIC: [u8; 4] = [0xD0, 0xCF, 0x11, 0xE0];

pub struct OfficeAnalyzer;

fn is_ooxml_zip(data: &[u8]) -> bool {
    if data.len() < 4 || data[0..2] != [0x50, 0x4B] {
        return false;
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    let has_content_types = archive.by_name("[Content_Types].xml").is_ok();
    has_content_types
}

fn is_ole_compound(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == OLE_MAGIC
}

fn analyze_ooxml(data: &[u8]) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) else {
        return findings;
    };

    for i in 0..archive.len() {
        let Ok(file) = archive.by_index(i) else {
            continue;
        };
        let name = file.name().to_ascii_lowercase();

        if name.contains("vbaproject.bin") {
            findings.push(finding(
                "OFFICE_MACRO",
                "VBA macro project detected (vbaProject.bin)",
                40,
                json!({ "member": file.name() }),
            ));
        }
        if name.contains("macrosheet") || name.contains("macrosheets") {
            findings.push(finding(
                "OFFICE_MACRO",
                "Excel macro sheet detected",
                35,
                json!({ "member": file.name() }),
            ));
        }
        if name.contains("activemime") {
            findings.push(finding(
                "OFFICE_MACRO",
                "ActiveMime content detected",
                45,
                json!({ "member": file.name() }),
            ));
        }
        if name.ends_with(".exe") || name.ends_with(".dll") || name.ends_with(".bin") {
            if name.contains("embed") || name.contains("oleobject") {
                findings.push(finding(
                    "OFFICE_EMBEDDED_EXECUTABLE",
                    "Embedded executable-like object in Office document",
                    50,
                    json!({ "member": file.name() }),
                ));
            }
        }
        if name.contains("external") && name.ends_with(".xml") {
            findings.push(finding(
                "OFFICE_EXTERNAL_TEMPLATE",
                "External relationship or template reference",
                25,
                json!({ "member": file.name() }),
            ));
        }
    }

    findings
}

fn analyze_ole(data: &[u8]) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let content = String::from_utf8_lossy(data);

    if content.contains("vbaProject") || content.contains("Macros") {
        findings.push(finding(
            "OFFICE_MACRO",
            "Legacy OLE document contains macro indicators",
            40,
            json!({ "format": "ole" }),
        ));
    }
    if content.contains("DDE") || content.contains("ddeauto") {
        findings.push(finding(
            "OFFICE_DDE",
            "DDE link indicators in OLE document",
            45,
            json!({ "format": "ole" }),
        ));
    }

    findings
}

fn finding(code: &str, message: &str, severity: u8, details: serde_json::Value) -> ScanFinding {
    ScanFinding {
        engine: "OFFICE_ANALYZER".into(),
        code: code.into(),
        category: "document".into(),
        severity,
        confidence: 75,
        message: message.into(),
        technical_details: Some(details),
        path_inside_archive: None,
    }
}

fn should_analyze(ctx: &ScannerContext, data: &[u8]) -> bool {
    if let Some(mime) = ctx.detected_mime_type.as_deref() {
        if mime.contains("officedocument")
            || mime.contains("msword")
            || mime.contains("ms-excel")
            || mime.contains("ms-powerpoint")
            || mime == "application/msword"
        {
            return true;
        }
    }

    let ext = Path::new(&ctx.original_filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    matches!(
        ext.as_deref(),
        Some("doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf")
    ) || is_ooxml_zip(data)
        || is_ole_compound(data)
}

#[async_trait]
impl FileScanner for OfficeAnalyzer {
    fn name(&self) -> &'static str {
        "OFFICE_ANALYZER"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;

        if !should_analyze(ctx, &data) {
            return Ok(ScannerOutput {
                engine: self.name().into(),
                version: Some("office-static-v1".into()),
                complete: true,
                findings: vec![],
                metadata: Some(json!({ "skipped": true })),
            });
        }

        let mut findings = if is_ooxml_zip(&data) {
            analyze_ooxml(&data)
        } else if is_ole_compound(&data) {
            analyze_ole(&data)
        } else {
            vec![]
        };

        for f in &mut findings {
            f.path_inside_archive = ctx.path_inside_archive.clone();
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("office-static-v1".into()),
            complete: true,
            findings,
            metadata: None,
        })
    }
}
