//! Windows PE analysis (Phase 4).

use async_trait::async_trait;
use goblin::pe::PE;
use serde_json::json;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

const SUSPICIOUS_IMPORTS: &[(&str, &str)] = &[
    ("VirtualAlloc", "Dynamic memory allocation"),
    ("VirtualAllocEx", "Remote process memory allocation"),
    ("WriteProcessMemory", "Cross-process memory write"),
    ("CreateRemoteThread", "Remote thread creation"),
    ("CreateRemoteThreadEx", "Remote thread creation"),
    ("NtCreateThreadEx", "Native remote thread creation"),
    ("LoadLibraryA", "Dynamic library loading"),
    ("LoadLibraryW", "Dynamic library loading"),
    ("GetProcAddress", "Dynamic API resolution"),
    ("WinExec", "Direct process execution"),
    ("ShellExecuteA", "Shell execution"),
    ("ShellExecuteW", "Shell execution"),
    ("URLDownloadToFileA", "File download"),
    ("URLDownloadToFileW", "File download"),
    ("RegSetValueExA", "Registry modification"),
    ("RegSetValueExW", "Registry modification"),
];

const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

pub struct PeAnalyzer;

fn section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn pe_machine_label(machine: u16) -> &'static str {
    match machine {
        0x014c => "i386",
        0x8664 => "x86_64",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        _ => "unknown",
    }
}

pub fn analyze_pe_bytes(data: &[u8]) -> Option<(Vec<ScanFinding>, serde_json::Value)> {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return None;
    }

    let pe = PE::parse(data).ok()?;
    let arch = pe_machine_label(pe.header.coff_header.machine);
    let mut findings = Vec::new();
    let mut suspicious_imports = Vec::new();

    for import in &pe.imports {
        let name = import.name.as_ref();
        for (pattern, desc) in SUSPICIOUS_IMPORTS {
            if name.eq_ignore_ascii_case(pattern) {
                suspicious_imports.push(json!({
                    "import": name,
                    "description": desc,
                    "dll": &import.dll,
                }));
                findings.push(ScanFinding {
                    engine: "PE_ANALYZER".into(),
                    code: "PE_SUSPICIOUS_IMPORT".into(),
                    category: "executable".into(),
                    severity: 30,
                    confidence: 70,
                    message: format!("Suspicious import: {name} ({desc})"),
                    technical_details: Some(json!({ "import": name, "dll": &import.dll })),
                    path_inside_archive: None,
                });
            }
        }
    }

    let mut high_entropy_sections = Vec::new();
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start + size <= data.len() && size > 0 {
            let entropy = section_entropy(&data[start..start + size]);
            if entropy >= HIGH_ENTROPY_THRESHOLD {
                let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
                high_entropy_sections.push(json!({
                    "section": name,
                    "entropy": (entropy * 100.0).round() / 100.0,
                }));
                findings.push(ScanFinding {
                    engine: "PE_ANALYZER".into(),
                    code: "PE_HIGH_ENTROPY_SECTION".into(),
                    category: "executable".into(),
                    severity: 25,
                    confidence: 60,
                    message: format!(
                        "Section {name} has high entropy ({entropy:.2}), possible packing"
                    ),
                    technical_details: Some(json!({
                        "section": name,
                        "entropy": entropy,
                    })),
                    path_inside_archive: None,
                });
            }
        }
    }

    let metadata = json!({
        "architecture": arch,
        "machine": pe.header.coff_header.machine,
        "sections": pe.sections.len(),
        "suspiciousImports": suspicious_imports,
        "highEntropySections": high_entropy_sections,
    });

    Some((findings, metadata))
}

#[async_trait]
impl FileScanner for PeAnalyzer {
    fn name(&self) -> &'static str {
        "PE_ANALYZER"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;

        let Some((mut findings, metadata)) = analyze_pe_bytes(&data) else {
            return Ok(ScannerOutput {
                engine: self.name().into(),
                version: Some("goblin-pe-v1".into()),
                complete: true,
                findings: vec![],
                metadata: Some(json!({ "skipped": true })),
            });
        };

        for f in &mut findings {
            f.path_inside_archive = ctx.path_inside_archive.clone();
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("goblin-pe-v1".into()),
            complete: true,
            findings,
            metadata: Some(metadata),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_mz_header_gracefully() {
        // Minimal MZ stub — goblin may fail parse; analyzer must not panic.
        let stub = [b'M', b'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(analyze_pe_bytes(&stub).is_none());
    }

    #[test]
    fn section_entropy_zero_for_empty() {
        assert_eq!(section_entropy(&[]), 0.0);
    }

    #[test]
    fn section_entropy_high_for_random_like_data() {
        let data: Vec<u8> = (0..=255).collect();
        assert!(section_entropy(&data) >= HIGH_ENTROPY_THRESHOLD);
    }
}
