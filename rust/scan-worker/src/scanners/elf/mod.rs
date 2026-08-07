//! Linux ELF analysis (Phase 4).

use async_trait::async_trait;
use goblin::elf::Elf;
use goblin::elf::header::{EM_AARCH64, EM_ARM, EM_X86_64, ET_DYN, ET_EXEC};
use serde_json::json;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

pub struct ElfAnalyzer;

fn elf_machine_label(machine: u16) -> &'static str {
    match machine {
        EM_X86_64 => "x86_64",
        EM_AARCH64 => "aarch64",
        EM_ARM => "arm",
        0x03 => "i386",
        _ => "unknown",
    }
}

fn elf_type_label(ty: u16) -> &'static str {
    match ty {
        ET_EXEC => "executable",
        ET_DYN => "shared_object",
        _ => "other",
    }
}

pub fn analyze_elf_bytes(data: &[u8]) -> Option<(Vec<ScanFinding>, serde_json::Value)> {
    if data.len() < 4 || &data[0..4] != b"\x7fELF" {
        return None;
    }

    let elf = Elf::parse(data).ok()?;
    let arch = elf_machine_label(elf.header.e_machine);
    let ty = elf_type_label(elf.header.e_type);
    let mut findings = Vec::new();

    let interpreter = elf.interpreter.map(str::to_string);

    if let Some(interp) = &interpreter {
        if interp.contains("busybox") || interp.contains("/tmp/") {
            findings.push(ScanFinding {
                engine: "ELF_ANALYZER".into(),
                code: "ELF_SUSPICIOUS_INTERPRETER".into(),
                category: "executable".into(),
                severity: 25,
                confidence: 65,
                message: format!("Unusual ELF interpreter: {interp}"),
                technical_details: Some(json!({ "interpreter": interp })),
                path_inside_archive: None,
            });
        }
    }

    for section in &elf.section_headers {
        if section.sh_type != goblin::elf::section_header::SHT_NOTE {
            continue;
        }
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if name.to_ascii_lowercase().contains("upx")
            || name.to_ascii_lowercase().contains("packed")
        {
            findings.push(ScanFinding {
                engine: "ELF_ANALYZER".into(),
                code: "ELF_SUSPICIOUS_NOTE".into(),
                category: "executable".into(),
                severity: 30,
                confidence: 60,
                message: format!("Suspicious ELF note section: {name}"),
                technical_details: Some(json!({ "note": name })),
                path_inside_archive: None,
            });
        }
    }

    let metadata = json!({
        "architecture": arch,
        "type": ty,
        "machine": elf.header.e_machine,
        "interpreter": interpreter,
        "entry": elf.entry,
        "sections": elf.section_headers.len(),
    });

    Some((findings, metadata))
}

#[async_trait]
impl FileScanner for ElfAnalyzer {
    fn name(&self) -> &'static str {
        "ELF_ANALYZER"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;

        let Some((mut findings, metadata)) = analyze_elf_bytes(&data) else {
            return Ok(ScannerOutput {
                engine: self.name().into(),
                version: Some("goblin-elf-v1".into()),
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
            version: Some("goblin-elf-v1".into()),
            complete: true,
            findings,
            metadata: Some(metadata),
        })
    }
}
