//! Derive VirusTotal-style threat labels from ClamAV signatures and YARA rule names.
//!
//! Parses free-form detection strings into threat categories (trojan, adware, …),
//! family labels, and a single popular threat label via simple frequency ranking.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::models::ScanFinding;

const THREAT_TYPES: &[&str] = &[
    "adware",
    "backdoor",
    "banker",
    "botnet",
    "coinminer",
    "cryptominer",
    "downloader",
    "dropper",
    "exploit",
    "hacktool",
    "heuristic",
    "joke",
    "keylogger",
    "macro",
    "malware",
    "miner",
    "packed",
    "phishing",
    "pua",
    "pup",
    "ransomware",
    "rat",
    "riskware",
    "rootkit",
    "spyware",
    "stealer",
    "test",
    "trojan",
    "virus",
    "worm",
];

const PLATFORMS: &[&str] = &[
    "android", "bat", "dos", "elf", "html", "ios", "java", "js", "linux", "macos",
    "multi", "osx", "perl", "php", "powershell", "python", "vbs", "w64", "win",
    "win32", "win64",
];

const GENERIC_FAMILY_TOKENS: &[&str] = &[
    "agent", "generic", "gen", "heur", "malicious", "malware", "suspicious",
    "unknown", "variant",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedThreatName {
    pub threat_type: Option<String>,
    pub family: Option<String>,
    /// Prefer `type.family`, else family, else type.
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatDetection {
    pub engine: String,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ThreatLabels {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub popular_threat_label: Option<String>,
    pub threat_categories: Vec<String>,
    pub family_labels: Vec<String>,
    pub detections: Vec<ThreatDetection>,
}

impl ThreatLabels {
    pub fn is_empty(&self) -> bool {
        self.popular_threat_label.is_none()
            && self.threat_categories.is_empty()
            && self.family_labels.is_empty()
            && self.detections.is_empty()
    }
}

/// Aggregate threat labels from scan findings (ClamAV signatures + YARA rules).
pub fn aggregate(findings: &[ScanFinding]) -> ThreatLabels {
    let mut detections = Vec::new();
    let mut category_counts: HashMap<String, u32> = HashMap::new();
    let mut family_counts: HashMap<String, u32> = HashMap::new();
    let mut label_counts: HashMap<String, u32> = HashMap::new();

    for finding in findings {
        let Some(raw) = detection_raw(finding) else {
            continue;
        };
        let parsed = parse_threat_name(&raw);
        if let Some(ref t) = parsed.threat_type {
            *category_counts.entry(t.clone()).or_insert(0) += 1;
        }
        if let Some(ref f) = parsed.family {
            *family_counts.entry(f.clone()).or_insert(0) += 1;
        }
        if let Some(ref label) = parsed.label {
            *label_counts.entry(label.clone()).or_insert(0) += 1;
        }
        detections.push(ThreatDetection {
            engine: finding.engine.clone(),
            raw,
            threat_type: parsed.threat_type,
            family: parsed.family,
            label: parsed.label,
        });
    }

    ThreatLabels {
        popular_threat_label: top_ranked(&label_counts),
        threat_categories: ranked_keys(&category_counts),
        family_labels: ranked_keys(&family_counts),
        detections,
    }
}

fn detection_raw(finding: &ScanFinding) -> Option<String> {
    match finding.engine.as_str() {
        "CLAMAV" if finding.code == "CLAMAV_DETECTION" => finding
            .technical_details
            .as_ref()
            .and_then(|v| v.get("signature"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && *s != "unknown")
            .map(str::to_string)
            .or_else(|| {
                finding
                    .message
                    .strip_prefix("ClamAV detected malware: ")
                    .map(str::to_string)
            }),
        "YARA" => finding
            .technical_details
            .as_ref()
            .and_then(|v| v.get("rule"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

/// Parse a free-form AV / YARA detection name into type + family.
pub fn parse_threat_name(raw: &str) -> ParsedThreatName {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParsedThreatName {
            threat_type: None,
            family: None,
            label: None,
        };
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("eicar") {
        return ParsedThreatName {
            threat_type: Some("test".into()),
            family: Some("eicar".into()),
            label: Some("test.eicar".into()),
        };
    }

    let tokens = tokenize(&lower);
    let threat_type = pick_threat_type(&tokens);
    let family = pick_family(&tokens, threat_type.as_deref());
    let label = compose_label(threat_type.as_deref(), family.as_deref());

    ParsedThreatName {
        threat_type,
        family,
        label,
    }
}

fn pick_threat_type(tokens: &[String]) -> Option<String> {
    const LOW_PRIORITY: &[&str] = &["pua", "pup", "malware", "heuristic", "riskware"];
    let matches: Vec<&String> = tokens
        .iter()
        .filter(|t| THREAT_TYPES.contains(&t.as_str()))
        .collect();
    matches
        .iter()
        .find(|t| !LOW_PRIORITY.contains(&t.as_str()))
        .or(matches.first())
        .map(|t| (*t).clone())
}

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
        .into_iter()
        .map(|t| strip_trailing_digits(&t))
        .filter(|t| t.len() >= 2)
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .collect()
}

fn strip_trailing_digits(token: &str) -> String {
    let trimmed = token.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.len() >= 2 {
        trimmed.to_string()
    } else {
        token.to_string()
    }
}

fn pick_family(tokens: &[String], threat_type: Option<&str>) -> Option<String> {
    let candidates: Vec<&String> = tokens
        .iter()
        .filter(|t| Some(t.as_str()) != threat_type)
        .filter(|t| !PLATFORMS.contains(&t.as_str()))
        .filter(|t| !THREAT_TYPES.contains(&t.as_str()))
        .filter(|t| !GENERIC_FAMILY_TOKENS.contains(&t.as_str()))
        .filter(|t| t.len() >= 3)
        .collect();

    if let Some(best) = candidates.iter().max_by_key(|t| t.len()) {
        return Some((*best).clone());
    }

    // Fall back to a generic family token if nothing else remains.
    tokens
        .iter()
        .filter(|t| Some(t.as_str()) != threat_type)
        .filter(|t| !PLATFORMS.contains(&t.as_str()))
        .filter(|t| !THREAT_TYPES.contains(&t.as_str()))
        .filter(|t| t.len() >= 3)
        .max_by_key(|t| t.len())
        .cloned()
}

fn compose_label(threat_type: Option<&str>, family: Option<&str>) -> Option<String> {
    match (threat_type, family) {
        (Some(t), Some(f)) => Some(format!("{t}.{f}")),
        (None, Some(f)) => Some(f.to_string()),
        (Some(t), None) => Some(t.to_string()),
        (None, None) => None,
    }
}

fn top_ranked(counts: &HashMap<String, u32>) -> Option<String> {
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(k, _)| k.clone())
}

fn ranked_keys(counts: &HashMap<String, u32>) -> Vec<String> {
    let mut items: Vec<_> = counts.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    items.into_iter().map(|(k, _)| k.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn clamav_finding(signature: &str) -> ScanFinding {
        ScanFinding {
            engine: "CLAMAV".into(),
            code: "CLAMAV_DETECTION".into(),
            category: "malware".into(),
            severity: 100,
            confidence: 100,
            message: format!("ClamAV detected malware: {signature}"),
            technical_details: Some(json!({ "signature": signature })),
            path_inside_archive: None,
        }
    }

    fn yara_finding(rule: &str, category: &str) -> ScanFinding {
        ScanFinding {
            engine: "YARA".into(),
            code: "YARA_MATCH".into(),
            category: category.into(),
            severity: 80,
            confidence: 95,
            message: format!("YARA rule {rule} matched"),
            technical_details: Some(json!({ "rule": rule, "string": "$a" })),
            path_inside_archive: None,
        }
    }

    #[test]
    fn parses_clamav_dotted_name() {
        let parsed = parse_threat_name("Win.Trojan.SparkRat-1");
        assert_eq!(parsed.threat_type.as_deref(), Some("trojan"));
        assert_eq!(parsed.family.as_deref(), Some("sparkrat"));
        assert_eq!(parsed.label.as_deref(), Some("trojan.sparkrat"));
    }

    #[test]
    fn parses_reversed_clamav_style() {
        let parsed = parse_threat_name("Trojan.Win32.GenericKD.5748901");
        assert_eq!(parsed.threat_type.as_deref(), Some("trojan"));
        assert_eq!(parsed.family.as_deref(), Some("generickd"));
        assert_eq!(parsed.label.as_deref(), Some("trojan.generickd"));
    }

    #[test]
    fn parses_adware() {
        let parsed = parse_threat_name("PUA.Win.Adware.BrowseFox");
        assert_eq!(parsed.threat_type.as_deref(), Some("adware"));
        assert_eq!(parsed.family.as_deref(), Some("browsefox"));
    }

    #[test]
    fn parses_eicar() {
        let parsed = parse_threat_name("Eicar-Test-Signature");
        assert_eq!(parsed.threat_type.as_deref(), Some("test"));
        assert_eq!(parsed.family.as_deref(), Some("eicar"));
        assert_eq!(parsed.label.as_deref(), Some("test.eicar"));
    }

    #[test]
    fn aggregates_popular_label() {
        let findings = vec![
            clamav_finding("Win.Trojan.SparkRat"),
            yara_finding("SparkRat_Config", "malware"),
            clamav_finding("Win.Adware.BrowseFox"),
        ];
        let labels = aggregate(&findings);
        assert_eq!(labels.popular_threat_label.as_deref(), Some("trojan.sparkrat"));
        assert!(labels.threat_categories.contains(&"trojan".to_string()));
        assert!(labels.threat_categories.contains(&"adware".to_string()));
        assert!(labels.family_labels.contains(&"sparkrat".to_string()));
        assert_eq!(labels.detections.len(), 3);
    }

    #[test]
    fn yara_eicar_rule() {
        let labels = aggregate(&[yara_finding("EICAR_BUILTIN", "malware")]);
        assert_eq!(labels.popular_threat_label.as_deref(), Some("test.eicar"));
        assert_eq!(labels.threat_categories, vec!["test".to_string()]);
    }
}
