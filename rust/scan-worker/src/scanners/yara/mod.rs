//! YARA rule scanner using a lightweight text-rules engine.
//!
//! Production deployments may swap [`TextYaraEngine`] for libyara / yara-x bindings.
//! This fallback parses `.yar` files, extracts literal `strings:` entries, and performs
//! substring matching — sufficient for EICAR and basic signature coverage in v1.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, warn};

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

/// Well-known EICAR test string (unescaped form).
pub const EICAR_STRING: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Debug, Clone)]
struct YaraStringDef {
    name: String,
    pattern: Vec<u8>,
}

#[derive(Debug, Clone)]
struct YaraRuleDef {
    name: String,
    severity: u8,
    category: String,
    strings: Vec<YaraStringDef>,
}

#[derive(Debug, Clone)]
pub struct TextYaraEngine {
    rules: Vec<YaraRuleDef>,
    rules_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub string_name: String,
    pub severity: u8,
    pub category: String,
}

impl TextYaraEngine {
    pub fn load_from_dir(rules_path: &Path) -> Result<Self> {
        let mut rules = Vec::new();

        if rules_path.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(rules_path)
                .with_context(|| format!("read YARA rules dir {}", rules_path.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext == "yar" || ext == "yara")
                })
                .collect();
            entries.sort();

            for path in entries {
                match parse_yara_file(&path) {
                    Ok(mut parsed) => rules.append(&mut parsed),
                    Err(err) => warn!(path = %path.display(), %err, "skip YARA rule file"),
                }
            }
        } else if rules_path.is_file() {
            rules = parse_yara_file(rules_path)?;
        } else {
            warn!(path = %rules_path.display(), "YARA rules path missing; engine starts empty");
        }

        if rules.is_empty() {
            debug!("no YARA rules loaded; EICAR fallback string match still active");
        }

        Ok(Self {
            rules,
            rules_path: rules_path.to_path_buf(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut matches = Vec::new();

        if data.windows(EICAR_STRING.len()).any(|w| w == EICAR_STRING.as_bytes()) {
            matches.push(YaraMatch {
                rule_name: "EICAR_BUILTIN".into(),
                string_name: "$eicar".into(),
                severity: 100,
                category: "malware".into(),
            });
        }

        for rule in &self.rules {
            for ystr in &rule.strings {
                if data.windows(ystr.pattern.len()).any(|w| w == ystr.pattern) {
                    matches.push(YaraMatch {
                        rule_name: rule.name.clone(),
                        string_name: ystr.name.clone(),
                        severity: rule.severity,
                        category: rule.category.clone(),
                    });
                    break;
                }
            }
        }

        matches
    }

    pub fn version_label(&self) -> String {
        format!("text-yara-v1:{}rules", self.rules.len())
    }

    pub fn empty() -> Self {
        Self {
            rules: vec![],
            rules_path: PathBuf::from("/tmp"),
        }
    }
}

fn parse_yara_file(path: &Path) -> Result<Vec<YaraRuleDef>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read YARA file {}", path.display()))?;
    parse_yara_source(&content)
}

fn parse_yara_source(content: &str) -> Result<Vec<YaraRuleDef>> {
    let mut rules = Vec::new();
    let mut current: Option<YaraRuleDef> = None;
    let mut in_strings = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("rule ") {
            if let Some(rule) = current.take() {
                rules.push(rule);
            }
            let rule_name = name
                .split_whitespace()
                .next()
                .unwrap_or("anonymous")
                .trim_end_matches('{')
                .to_string();
            current = Some(YaraRuleDef {
                name: rule_name,
                severity: 70,
                category: "malware".into(),
                strings: Vec::new(),
            });
            in_strings = false;
            continue;
        }

        let Some(rule) = current.as_mut() else {
            continue;
        };

        if trimmed.starts_with("meta:") {
            in_strings = false;
            continue;
        }
        if trimmed.starts_with("strings:") {
            in_strings = true;
            continue;
        }
        if trimmed.starts_with("condition:") {
            in_strings = false;
            continue;
        }

        if in_strings {
            if let Some(parsed) = parse_string_line(trimmed) {
                rule.strings.push(parsed);
            }
        } else if trimmed.contains("severity") {
            if let Some(sev) = parse_meta_severity(trimmed) {
                rule.severity = sev;
            }
        } else if trimmed.contains("category") {
            if let Some(value) = parse_meta_string(trimmed, "category") {
                rule.category = value;
            }
        }
    }

    if let Some(rule) = current {
        rules.push(rule);
    }

    Ok(rules)
}

fn parse_meta_severity(line: &str) -> Option<u8> {
    let value = parse_meta_string(line, "severity")?;
    match value.to_ascii_lowercase().as_str() {
        "malicious" | "critical" | "high" => Some(100),
        "medium" => Some(50),
        "low" => Some(20),
        digits => digits.parse().ok(),
    }
}

fn parse_meta_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key} =");
    let after = line.split_once(&needle)?.1.trim();
    let value = after.trim_matches('"').trim();
    Some(value.to_string())
}

fn parse_string_line(line: &str) -> Option<YaraStringDef> {
    let line = line.trim().trim_end_matches(';');
    let (name_part, rest) = line.split_once('=')?;
    let name = name_part.trim().trim_start_matches('$').to_string();
    let rest = rest.trim();

    if let Some(literal) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Some(YaraStringDef {
            name,
            pattern: unescape_yara_string(literal),
        });
    }

    None
}

fn unescape_yara_string(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some(other) => {
                    out.push(b'\\');
                    out.push(other as u8);
                }
                None => out.push(b'\\'),
            }
        } else {
            out.extend(ch.to_string().as_bytes());
        }
    }

    out
}

pub struct YaraScanner {
    engine: TextYaraEngine,
}

impl YaraScanner {
    pub fn new(rules_path: &Path) -> Result<Self> {
        Ok(Self {
            engine: TextYaraEngine::load_from_dir(rules_path)?,
        })
    }
}

#[async_trait]
impl FileScanner for YaraScanner {
    fn name(&self) -> &'static str {
        "YARA"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;
        let matches = self.engine.scan_bytes(&data);
        let mut findings = Vec::new();

        for m in matches {
            let code = if m.rule_name.contains("Eicar") || m.rule_name == "EICAR_BUILTIN" {
                "YARA_EICAR"
            } else {
                "YARA_MATCH"
            };

            let parsed = crate::threat_labels::parse_threat_name(&m.rule_name);
            let category = parsed
                .threat_type
                .clone()
                .filter(|_| m.category == "malware" || m.category.is_empty())
                .unwrap_or(m.category);

            findings.push(ScanFinding {
                engine: self.name().into(),
                code: code.into(),
                category,
                severity: m.severity,
                confidence: 95,
                message: format!("YARA rule {} matched string {}", m.rule_name, m.string_name),
                technical_details: Some(json!({
                    "rule": m.rule_name,
                    "string": m.string_name,
                    "threatType": parsed.threat_type,
                    "family": parsed.family,
                    "label": parsed.label,
                })),
                path_inside_archive: None,
            });
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version: Some(self.engine.version_label()),
            complete: true,
            findings,
            metadata: Some(json!({
                "rulesPath": self.engine.rules_path,
                "ruleCount": self.engine.rule_count(),
                "engine": "text-yara-v1",
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eicar_string() {
        let engine = TextYaraEngine {
            rules: vec![],
            rules_path: PathBuf::from("/tmp"),
        };
        let matches = engine.scan_bytes(EICAR_STRING.as_bytes());
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "EICAR_BUILTIN");
    }

    #[test]
    fn parses_eicar_yara_file() {
        let source = include_str!("../../../../../infrastructure/yara/rules/eicar.yar");
        let rules = parse_yara_source(source).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Kapea_Eicar_Test");
        assert_eq!(rules[0].severity, 100);

        let engine = TextYaraEngine {
            rules,
            rules_path: PathBuf::from("/tmp"),
        };
        let matches = engine.scan_bytes(EICAR_STRING.as_bytes());
        assert!(!matches.is_empty());
    }

    #[test]
    fn unescapes_yara_backslashes() {
        let pattern = unescape_yara_string(r"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        assert_eq!(pattern, EICAR_STRING.as_bytes());
    }
}
