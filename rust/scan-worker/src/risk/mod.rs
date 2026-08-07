//! Deterministic risk scoring and automated verdict selection.
//!
//! # Scoring model
//!
//! Each finding contributes up to its `severity` value (0–100). Contributions are summed and
//! capped at 100 to produce the final `risk_score`.
//!
//! Special overrides (evaluated after summation):
//! - **ClamAV detection** (`CLAMAV_DETECTION`) → score 100, verdict `MALICIOUS`
//! - **High-severity YARA** (severity ≥ 80 or meta severity `malicious`) → score ≥ 80, verdict `MALICIOUS`
//! - **EICAR test string** (`YARA_EICAR`) → score 100, verdict `MALICIOUS`
//!
//! # Verdict thresholds (when scan is complete)
//!
//! | Risk score | Verdict     |
//! |-----------:|-------------|
//! | 0          | CLEAN       |
//! | 1–19       | CLEAN       |
//! | 20–49      | SUSPICIOUS  |
//! | 50–100     | MALICIOUS   |
//!
//! # Completeness rules
//!
//! Required scanners for v1: `CLAMAV`, `YARA`, `FILE_TYPE`.
//! If any required scanner reports `complete: false`, verdict is **never** `CLEAN` — it becomes
//! `UNKNOWN` (or `SCAN_FAILED` when a fatal pipeline error occurred).

use crate::models::{ScanFinding, ScannerOutput, Verdict};

const REQUIRED_SCANNERS: &[&str] = &["CLAMAV", "YARA", "FILE_TYPE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub risk_score: u8,
    pub verdict: Verdict,
    pub scan_complete: bool,
    pub summary: String,
}

pub fn assess(
    findings: &[ScanFinding],
    scanner_outputs: &[ScannerOutput],
    fatal_error: bool,
) -> RiskAssessment {
    if fatal_error {
        return RiskAssessment {
            risk_score: 0,
            verdict: Verdict::ScanFailed,
            scan_complete: false,
            summary: "Scan failed due to a fatal pipeline error".into(),
        };
    }

    let scan_complete = required_scanners_complete(scanner_outputs);
    let risk_score = compute_risk_score(findings);
    let mut verdict = verdict_from_score(risk_score, findings);

    if !scan_complete {
        if verdict == Verdict::Clean {
            verdict = Verdict::Unknown;
        } else if verdict == Verdict::Suspicious {
            // Keep suspicious/malicious when findings exist despite incomplete scanners.
        }
    }

    if !scan_complete && verdict == Verdict::Clean {
        verdict = Verdict::Unknown;
    }

    let summary = build_summary(verdict, risk_score, findings.len(), scan_complete);

    RiskAssessment {
        risk_score,
        verdict,
        scan_complete,
        summary,
    }
}

fn required_scanners_complete(outputs: &[ScannerOutput]) -> bool {
    REQUIRED_SCANNERS.iter().all(|required| {
        outputs
            .iter()
            .any(|o| o.engine == *required && o.complete)
    })
}

pub fn compute_risk_score(findings: &[ScanFinding]) -> u8 {
    if findings.iter().any(|f| f.code == "CLAMAV_DETECTION" || f.code == "YARA_EICAR") {
        return 100;
    }

    let sum: u32 = findings.iter().map(|f| u32::from(f.severity)).sum();
    sum.min(100) as u8
}

fn verdict_from_score(score: u8, findings: &[ScanFinding]) -> Verdict {
    if findings
        .iter()
        .any(|f| f.code == "CLAMAV_DETECTION" || f.code == "YARA_EICAR")
    {
        return Verdict::Malicious;
    }

    if findings.iter().any(|f| {
        f.engine == "YARA" && f.severity >= 80 && f.category == "malware"
    }) {
        return Verdict::Malicious;
    }

    match score {
        0..=19 => Verdict::Clean,
        20..=49 => Verdict::Suspicious,
        _ => Verdict::Malicious,
    }
}

fn build_summary(
    verdict: Verdict,
    risk_score: u8,
    finding_count: usize,
    scan_complete: bool,
) -> String {
    if !scan_complete {
        return format!(
            "Scan incomplete (risk score {risk_score}, {finding_count} finding(s)); verdict {}",
            verdict.as_str()
        );
    }

    match verdict {
        Verdict::Clean => "No threats detected".into(),
        Verdict::Suspicious => format!(
            "Suspicious indicators detected (risk score {risk_score}, {finding_count} finding(s))"
        ),
        Verdict::Malicious => format!(
            "Malicious content detected (risk score {risk_score}, {finding_count} finding(s))"
        ),
        Verdict::Unknown => format!(
            "Scan incomplete or indeterminate (risk score {risk_score})"
        ),
        Verdict::ScanFailed => "Scan failed".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanFinding;

    fn finding(code: &str, engine: &str, severity: u8, category: &str) -> ScanFinding {
        ScanFinding {
            engine: engine.into(),
            code: code.into(),
            category: category.into(),
            severity,
            confidence: 90,
            message: code.into(),
            technical_details: None,
            path_inside_archive: None,
        }
    }

    fn complete_output(engine: &str) -> ScannerOutput {
        ScannerOutput {
            engine: engine.into(),
            version: Some("test".into()),
            complete: true,
            findings: vec![],
            metadata: None,
        }
    }

    fn incomplete_output(engine: &str) -> ScannerOutput {
        ScannerOutput {
            engine: engine.into(),
            version: None,
            complete: false,
            findings: vec![],
            metadata: None,
        }
    }

    #[test]
    fn extension_mismatch_is_suspicious() {
        let findings = vec![finding(
            "EXTENSION_MISMATCH",
            "FILE_TYPE",
            25,
            "integrity",
        )];
        let outputs = vec![
            complete_output("CLAMAV"),
            complete_output("YARA"),
            complete_output("FILE_TYPE"),
        ];
        let result = assess(&findings, &outputs, false);
        assert_eq!(result.risk_score, 25);
        assert_eq!(result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn clamav_detection_is_malicious() {
        let findings = vec![finding("CLAMAV_DETECTION", "CLAMAV", 100, "malware")];
        let outputs = vec![
            complete_output("CLAMAV"),
            complete_output("YARA"),
            complete_output("FILE_TYPE"),
        ];
        let result = assess(&findings, &outputs, false);
        assert_eq!(result.risk_score, 100);
        assert_eq!(result.verdict, Verdict::Malicious);
    }

    #[test]
    fn incomplete_scan_never_clean() {
        let outputs = vec![
            incomplete_output("CLAMAV"),
            complete_output("YARA"),
            complete_output("FILE_TYPE"),
        ];
        let result = assess(&[], &outputs, false);
        assert_ne!(result.verdict, Verdict::Clean);
        assert_eq!(result.verdict, Verdict::Unknown);
        assert!(!result.scan_complete);
    }

    #[test]
    fn clean_when_no_findings_and_complete() {
        let outputs = vec![
            complete_output("CLAMAV"),
            complete_output("YARA"),
            complete_output("FILE_TYPE"),
        ];
        let result = assess(&[], &outputs, false);
        assert_eq!(result.verdict, Verdict::Clean);
        assert_eq!(result.risk_score, 0);
        assert!(result.scan_complete);
    }

    #[test]
    fn eicar_finding_is_malicious() {
        let findings = vec![finding("YARA_EICAR", "YARA", 100, "malware")];
        let outputs = vec![
            complete_output("CLAMAV"),
            complete_output("YARA"),
            complete_output("FILE_TYPE"),
        ];
        let result = assess(&findings, &outputs, false);
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.risk_score, 100);
    }
}
