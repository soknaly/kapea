//! ClamAV scanner via clamd TCP INSTREAM protocol.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;

use super::trait_def::{FileScanner, ScannerContext, ScannerOutput};
use crate::models::ScanFinding;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SCAN_TIMEOUT: Duration = Duration::from_secs(120);
const CHUNK_SIZE: usize = 32 * 1024;

pub struct ClamAvScanner {
    host: String,
    port: u16,
}

impl ClamAvScanner {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    async fn connect(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.host, self.port);
        timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .context("ClamAV connect timed out")?
            .with_context(|| format!("connect to ClamAV at {addr}"))
    }

    async fn command(&self, cmd: &str) -> Result<String> {
        let mut stream = self.connect().await?;
        let framed = format!("z{cmd}\0");
        stream.write_all(framed.as_bytes()).await?;
        stream.shutdown().await?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(trim_clamav_response(&response))
    }

    pub async fn ping(&self) -> Result<bool> {
        match self.command("PING").await {
            Ok(resp) => Ok(resp.eq_ignore_ascii_case("PONG")),
            Err(err) => {
                tracing::debug!(%err, "ClamAV ping failed");
                Ok(false)
            }
        }
    }

    pub async fn version(&self) -> Option<String> {
        self.command("VERSION").await.ok()
    }

    async fn instream_scan(&self, data: &[u8]) -> Result<ClamAvScanResult> {
        let mut stream = self.connect().await?;
        stream.write_all(b"zINSTREAM\0").await?;

        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + CHUNK_SIZE).min(data.len());
            let chunk = &data[offset..end];
            let len = (chunk.len() as u32).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(chunk).await?;
            offset = end;
        }

        stream.write_all(&0u32.to_be_bytes()).await?;
        stream.shutdown().await?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(parse_clamav_response(&trim_clamav_response(&response)))
    }
}

/// clamd z-protocol replies are null-terminated (`PONG\0`, `stream: OK\0`).
fn trim_clamav_response(response: &str) -> String {
    response
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string()
}

#[derive(Debug, Clone)]
struct ClamAvScanResult {
    infected: bool,
    signature: Option<String>,
    raw_response: String,
}

fn parse_clamav_response(response: &str) -> ClamAvScanResult {
    let trimmed = response.trim();
    if trimmed.ends_with("OK") {
        return ClamAvScanResult {
            infected: false,
            signature: None,
            raw_response: trimmed.to_string(),
        };
    }

    if let Some(found) = trimmed.split(':').nth(1) {
        let sig = found
            .trim()
            .strip_suffix(" FOUND")
            .or_else(|| found.strip_suffix(" FOUND\r"))
            .unwrap_or(found)
            .trim()
            .to_string();
        return ClamAvScanResult {
            infected: true,
            signature: Some(sig),
            raw_response: trimmed.to_string(),
        };
    }

    ClamAvScanResult {
        infected: false,
        signature: None,
        raw_response: trimmed.to_string(),
    }
}

#[async_trait]
impl FileScanner for ClamAvScanner {
    fn name(&self) -> &'static str {
        "CLAMAV"
    }

    async fn scan(&self, ctx: &ScannerContext) -> anyhow::Result<ScannerOutput> {
        let data = tokio::fs::read(&ctx.file_path).await?;
        let scan_timeout = Duration::from_millis(ctx.timeout_ms.max(1));

        let result = match timeout(scan_timeout.min(SCAN_TIMEOUT), self.instream_scan(&data)).await
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                warn!(%err, "ClamAV scan error");
                return Ok(ScannerOutput {
                    engine: self.name().into(),
                    version: self.version().await,
                    complete: false,
                    findings: vec![],
                    metadata: Some(json!({ "error": err.to_string() })),
                });
            }
            Err(_) => {
                return Ok(ScannerOutput {
                    engine: self.name().into(),
                    version: self.version().await,
                    complete: false,
                    findings: vec![],
                    metadata: Some(json!({ "error": "ClamAV scan timed out" })),
                });
            }
        };

        let version = self.version().await;
        let mut findings = Vec::new();

        if result.infected {
            let signature = result.signature.as_deref().unwrap_or("unknown signature");
            let parsed = crate::threat_labels::parse_threat_name(signature);
            let category = parsed
                .threat_type
                .clone()
                .unwrap_or_else(|| "malware".into());
            findings.push(ScanFinding {
                engine: self.name().into(),
                code: "CLAMAV_DETECTION".into(),
                category,
                severity: 100,
                confidence: 100,
                message: format!("ClamAV detected malware: {signature}"),
                technical_details: Some(json!({
                    "signature": result.signature,
                    "response": result.raw_response,
                    "threatType": parsed.threat_type,
                    "family": parsed.family,
                    "label": parsed.label,
                })),
                path_inside_archive: None,
            });
        }

        Ok(ScannerOutput {
            engine: self.name().into(),
            version,
            complete: true,
            findings,
            metadata: Some(json!({ "response": result.raw_response })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_response() {
        let result = parse_clamav_response("stream: OK");
        assert!(!result.infected);
    }

    #[test]
    fn parses_infected_response() {
        let result = parse_clamav_response("stream: Eicar-Test-Signature FOUND");
        assert!(result.infected);
        assert_eq!(result.signature.as_deref(), Some("Eicar-Test-Signature"));
    }

    #[test]
    fn trims_z_protocol_null_terminator() {
        assert_eq!(trim_clamav_response("PONG\0"), "PONG");
        assert_eq!(trim_clamav_response("stream: OK\0"), "stream: OK");
        let result = parse_clamav_response(&trim_clamav_response("stream: OK\0"));
        assert!(!result.infected);
    }
}
