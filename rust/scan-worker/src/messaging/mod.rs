//! Scan event parsing and ID helpers.

use anyhow::{Context, Result};
use ulid::Ulid;

use crate::models::ScanRequestedEvent;

pub fn parse_scan_requested(payload: &serde_json::Value) -> Result<ScanRequestedEvent> {
    let event: ScanRequestedEvent =
        serde_json::from_value(payload.clone()).context("deserialize scan.requested event")?;
    event
        .validate()
        .map_err(|msg| anyhow::anyhow!("invalid scan.requested event: {msg}"))?;
    Ok(event)
}

pub fn new_event_id(prefix: &str) -> String {
    format!("{prefix}_{}", Ulid::new())
}
