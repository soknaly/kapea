//! Progress reporting for BullMQ jobs and local CLI scans.

use anyhow::{Context, Result};
use bullmq::{Job, JobProgress};
use tracing::info;

use crate::models::ScanProgressEvent;

pub enum ProgressSink<'a> {
    /// Publish progress onto a BullMQ job.
    BullMq(&'a mut Job),
    /// Log progress to tracing (local `--file` mode).
    Local,
}

impl ProgressSink<'_> {
    pub async fn report(&mut self, event: &ScanProgressEvent) -> Result<()> {
        match self {
            ProgressSink::BullMq(job) => {
                job.update_progress(JobProgress::Object(
                    serde_json::to_value(event).context("serialize scan progress")?,
                ))
                .await
                .context("update BullMQ job progress")?;
            }
            ProgressSink::Local => {
                info!(
                    scan_id = %event.scan_id,
                    progress = event.progress,
                    stage = ?event.current_stage,
                    message = event.message.as_deref().unwrap_or(""),
                    "scan progress"
                );
            }
        }
        Ok(())
    }
}
