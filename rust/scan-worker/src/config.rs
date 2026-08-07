use anyhow::{Context, Result};
use ulid::Ulid;

#[derive(Debug, Clone)]
pub struct Config {
    pub worker_id: String,
    pub redis_url: String,
    pub worker_concurrency: usize,
    pub s3_endpoint: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket: String,
    pub clamav_host: String,
    pub clamav_port: u16,
    pub yara_rules_path: String,
    pub work_dir: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            worker_id: std::env::var("WORKER_ID")
                .unwrap_or_else(|_| format!("worker_{}", Ulid::new())),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            worker_concurrency: std::env::var("SCAN_WORKER_CONCURRENCY")
                .unwrap_or_else(|_| "10".into())
                .parse()
                .context("invalid SCAN_WORKER_CONCURRENCY")?,
            s3_endpoint: std::env::var("S3_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:9000".into()),
            s3_region: std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into()),
            s3_secret_key: std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into()),
            s3_bucket: std::env::var("S3_BUCKET").unwrap_or_else(|_| "quarantine".into()),
            clamav_host: std::env::var("CLAMAV_HOST").unwrap_or_else(|_| "localhost".into()),
            clamav_port: std::env::var("CLAMAV_PORT")
                .unwrap_or_else(|_| "3310".into())
                .parse()
                .context("invalid CLAMAV_PORT")?,
            yara_rules_path: std::env::var("YARA_RULES_PATH").unwrap_or_else(|_| "/rules".into()),
            work_dir: std::env::var("WORK_DIR").unwrap_or_else(|_| "/tmp/kapea".into()),
        })
    }
}
