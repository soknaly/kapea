mod config;
mod errors;
mod hashing;
mod limits;
mod messaging;
mod models;
mod pipeline;
mod progress;
mod risk;
mod scanners;
mod storage;
mod telemetry;
mod threat_labels;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bullmq::options::RedisConnectionOptions;
use bullmq::worker::{CancellationToken, ProcessorFn};
use bullmq::{Worker, WorkerOptions};
use clap::Parser;
use pipeline::ScanPipeline;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

const SCAN_QUEUE_NAME: &str = "scan-jobs";
const SCAN_JOB_NAME: &str = "scan.requested";

#[derive(Debug, Parser)]
#[command(
    name = "scan-worker",
    about = "KAPEA scan worker — BullMQ consumer or local single-file scanner"
)]
struct Cli {
    /// Local file to scan (positional). If omitted, runs the BullMQ worker.
    #[arg(value_name = "FILE")]
    path: Option<PathBuf>,

    /// Local file to scan (alternative to positional FILE)
    #[arg(long = "file", short = 'f', value_name = "PATH")]
    file: Option<PathBuf>,

    /// Pretty-print JSON output (local file mode)
    #[arg(long)]
    pretty: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let local_path = cli.file.or(cli.path);

    if let Some(path) = local_path {
        return run_local_file(path, cli.pretty).await;
    }

    run_queue_worker().await
}

async fn run_local_file(path: PathBuf, pretty: bool) -> anyhow::Result<()> {
    // Human-readable logs on stderr; scan result JSON on stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let mut config = config::Config::from_env()?;
    // Prefer repo rules when unset / default container path.
    if config.yara_rules_path == "/rules"
        || std::env::var_os("YARA_RULES_PATH").is_none()
    {
        let local_rules = PathBuf::from("infrastructure/yara/rules");
        if local_rules.is_dir() {
            config.yara_rules_path = local_rules.display().to_string();
        }
    }
    if std::env::var_os("WORK_DIR").is_none() {
        config.work_dir = std::env::temp_dir()
            .join("kapea-local-scan")
            .display()
            .to_string();
    }

    info!(
        file = %path.display(),
        yara_rules = %config.yara_rules_path,
        "starting local file scan"
    );

    let pipeline = ScanPipeline::new_local(config).await?;
    let completed = pipeline.scan_local_file(&path).await?;

    if pretty {
        println!("{}", serde_json::to_string_pretty(&completed)?);
    } else {
        println!("{}", serde_json::to_string(&completed)?);
    }

    // Non-zero exit for malicious / failed outcomes so scripts can branch.
    match completed.automated_verdict {
        models::Verdict::Malicious | models::Verdict::ScanFailed => {
            std::process::exit(2);
        }
        _ => Ok(()),
    }
}

async fn run_queue_worker() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_max_level(Level::INFO)
        .init();

    let config = config::Config::from_env()?;
    info!(
        worker_id = %config.worker_id,
        queue = SCAN_QUEUE_NAME,
        concurrency = config.worker_concurrency,
        "kapea scan-worker starting"
    );

    let pipeline = Arc::new(ScanPipeline::new(config.clone()).await?);
    let connection = RedisConnectionOptions {
        url: config.redis_url.clone(),
        ..Default::default()
    };

    let processor: ProcessorFn = {
        let pipeline = Arc::clone(&pipeline);
        Arc::new(move |mut job, _token: CancellationToken| {
            let pipeline = Arc::clone(&pipeline);
            Box::pin(async move {
                if job.name() != SCAN_JOB_NAME {
                    return Err(bullmq::Error::Unrecoverable(format!(
                        "unexpected job name: {}",
                        job.name()
                    )));
                }

                let event = messaging::parse_scan_requested(job.data()).map_err(|err| {
                    error!(%err, job_id = %job.id(), "invalid scan.requested job data");
                    bullmq::Error::Unrecoverable(err.to_string())
                })?;

                info!(
                    job_id = %job.id(),
                    scan_id = %event.scan_id,
                    "processing scan job"
                );

                let completed = pipeline
                    .handle_scan_requested(&mut job, event)
                    .await
                    .map_err(|err| {
                        error!(%err, job_id = %job.id(), "scan pipeline returned unexpected error");
                        bullmq::Error::ProcessingError(err.to_string())
                    })?;

                serde_json::to_value(completed).map_err(|err| {
                    error!(%err, "serialize scan.completed return value");
                    bullmq::Error::from(err)
                })
            })
        })
    };

    let worker = Worker::with_options(
        SCAN_QUEUE_NAME,
        processor,
        WorkerOptions {
            connection,
            concurrency: config.worker_concurrency,
            ..Default::default()
        },
    )
    .await
    .context("create BullMQ scan-jobs worker")?;

    info!(queue = SCAN_QUEUE_NAME, "BullMQ worker ready");

    // Stay alive until SIGINT/SIGTERM. Do not rely on ctrl_c alone — under some
    // supervised/nohup environments only SIGTERM is delivered on shutdown.
    wait_for_shutdown_signal().await;
    info!("shutdown signal received");

    worker
        .close(5_000)
        .await
        .context("graceful BullMQ worker shutdown")?;

    info!("shutting down");
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                error!(%err, "failed to install SIGTERM handler; waiting on ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        return;
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
