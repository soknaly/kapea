-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('UPLOADING', 'QUEUED', 'SCANNING', 'COMPLETED', 'FAILED', 'EXPIRED', 'DELETED');

-- CreateEnum
CREATE TYPE "Verdict" AS ENUM ('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN', 'SCAN_FAILED');

-- CreateEnum
CREATE TYPE "FileSource" AS ENUM ('WEB_API', 'TELEGRAM');

-- CreateTable
CREATE TABLE "files" (
    "id" TEXT NOT NULL,
    "original_filename" TEXT NOT NULL,
    "sanitized_filename" TEXT NOT NULL,
    "storage_bucket" TEXT NOT NULL,
    "storage_key" TEXT NOT NULL,
    "size_bytes" BIGINT NOT NULL,
    "claimed_mime_type" TEXT,
    "detected_mime_type" TEXT,
    "extension" TEXT,
    "sha256" TEXT,
    "sha1" TEXT,
    "md5" TEXT,
    "source" "FileSource" NOT NULL,
    "source_reference" TEXT,
    "uploaded_by" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3),
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "files_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_jobs" (
    "id" TEXT NOT NULL,
    "file_id" TEXT NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "current_stage" TEXT,
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "message_event_id" TEXT,
    "started_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "failed_at" TIMESTAMP(3),
    "failure_code" TEXT,
    "failure_message" TEXT,
    "worker_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scan_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" TEXT NOT NULL,
    "scan_job_id" TEXT NOT NULL,
    "verdict" "Verdict" NOT NULL,
    "automated_verdict" "Verdict" NOT NULL,
    "risk_score" INTEGER NOT NULL,
    "summary" TEXT NOT NULL,
    "scan_complete" BOOLEAN NOT NULL,
    "clamav_version" TEXT,
    "clamav_signature_version" TEXT,
    "yara_rule_version" TEXT,
    "scanner_version" TEXT,
    "event_version" INTEGER NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_findings" (
    "id" TEXT NOT NULL,
    "scan_result_id" TEXT NOT NULL,
    "engine" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" INTEGER NOT NULL,
    "confidence" INTEGER NOT NULL,
    "message" TEXT NOT NULL,
    "technical_details_json" JSONB,
    "path_inside_archive" TEXT,
    "parent_file_reference" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "extracted_indicators" (
    "id" TEXT NOT NULL,
    "scan_result_id" TEXT NOT NULL,
    "indicator_type" TEXT NOT NULL,
    "indicator_value" TEXT NOT NULL,
    "source_path" TEXT,
    "reputation" TEXT,
    "reputation_provider" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "extracted_indicators_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" TEXT NOT NULL,
    "actor_type" TEXT NOT NULL,
    "actor_id" TEXT,
    "action" TEXT NOT NULL,
    "entity_type" TEXT NOT NULL,
    "entity_id" TEXT NOT NULL,
    "metadata_json" JSONB,
    "ip_address" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scanner_definitions" (
    "id" TEXT NOT NULL,
    "engine" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "installed_at" TIMESTAMP(3) NOT NULL,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "metadata_json" JSONB,

    CONSTRAINT "scanner_definitions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "files_sha256_idx" ON "files"("sha256");

-- CreateIndex
CREATE INDEX "scan_jobs_status_idx" ON "scan_jobs"("status");

-- CreateIndex
CREATE INDEX "scan_jobs_file_id_idx" ON "scan_jobs"("file_id");

-- CreateIndex
CREATE UNIQUE INDEX "scan_results_scan_job_id_key" ON "scan_results"("scan_job_id");

-- CreateIndex
CREATE INDEX "scan_findings_scan_result_id_idx" ON "scan_findings"("scan_result_id");

-- CreateIndex
CREATE INDEX "extracted_indicators_scan_result_id_idx" ON "extracted_indicators"("scan_result_id");

-- CreateIndex
CREATE INDEX "audit_logs_entity_type_entity_id_idx" ON "audit_logs"("entity_type", "entity_id");

-- CreateIndex
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "scanner_definitions_engine_key" ON "scanner_definitions"("engine");

-- AddForeignKey
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_scan_job_id_fkey" FOREIGN KEY ("scan_job_id") REFERENCES "scan_jobs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_result_id_fkey" FOREIGN KEY ("scan_result_id") REFERENCES "scan_results"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "extracted_indicators" ADD CONSTRAINT "extracted_indicators_scan_result_id_fkey" FOREIGN KEY ("scan_result_id") REFERENCES "scan_results"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

