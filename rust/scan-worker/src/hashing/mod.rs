//! File hash computation and integrity verification.

use std::path::Path;

use anyhow::{Context, Result};
use md5::{Digest as Md5Digest, Md5};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::models::FileHashes;

const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashVerificationError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct HashResult {
    pub size_bytes: u64,
    pub hashes: FileHashes,
}

pub async fn hash_file(path: &Path) -> Result<HashResult> {
    let mut file = File::open(path)
        .await
        .with_context(|| format!("open file for hashing: {}", path.display()))?;

    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut size_bytes = 0u64;
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let read = file
            .read(&mut buffer)
            .await
            .context("read file while hashing")?;
        if read == 0 {
            break;
        }
        size_bytes += read as u64;
        sha256.update(&buffer[..read]);
        sha1.update(&buffer[..read]);
        md5.update(&buffer[..read]);
    }

    Ok(HashResult {
        size_bytes,
        hashes: FileHashes {
            sha256: hex::encode(sha256.finalize()),
            sha1: hex::encode(sha1.finalize()),
            md5: hex::encode(md5.finalize()),
        },
    })
}

pub fn verify_integrity(
    actual_size: u64,
    expected_size: u64,
    actual_sha256: &str,
    expected_sha256: Option<&str>,
) -> Result<(), HashVerificationError> {
    if actual_size != expected_size {
        return Err(HashVerificationError {
            code: "SIZE_MISMATCH",
            message: format!(
                "expected size {expected_size} bytes, got {actual_size} bytes"
            ),
        });
    }

    if let Some(expected) = expected_sha256 {
        let expected = expected.to_ascii_lowercase();
        let actual = actual_sha256.to_ascii_lowercase();
        if expected != actual {
            return Err(HashVerificationError {
                code: "HASH_MISMATCH",
                message: format!("expected sha256 {expected}, got {actual}"),
            });
        }
    }

    Ok(())
}

pub fn hash_bytes(data: &[u8]) -> FileHashes {
    FileHashes {
        sha256: hex::encode(Sha256::digest(data)),
        sha1: hex::encode(Sha1::digest(data)),
        md5: hex::encode(Md5::digest(data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn hash_mismatch_detected() {
        let err = verify_integrity(10, 10, "abc", Some("def")).unwrap_err();
        assert_eq!(err.code, "HASH_MISMATCH");
    }

    #[test]
    fn size_mismatch_detected() {
        let err = verify_integrity(5, 10, "abc", None).unwrap_err();
        assert_eq!(err.code, "SIZE_MISMATCH");
    }

    #[test]
    fn matching_integrity_passes() {
        verify_integrity(10, 10, "abc", Some("abc")).unwrap();
    }

    #[tokio::test]
    async fn hash_file_matches_hash_bytes() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"kapea-test").unwrap();
        tmp.flush().unwrap();

        let result = hash_file(tmp.path()).await.unwrap();
        let direct = hash_bytes(b"kapea-test");
        assert_eq!(result.hashes.sha256, direct.sha256);
        assert_eq!(result.hashes.sha1, direct.sha1);
        assert_eq!(result.hashes.md5, direct.md5);
        assert_eq!(result.size_bytes, 14);
    }
}
