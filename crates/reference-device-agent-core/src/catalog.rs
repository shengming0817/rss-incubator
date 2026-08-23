use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::material::{CredentialError, ValidatedCredential, validate_credential};
use crate::{CredentialFiles, CredentialGeneration, DeviceCommand, DeviceIdentity, Sha256Digest};

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("artifact catalog is unavailable")]
    Unavailable,
    #[error("artifact catalog is malformed or unsupported")]
    Malformed,
    #[error("artifact was not found")]
    NotFound,
    #[error("artifact binding does not match the command")]
    BindingMismatch,
    #[error("artifact digest does not match its files")]
    DigestMismatch,
    #[error("artifact credential is revoked")]
    Revoked,
    #[error(transparent)]
    Credential(#[from] CredentialError),
}

pub(crate) struct ResolvedArtifact {
    pub credential_generation: CredentialGeneration,
    pub credential: ValidatedCredential,
    pub digest: Sha256Digest,
}

#[derive(Debug)]
pub struct ArtifactCatalog {
    path: PathBuf,
}

impl ArtifactCatalog {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn resolve(
        &self,
        identity: &DeviceIdentity,
        command: &DeviceCommand,
        now_epoch_seconds: u64,
    ) -> Result<ResolvedArtifact, CatalogError> {
        let bytes = fs::read(&self.path).map_err(|_| CatalogError::Unavailable)?;
        let catalog: CatalogV1 =
            serde_json::from_slice(&bytes).map_err(|_| CatalogError::Malformed)?;
        if catalog.schema_version != 1 {
            return Err(CatalogError::Malformed);
        }
        let entry = catalog
            .artifacts
            .into_iter()
            .find(|entry| entry.artifact_id == command.artifact_id().expose())
            .ok_or(CatalogError::NotFound)?;
        validate_binding(identity, command, &entry)?;
        if entry.revoked {
            return Err(CatalogError::Revoked);
        }

        let root = self.path.parent().unwrap_or_else(|| Path::new("."));
        let files = CredentialFiles::new(
            safe_catalog_path(root, &entry.ca_path)?,
            safe_catalog_path(root, &entry.certificate_path)?,
            safe_catalog_path(root, &entry.private_key_path)?,
        );
        let computed = compute_artifact_digest(&files).map_err(|_| CatalogError::Unavailable)?;
        let declared =
            Sha256Digest::try_from(entry.artifact_digest).map_err(|_| CatalogError::Malformed)?;
        if &computed != command.artifact_digest() || computed != declared {
            return Err(CatalogError::DigestMismatch);
        }
        let generation = CredentialGeneration::try_from(entry.credential_generation)
            .map_err(|_| CatalogError::Malformed)?;
        let target_identity = DeviceIdentity::new(identity.tenant(), identity.device(), generation);
        let credential = validate_credential(&files, &target_identity, now_epoch_seconds)?;
        Ok(ResolvedArtifact {
            credential_generation: generation,
            credential,
            digest: computed,
        })
    }
}

/// Computes the domain-separated digest of a local credential artifact closure.
///
/// # Errors
///
/// Returns an error when any credential file cannot be read.
pub fn compute_artifact_digest(files: &CredentialFiles) -> Result<Sha256Digest, std::io::Error> {
    let mut hasher = Sha256::new();
    hasher.update(b"rss.reference-device-agent.artifact.v1\0");
    for path in [
        files.ca_certificate(),
        files.certificate_chain(),
        files.private_key(),
    ] {
        let bytes = fs::read(path)?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        hasher.update(len.to_be_bytes());
        hasher.update(bytes);
    }
    Sha256Digest::try_from(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|_| std::io::Error::other("SHA-256 formatting failed"))
}

fn validate_binding(
    identity: &DeviceIdentity,
    command: &DeviceCommand,
    entry: &CatalogEntryV1,
) -> Result<(), CatalogError> {
    let matches = entry.tenant_id == identity.tenant()
        && entry.device_id == identity.device()
        && entry.desired_generation == command.desired_generation().get()
        && entry.fence_epoch == command.fence_epoch().get()
        && entry.intent_digest == command.intent_digest().expose()
        && entry.policy_hash == command.policy_hash().expose();
    matches.then_some(()).ok_or(CatalogError::BindingMismatch)
}

fn safe_catalog_path(root: &Path, raw: &str) -> Result<PathBuf, CatalogError> {
    let path = Path::new(raw);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CatalogError::Malformed);
    }
    let canonical_root = root.canonicalize().map_err(|_| CatalogError::Unavailable)?;
    let mut candidate = canonical_root.clone();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(CatalogError::Malformed);
        };
        candidate.push(component);
        let metadata = fs::symlink_metadata(&candidate).map_err(|_| CatalogError::Unavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(CatalogError::Malformed);
        }
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|_| CatalogError::Unavailable)?;
    if !canonical.starts_with(&canonical_root)
        || !fs::metadata(&canonical)
            .map_err(|_| CatalogError::Unavailable)?
            .is_file()
    {
        return Err(CatalogError::Malformed);
    }
    Ok(canonical)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogV1 {
    schema_version: u8,
    artifacts: Vec<CatalogEntryV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogEntryV1 {
    artifact_id: String,
    artifact_digest: String,
    tenant_id: Uuid,
    device_id: Uuid,
    credential_generation: u64,
    desired_generation: u64,
    fence_epoch: u64,
    intent_digest: String,
    policy_hash: String,
    ca_path: String,
    certificate_path: String,
    private_key_path: String,
    revoked: bool,
}
