use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rotation_model::{CredentialRevision, InstalledCredentialPosition};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::material::ValidatedCredential;
use crate::{
    AckFact, CommandRejection, CredentialFiles, CredentialGeneration, DeviceIdentity, OutboundFact,
    ReportFact, Sha256Digest,
};

pub(crate) const OUTBOX_LIMIT: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("device state is unavailable")]
    Unavailable,
    #[error("device state is malformed, unsupported, or bound to another identity")]
    InvalidState,
    #[error("durable outbox is full")]
    OutboxFull,
    #[error("credential revision already exists with different material")]
    RevisionConflict,
}

pub(crate) struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub fn load(
        root: impl Into<PathBuf>,
        identity: &DeviceIdentity,
    ) -> Result<(Self, StateV1), StoreError> {
        let store = Self { root: root.into() };
        let bytes = fs::read(store.state_path()).map_err(|_| StoreError::Unavailable)?;
        let state: StateV1 =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidState)?;
        state.verify(identity)?;
        Ok((store, state))
    }

    pub fn open_or_initialize(
        root: impl Into<PathBuf>,
        identity: &DeviceIdentity,
        position: InstalledCredentialPosition,
        initial: &ValidatedCredential,
        initial_digest: &Sha256Digest,
    ) -> Result<(Self, StateV1), StoreError> {
        let store = Self { root: root.into() };
        fs::create_dir_all(store.credentials_root()).map_err(|_| StoreError::Unavailable)?;
        let state_path = store.state_path();
        let state = if state_path.exists() {
            let bytes = fs::read(&state_path).map_err(|_| StoreError::Unavailable)?;
            let state: StateV1 =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidState)?;
            state.verify(identity)?;
            state
        } else {
            store.install_revision(position.credential_revision(), initial)?;
            let state = StateV1::initial(identity, position, initial_digest, initial.expires_at);
            store.persist(&state)?;
            state
        };
        Ok((store, state))
    }

    pub fn persist(&self, state: &StateV1) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(state).map_err(|_| StoreError::InvalidState)?;
        let temporary = self.root.join("state.v1.json.tmp");
        remove_stale_file(&temporary)?;
        write_synced(&temporary, &bytes, 0o600)?;
        fs::rename(&temporary, self.state_path()).map_err(|_| StoreError::Unavailable)?;
        sync_directory(&self.root)
    }

    pub fn install_revision(
        &self,
        revision: CredentialRevision,
        credential: &ValidatedCredential,
    ) -> Result<(), StoreError> {
        let target = self.revision_root(revision.get());
        if target.exists() {
            return verify_existing_revision(&target, credential);
        }
        let staging = self
            .credentials_root()
            .join(format!(".revision-{}.staging", revision.get()));
        remove_stale_directory(&staging)?;
        fs::create_dir(&staging).map_err(|_| StoreError::Unavailable)?;
        let result = (|| {
            write_synced(&staging.join("ca.pem"), &credential.ca, 0o600)?;
            write_synced(
                &staging.join("certificate.pem"),
                &credential.certificate,
                0o600,
            )?;
            write_synced(
                &staging.join("private-key.pem"),
                &credential.private_key,
                0o600,
            )?;
            sync_directory(&staging)?;
            fs::rename(&staging, &target).map_err(|_| StoreError::Unavailable)?;
            sync_directory(&self.credentials_root())
        })();
        if result.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    #[must_use]
    pub fn credential_files(&self, revision: u64) -> CredentialFiles {
        let root = self.revision_root(revision);
        CredentialFiles::new(
            root.join("ca.pem"),
            root.join("certificate.pem"),
            root.join("private-key.pem"),
        )
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.v1.json")
    }

    fn credentials_root(&self) -> PathBuf {
        self.root.join("credentials")
    }

    fn revision_root(&self, revision: u64) -> PathBuf {
        self.credentials_root().join(format!("revision-{revision}"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateV1 {
    schema_version: u8,
    identity: StoredIdentity,
    current: StoredCurrent,
    device_sequence: u64,
    last_command: Option<StoredCommand>,
    outbox: Vec<StoredOutbound>,
    reconnect_revision: Option<u64>,
}

impl StateV1 {
    fn initial(
        identity: &DeviceIdentity,
        position: InstalledCredentialPosition,
        digest: &Sha256Digest,
        expires_at: i64,
    ) -> Self {
        Self {
            schema_version: 1,
            identity: StoredIdentity::from_identity(identity),
            current: StoredCurrent {
                desired_generation: position.desired_generation().get(),
                fence_epoch: position.fence_epoch().get(),
                credential_revision: position.credential_revision().get(),
                artifact_digest: digest.expose().to_owned(),
                expires_at,
            },
            device_sequence: 0,
            last_command: None,
            outbox: Vec::new(),
            reconnect_revision: None,
        }
    }

    fn verify(&self, identity: &DeviceIdentity) -> Result<(), StoreError> {
        let valid = self.schema_version == 1
            && self.identity.tenant_id == identity.tenant()
            && self.identity.device_id == identity.device()
            && self.current.desired_generation > 0
            && self.current.fence_epoch > 0
            && self.current.credential_revision > 0
            && self.outbox.len() <= OUTBOX_LIMIT;
        valid.then_some(()).ok_or(StoreError::InvalidState)
    }

    pub fn current_generation(&self) -> u64 {
        self.current.desired_generation
    }
    pub fn current_fence(&self) -> u64 {
        self.current.fence_epoch
    }
    pub fn current_revision(&self) -> u64 {
        self.current.credential_revision
    }
    pub fn current_credential_generation(&self) -> u64 {
        self.identity.credential_generation
    }
    pub fn current_identity(&self) -> Result<DeviceIdentity, StoreError> {
        let generation = CredentialGeneration::try_from(self.identity.credential_generation)
            .map_err(|_| StoreError::InvalidState)?;
        Ok(DeviceIdentity::new(
            self.identity.tenant_id,
            self.identity.device_id,
            generation,
        ))
    }
    pub fn reconnect_revision(&self) -> Option<u64> {
        self.reconnect_revision
    }
    pub fn last_command(&self) -> Option<&StoredCommand> {
        self.last_command.as_ref()
    }

    pub fn reserve_outbox(&self, count: usize) -> Result<(), StoreError> {
        (self.outbox.len().saturating_add(count) <= OUTBOX_LIMIT)
            .then_some(())
            .ok_or(StoreError::OutboxFull)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        command_id: String,
        fingerprint: String,
        generation: u64,
        fence: u64,
        credential_generation: u64,
        revision: u64,
        artifact_digest: String,
        expires_at: i64,
        observed_at: i64,
    ) {
        self.device_sequence = self.device_sequence.saturating_add(1);
        let ack_sequence = self.device_sequence;
        self.device_sequence = self.device_sequence.saturating_add(1);
        let report_sequence = self.device_sequence;
        let ack_event = event_id("ack", &command_id);
        let report_event = event_id("report", &command_id);
        let state_hash = state_hash(
            self.identity.tenant_id,
            self.identity.device_id,
            credential_generation,
            generation,
            fence,
            revision,
            &artifact_digest,
        );
        self.identity.credential_generation = credential_generation;
        self.current = StoredCurrent {
            desired_generation: generation,
            fence_epoch: fence,
            credential_revision: revision,
            artifact_digest: artifact_digest.clone(),
            expires_at,
        };
        self.last_command = Some(StoredCommand {
            command_id: command_id.clone(),
            fingerprint,
            desired_generation: generation,
            fence_epoch: fence,
            outcome: StoredCommandOutcome::Accepted,
        });
        self.outbox.push(StoredOutbound::Ack {
            event_id: ack_event,
            payload: StoredAck {
                command_id,
                desired_generation: generation,
                fence_epoch: fence,
                device_sequence: ack_sequence,
                observed_at,
                rejection: None,
            },
        });
        self.outbox.push(StoredOutbound::ReportBlocked {
            event_id: report_event,
            payload: StoredReport {
                observed_generation: generation,
                fence_epoch: fence,
                device_sequence: report_sequence,
                observed_at,
                state_hash,
                artifact_digest,
                expires_at: Some(expires_at),
            },
        });
    }

    pub fn reject(
        &mut self,
        command_id: String,
        fingerprint: String,
        generation: u64,
        fence: u64,
        rejection: CommandRejection,
        observed_at: i64,
    ) {
        self.device_sequence = self.device_sequence.saturating_add(1);
        self.last_command = Some(StoredCommand {
            command_id: command_id.clone(),
            fingerprint,
            desired_generation: generation,
            fence_epoch: fence,
            outcome: StoredCommandOutcome::Rejected(rejection.into()),
        });
        self.outbox.push(StoredOutbound::Ack {
            event_id: event_id("ack", &command_id),
            payload: StoredAck {
                command_id,
                desired_generation: generation,
                fence_epoch: fence,
                device_sequence: self.device_sequence,
                observed_at,
                rejection: Some(rejection.into()),
            },
        });
    }

    pub fn reject_conflicting_replay(
        &mut self,
        command_id: String,
        fingerprint: &str,
        generation: u64,
        fence: u64,
        observed_at: i64,
    ) {
        self.device_sequence = self.device_sequence.saturating_add(1);
        let mut event_source = command_id.clone();
        event_source.push('\0');
        event_source.push_str(fingerprint);
        self.outbox.push(StoredOutbound::Ack {
            event_id: event_id("rejected", &event_source),
            payload: StoredAck {
                command_id,
                desired_generation: generation,
                fence_epoch: fence,
                device_sequence: self.device_sequence,
                observed_at,
                rejection: Some(StoredRejection::MalformedCommand),
            },
        });
    }

    pub fn has_command_ack(&self, command_id: &str) -> bool {
        self.outbox.iter().any(|entry| {
            matches!(entry, StoredOutbound::Ack { payload, .. } if payload.command_id == command_id)
        })
    }

    pub fn replay_last(&mut self, observed_at: i64) -> Result<(), StoreError> {
        let last = self.last_command.clone().ok_or(StoreError::InvalidState)?;
        self.device_sequence = self.device_sequence.saturating_add(1);
        let rejection = match last.outcome {
            StoredCommandOutcome::Accepted => None,
            StoredCommandOutcome::Rejected(reason) => Some(reason),
        };
        self.outbox.push(StoredOutbound::Ack {
            event_id: event_id("ack", &last.command_id),
            payload: StoredAck {
                command_id: last.command_id,
                desired_generation: last.desired_generation,
                fence_epoch: last.fence_epoch,
                device_sequence: self.device_sequence,
                observed_at,
                rejection,
            },
        });
        Ok(())
    }

    pub fn next_outbound(&self) -> Option<OutboundFact> {
        self.outbox.iter().find_map(StoredOutbound::ready_fact)
    }

    pub fn confirm_outbound(&mut self, event_id: &str) -> bool {
        let Some(index) = self
            .outbox
            .iter()
            .position(|item| item.event_id() == event_id)
        else {
            return false;
        };
        let was_ack = matches!(self.outbox[index], StoredOutbound::Ack { .. });
        self.outbox.remove(index);
        if was_ack
            && self
                .outbox
                .iter()
                .any(|item| matches!(item, StoredOutbound::ReportBlocked { .. }))
        {
            self.reconnect_revision = Some(self.current.credential_revision);
        }
        true
    }

    pub fn mark_reconnected(&mut self, revision: u64) -> bool {
        if self.reconnect_revision != Some(revision) {
            return false;
        }
        for entry in &mut self.outbox {
            if let StoredOutbound::ReportBlocked { event_id, payload } = entry.clone() {
                *entry = StoredOutbound::ReportReady { event_id, payload };
            }
        }
        self.reconnect_revision = None;
        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredIdentity {
    tenant_id: Uuid,
    device_id: Uuid,
    credential_generation: u64,
}

impl StoredIdentity {
    fn from_identity(identity: &DeviceIdentity) -> Self {
        Self {
            tenant_id: identity.tenant(),
            device_id: identity.device(),
            credential_generation: identity.credential_generation().get(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCurrent {
    desired_generation: u64,
    fence_epoch: u64,
    credential_revision: u64,
    artifact_digest: String,
    expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredCommand {
    command_id: String,
    fingerprint: String,
    desired_generation: u64,
    fence_epoch: u64,
    outcome: StoredCommandOutcome,
}

impl StoredCommand {
    pub fn matches(&self, command_id: &str, fingerprint: &str) -> Option<bool> {
        (self.command_id == command_id).then(|| self.fingerprint == fingerprint)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "reason")]
enum StoredCommandOutcome {
    Accepted,
    Rejected(StoredRejection),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
enum StoredOutbound {
    Ack {
        event_id: String,
        payload: StoredAck,
    },
    ReportBlocked {
        event_id: String,
        payload: StoredReport,
    },
    ReportReady {
        event_id: String,
        payload: StoredReport,
    },
}

impl StoredOutbound {
    fn event_id(&self) -> &str {
        match self {
            Self::Ack { event_id, .. }
            | Self::ReportBlocked { event_id, .. }
            | Self::ReportReady { event_id, .. } => event_id,
        }
    }

    fn ready_fact(&self) -> Option<OutboundFact> {
        match self {
            Self::Ack { event_id, payload } => Some(OutboundFact::CommandAcknowledged {
                event_id: event_id.clone(),
                payload: payload.clone().into(),
            }),
            Self::ReportReady { event_id, payload } => Some(OutboundFact::CertificateReported {
                event_id: event_id.clone(),
                payload: payload.clone().into(),
            }),
            Self::ReportBlocked { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAck {
    command_id: String,
    desired_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    observed_at: i64,
    rejection: Option<StoredRejection>,
}

impl From<StoredAck> for AckFact {
    fn from(value: StoredAck) -> Self {
        Self {
            command_id: value.command_id,
            desired_generation: value.desired_generation,
            fence_epoch: value.fence_epoch,
            device_sequence: value.device_sequence,
            observed_at: value.observed_at,
            rejection: value.rejection.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredReport {
    observed_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    observed_at: i64,
    state_hash: String,
    artifact_digest: String,
    expires_at: Option<i64>,
}

impl From<StoredReport> for ReportFact {
    fn from(value: StoredReport) -> Self {
        Self {
            observed_generation: value.observed_generation,
            fence_epoch: value.fence_epoch,
            device_sequence: value.device_sequence,
            observed_at: value.observed_at,
            state_hash: value.state_hash,
            artifact_digest: value.artifact_digest,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum StoredRejection {
    ArtifactUnavailable,
    ArtifactDigestMismatch,
    PolicyRejected,
    GenerationStale,
    FenceEpochStale,
    MalformedCommand,
    DeviceFailure,
}

impl From<CommandRejection> for StoredRejection {
    fn from(value: CommandRejection) -> Self {
        match value {
            CommandRejection::ArtifactUnavailable => Self::ArtifactUnavailable,
            CommandRejection::ArtifactDigestMismatch => Self::ArtifactDigestMismatch,
            CommandRejection::PolicyRejected => Self::PolicyRejected,
            CommandRejection::GenerationStale => Self::GenerationStale,
            CommandRejection::FenceEpochStale => Self::FenceEpochStale,
            CommandRejection::MalformedCommand => Self::MalformedCommand,
            CommandRejection::DeviceFailure => Self::DeviceFailure,
        }
    }
}

impl From<StoredRejection> for CommandRejection {
    fn from(value: StoredRejection) -> Self {
        match value {
            StoredRejection::ArtifactUnavailable => Self::ArtifactUnavailable,
            StoredRejection::ArtifactDigestMismatch => Self::ArtifactDigestMismatch,
            StoredRejection::PolicyRejected => Self::PolicyRejected,
            StoredRejection::GenerationStale => Self::GenerationStale,
            StoredRejection::FenceEpochStale => Self::FenceEpochStale,
            StoredRejection::MalformedCommand => Self::MalformedCommand,
            StoredRejection::DeviceFailure => Self::DeviceFailure,
        }
    }
}

fn event_id(kind: &str, command_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rss.reference-device-agent.event.v1\0");
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(command_id.as_bytes());
    format!("reference-{kind}-{:x}", hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
fn state_hash(
    tenant: Uuid,
    device: Uuid,
    credential_generation: u64,
    desired_generation: u64,
    fence: u64,
    revision: u64,
    artifact_digest: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rss.reference-device-agent.state.v1\0");
    hasher.update(tenant.as_bytes());
    hasher.update(device.as_bytes());
    for value in [credential_generation, desired_generation, fence, revision] {
        hasher.update(value.to_be_bytes());
    }
    hasher.update(artifact_digest.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn write_synced(path: &Path, bytes: &[u8], mode: u32) -> Result<(), StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|_| StoreError::Unavailable)?;
    file.write_all(bytes).map_err(|_| StoreError::Unavailable)?;
    file.sync_all().map_err(|_| StoreError::Unavailable)
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::Unavailable)
}

fn remove_stale_file(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => sync_directory(path.parent().ok_or(StoreError::Unavailable)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::Unavailable),
    }
}

fn remove_stale_directory(path: &Path) -> Result<(), StoreError> {
    match fs::remove_dir_all(path) {
        Ok(()) => sync_directory(path.parent().ok_or(StoreError::Unavailable)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::Unavailable),
    }
}

fn verify_existing_revision(
    root: &Path,
    credential: &ValidatedCredential,
) -> Result<(), StoreError> {
    let matches = fs::read(root.join("ca.pem")).ok().as_deref() == Some(&credential.ca)
        && fs::read(root.join("certificate.pem")).ok().as_deref() == Some(&credential.certificate)
        && fs::read(root.join("private-key.pem")).ok().as_deref() == Some(&credential.private_key);
    matches.then_some(()).ok_or(StoreError::RevisionConflict)
}

pub(crate) fn next_revision(state: &StateV1) -> Result<CredentialRevision, StoreError> {
    let revision = state
        .current_revision()
        .checked_add(1)
        .ok_or(StoreError::InvalidState)?;
    CredentialRevision::try_from(revision).map_err(|_| StoreError::InvalidState)
}
