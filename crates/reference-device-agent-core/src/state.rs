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
    ReportFact, Sha256Digest, TopicSet,
};

pub(crate) const OUTBOX_LIMIT: usize = 128;
const COMMAND_JOURNAL_LIMIT: usize = 1024;

pub(crate) struct AcceptedCommand {
    pub command_id: String,
    pub fingerprint: String,
    pub generation: u64,
    pub fence: u64,
    pub credential_generation: u64,
    pub revision: u64,
    pub artifact_digest: String,
    pub expires_at: i64,
    pub observed_at: i64,
    pub retain_until_epoch_seconds: u64,
}

pub(crate) struct RejectedCommand {
    pub command_id: String,
    pub fingerprint: String,
    pub generation: u64,
    pub fence: u64,
    pub rejection: CommandRejection,
    pub observed_at: i64,
    pub retain_until_epoch_seconds: u64,
}

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
    #[error("device state is already owned by another process")]
    AlreadyOpen,
    #[error("durable command journal is full")]
    CommandJournalFull,
}

pub(crate) struct StateStore {
    root: PathBuf,
    _owner_lock: File,
}

impl StateStore {
    fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| StoreError::Unavailable)?;
        let lock_path = root.join("state.owner.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let owner_lock = options
            .open(lock_path)
            .map_err(|_| StoreError::Unavailable)?;
        rustix::fs::flock(
            &owner_lock,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                StoreError::AlreadyOpen
            } else {
                StoreError::Unavailable
            }
        })?;
        Ok(Self {
            root,
            _owner_lock: owner_lock,
        })
    }

    pub fn load(
        root: impl Into<PathBuf>,
        identity: &DeviceIdentity,
    ) -> Result<(Self, StateV1), StoreError> {
        let store = Self::open(root)?;
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
        let store = Self::open(root)?;
        fs::create_dir_all(store.credentials_root()).map_err(|_| StoreError::Unavailable)?;
        let state_path = store.state_path();
        let state = if state_path.exists() {
            let bytes = fs::read(&state_path).map_err(|_| StoreError::Unavailable)?;
            let state: StateV1 =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidState)?;
            state.verify(identity)?;
            state
        } else {
            if store.has_committed_revision()? {
                return Err(StoreError::InvalidState);
            }
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

    fn has_committed_revision(&self) -> Result<bool, StoreError> {
        let entries = match fs::read_dir(self.credentials_root()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(StoreError::Unavailable),
        };
        for entry in entries {
            let entry = entry.map_err(|_| StoreError::Unavailable)?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("revision-") {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateV1 {
    schema_version: u8,
    identity: StoredIdentity,
    current: StoredCurrent,
    device_sequence: u64,
    command_journal: Vec<StoredCommand>,
    outbox: Vec<StoredOutbound>,
    reconnect_revision: Option<u64>,
    pending_inbound: Option<StoredInboundSettlement>,
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
            command_journal: Vec::new(),
            outbox: Vec::new(),
            reconnect_revision: None,
            pending_inbound: None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn verify(&self, identity: &DeviceIdentity) -> Result<(), StoreError> {
        let coordinates_valid = self.schema_version == 1
            && self.identity.tenant_id == identity.tenant()
            && self.identity.device_id == identity.device()
            && self.identity.credential_generation > 0
            && self.current.desired_generation > 0
            && self.current.fence_epoch > 0
            && self.current.credential_revision > 0
            && self.current.expires_at > 0
            && Sha256Digest::try_from(self.current.artifact_digest.clone()).is_ok()
            && self.outbox.len() <= OUTBOX_LIMIT
            && self.command_journal.len() <= COMMAND_JOURNAL_LIMIT;
        if !coordinates_valid {
            return Err(StoreError::InvalidState);
        }
        let mut event_ids = std::collections::HashSet::new();
        let mut sequences = std::collections::HashSet::new();
        for entry in &self.outbox {
            if !event_ids.insert(entry.event_id()) {
                return Err(StoreError::InvalidState);
            }
            let sequence = entry.sequence();
            if sequence == 0
                || sequence > self.device_sequence
                || !sequences.insert(sequence)
                || !entry.semantic_valid()
            {
                return Err(StoreError::InvalidState);
            }
            if let Some(report) = entry.report_payload() {
                let expected_hash = state_hash(
                    self.identity.tenant_id,
                    self.identity.device_id,
                    report.credential_generation,
                    report.observed_generation,
                    report.fence_epoch,
                    report.credential_revision,
                    &report.artifact_digest,
                );
                if report.state_hash != expected_hash
                    || report.credential_revision != self.current.credential_revision
                    || report.observed_generation != self.current.desired_generation
                    || report.fence_epoch != self.current.fence_epoch
                    || report.artifact_digest != self.current.artifact_digest
                {
                    return Err(StoreError::InvalidState);
                }
            }
        }
        let mut command_ids = std::collections::HashSet::new();
        for command in &self.command_journal {
            if !command_ids.insert(command.command_id.as_str()) || !command.semantic_valid() {
                return Err(StoreError::InvalidState);
            }
        }
        if let Some(pending) = &self.pending_inbound {
            let generation = CredentialGeneration::try_from(pending.credential_generation)
                .map_err(|_| StoreError::InvalidState)?;
            let identity = DeviceIdentity::try_new(
                self.identity.tenant_id,
                self.identity.device_id,
                generation,
            )
            .map_err(|_| StoreError::InvalidState)?;
            let valid = !pending.command_id.is_empty()
                && Sha256Digest::try_from(pending.fingerprint.clone()).is_ok()
                && pending.topic == TopicSet::new(&identity).command()
                && pending.settlement_token
                    == settlement_token(&pending.topic, &pending.command_id, &pending.fingerprint)
                && self.command_journal.iter().any(|command| {
                    command.command_id == pending.command_id
                        && command.fingerprint == pending.fingerprint
                });
            if !valid {
                return Err(StoreError::InvalidState);
            }
        }
        let reports = self
            .outbox
            .iter()
            .filter(|entry| entry.report_payload().is_some())
            .count();
        if reports > 1 {
            return Err(StoreError::InvalidState);
        }
        if self.pending_inbound.is_some() != (reports == 1) {
            return Err(StoreError::InvalidState);
        }
        for entry in &self.outbox {
            match entry {
                StoredOutbound::Ack { payload, .. } if payload.activates_revision.is_some() => {
                    let revision = payload.activates_revision.unwrap_or_default();
                    let matching = revision == self.current.credential_revision
                        && self.outbox.iter().any(|candidate| {
                            matches!(candidate, StoredOutbound::ReportBlocked { payload: report, .. }
                                if report.credential_revision == revision
                                    && report.command_id == payload.command_id)
                        })
                        && self.reconnect_revision.is_none();
                    if !matching {
                        return Err(StoreError::InvalidState);
                    }
                }
                StoredOutbound::ReportBlocked { payload, .. } => {
                    let has_activation = self.outbox.iter().any(|candidate| {
                        matches!(candidate, StoredOutbound::Ack { payload: ack, .. }
                            if ack.activates_revision == Some(payload.credential_revision)
                                && ack.command_id == payload.command_id)
                    });
                    if has_activation == (self.reconnect_revision.is_some())
                        || self
                            .reconnect_revision
                            .is_some_and(|revision| revision != payload.credential_revision)
                    {
                        return Err(StoreError::InvalidState);
                    }
                }
                StoredOutbound::ReportReady { .. } if self.reconnect_revision.is_some() => {
                    return Err(StoreError::InvalidState);
                }
                _ => {}
            }
        }
        if self.reconnect_revision.is_some() && reports != 1 {
            return Err(StoreError::InvalidState);
        }
        if let Some(revision) = self.reconnect_revision
            && revision != self.current.credential_revision
        {
            return Err(StoreError::InvalidState);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.verify(&self.current_identity()?)
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
    pub fn current_artifact_digest(&self) -> &str {
        &self.current.artifact_digest
    }
    pub fn current_credential_generation(&self) -> u64 {
        self.identity.credential_generation
    }
    pub fn current_identity(&self) -> Result<DeviceIdentity, StoreError> {
        let generation = CredentialGeneration::try_from(self.identity.credential_generation)
            .map_err(|_| StoreError::InvalidState)?;
        DeviceIdentity::try_new(self.identity.tenant_id, self.identity.device_id, generation)
            .map_err(|_| StoreError::InvalidState)
    }
    pub fn reconnect_revision(&self) -> Option<u64> {
        self.reconnect_revision
    }
    pub fn rotation_in_flight(&self) -> bool {
        self.outbox
            .iter()
            .any(|entry| entry.report_payload().is_some())
    }
    pub fn pending_inbound(&self) -> Option<(&str, &str, u64, &str, bool)> {
        self.pending_inbound.as_ref().map(|pending| {
            (
                pending.topic.as_str(),
                pending.command_id.as_str(),
                pending.credential_generation,
                pending.settlement_token.as_str(),
                pending.settled,
            )
        })
    }
    pub fn pending_settlement_token(&self, command_id: &str, fingerprint: &str) -> Option<&str> {
        self.pending_inbound.as_ref().and_then(|pending| {
            (pending.command_id == command_id && pending.fingerprint == fingerprint)
                .then_some(pending.settlement_token.as_str())
        })
    }
    pub fn command_match(
        &self,
        command_id: &str,
        fingerprint: &str,
        now_epoch_seconds: u64,
    ) -> Option<bool> {
        self.command_journal
            .iter()
            .find(|command| {
                command.command_id == command_id
                    && command.retain_until_epoch_seconds > now_epoch_seconds
            })
            .map(|command| command.fingerprint == fingerprint)
    }

    pub fn expire_command_journal(&mut self, now_epoch_seconds: u64) {
        let pending_command = self
            .pending_inbound
            .as_ref()
            .map(|pending| pending.command_id.as_str());
        self.command_journal.retain(|command| {
            command.retain_until_epoch_seconds > now_epoch_seconds
                || pending_command == Some(command.command_id.as_str())
        });
    }

    pub fn reserve_command_journal(&self) -> Result<(), StoreError> {
        (self.command_journal.len() < COMMAND_JOURNAL_LIMIT)
            .then_some(())
            .ok_or(StoreError::CommandJournalFull)
    }

    pub fn command_journal_has_capacity(&self, now_epoch_seconds: u64) -> bool {
        self.command_journal.len() < COMMAND_JOURNAL_LIMIT
            || self.command_journal.iter().any(|command| {
                command.retain_until_epoch_seconds <= now_epoch_seconds
                    && self
                        .pending_inbound
                        .as_ref()
                        .is_none_or(|pending| pending.command_id != command.command_id)
            })
    }

    pub fn reserve_outbox(&self, count: usize) -> Result<(), StoreError> {
        (self.outbox.len().saturating_add(count) <= OUTBOX_LIMIT)
            .then_some(())
            .ok_or(StoreError::OutboxFull)
    }

    pub fn accept(&mut self, command: AcceptedCommand) -> Result<(), StoreError> {
        let AcceptedCommand {
            command_id,
            fingerprint,
            generation,
            fence,
            credential_generation,
            revision,
            artifact_digest,
            expires_at,
            observed_at,
            retain_until_epoch_seconds,
        } = command;
        let previous_identity = self.current_identity()?;
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
        let acknowledgement = StoredAck {
            command_id: command_id.clone(),
            event_cause: command_id.clone(),
            desired_generation: generation,
            fence_epoch: fence,
            device_sequence: ack_sequence,
            observed_at,
            rejection: None,
            activates_revision: Some(revision),
            settled_replay: false,
        };
        let pending_fingerprint = fingerprint.clone();
        self.command_journal.push(StoredCommand {
            command_id: command_id.clone(),
            fingerprint,
            acknowledgement: acknowledgement.clone(),
            retain_until_epoch_seconds,
        });
        let pending_topic = TopicSet::new(&previous_identity).command().to_owned();
        self.pending_inbound = Some(StoredInboundSettlement {
            settlement_token: settlement_token(&pending_topic, &command_id, &pending_fingerprint),
            topic: pending_topic,
            command_id: command_id.clone(),
            fingerprint: pending_fingerprint,
            credential_generation: previous_identity.credential_generation().get(),
            settled: false,
        });
        self.outbox.push(StoredOutbound::Ack {
            event_id: ack_event,
            payload: acknowledgement,
        });
        self.outbox.push(StoredOutbound::ReportBlocked {
            event_id: report_event,
            payload: StoredReport {
                command_id,
                observed_generation: generation,
                fence_epoch: fence,
                device_sequence: report_sequence,
                observed_at,
                state_hash,
                artifact_digest,
                expires_at: Some(expires_at),
                credential_generation,
                credential_revision: revision,
            },
        });
        Ok(())
    }

    pub fn reject(&mut self, command: RejectedCommand) {
        let RejectedCommand {
            command_id,
            fingerprint,
            generation,
            fence,
            rejection,
            observed_at,
            retain_until_epoch_seconds,
        } = command;
        self.device_sequence = self.device_sequence.saturating_add(1);
        let acknowledgement = StoredAck {
            command_id: command_id.clone(),
            event_cause: command_id.clone(),
            desired_generation: generation,
            fence_epoch: fence,
            device_sequence: self.device_sequence,
            observed_at,
            rejection: Some(rejection.into()),
            activates_revision: None,
            settled_replay: false,
        };
        self.command_journal.push(StoredCommand {
            command_id: command_id.clone(),
            fingerprint,
            acknowledgement: acknowledgement.clone(),
            retain_until_epoch_seconds,
        });
        self.outbox.push(StoredOutbound::Ack {
            event_id: event_id("ack", &command_id),
            payload: acknowledgement,
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
                event_cause: event_source,
                desired_generation: generation,
                fence_epoch: fence,
                device_sequence: self.device_sequence,
                observed_at,
                rejection: Some(StoredRejection::MalformedCommand),
                activates_revision: None,
                settled_replay: false,
            },
        });
    }

    pub fn has_conflicting_replay(&self, command_id: &str, fingerprint: &str) -> bool {
        let mut event_source = command_id.to_owned();
        event_source.push('\0');
        event_source.push_str(fingerprint);
        let expected = event_id("rejected", &event_source);
        self.outbox.iter().any(|entry| entry.event_id() == expected)
    }

    pub fn has_command_ack(&self, command_id: &str) -> bool {
        self.outbox.iter().any(|entry| {
            matches!(entry, StoredOutbound::Ack { payload, .. } if payload.command_id == command_id)
        })
    }

    pub fn replay_command(
        &mut self,
        command_id: &str,
        fingerprint: &str,
    ) -> Result<(), StoreError> {
        let command = self
            .command_journal
            .iter()
            .find(|command| command.command_id == command_id && command.fingerprint == fingerprint)
            .cloned()
            .ok_or(StoreError::InvalidState)?;
        let mut acknowledgement = command.acknowledgement;
        if acknowledgement.rejection.is_none() {
            acknowledgement.activates_revision = None;
            acknowledgement.settled_replay = true;
        }
        self.outbox.push(StoredOutbound::Ack {
            event_id: event_id("ack", &command.command_id),
            payload: acknowledgement,
        });
        Ok(())
    }

    pub fn next_outbound(&self) -> Option<OutboundFact> {
        self.outbox.iter().find_map(|entry| {
            if matches!(entry, StoredOutbound::ReportReady { .. })
                && !self
                    .pending_inbound
                    .as_ref()
                    .is_some_and(|pending| pending.settled)
            {
                None
            } else {
                entry.ready_fact()
            }
        })
    }

    pub fn confirm_outbound(&mut self, event_id: &str) -> bool {
        let Some(index) = self
            .outbox
            .iter()
            .position(|item| item.event_id() == event_id)
        else {
            return false;
        };
        if matches!(self.outbox[index], StoredOutbound::ReportReady { .. })
            && !self
                .pending_inbound
                .as_ref()
                .is_some_and(|pending| pending.settled)
        {
            return false;
        }
        let confirmed = self.outbox.remove(index);
        if let StoredOutbound::Ack { payload, .. } = &confirmed
            && let Some(revision) = payload.activates_revision
            && self.outbox.iter().any(|item| {
                matches!(item, StoredOutbound::ReportBlocked { payload, .. }
                    if payload.credential_revision == revision)
            })
        {
            self.reconnect_revision = Some(revision);
        }
        if matches!(confirmed, StoredOutbound::ReportReady { .. }) {
            self.pending_inbound = None;
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

    pub fn mark_inbound_settled(&mut self, token: Option<&str>) -> bool {
        let Some(pending) = self.pending_inbound.as_mut() else {
            return false;
        };
        if let Some(token) = token
            && token != pending.settlement_token
        {
            return false;
        }
        pending.settled = true;
        true
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredInboundSettlement {
    topic: String,
    command_id: String,
    fingerprint: String,
    credential_generation: u64,
    settlement_token: String,
    settled: bool,
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
    acknowledgement: StoredAck,
    retain_until_epoch_seconds: u64,
}

impl StoredCommand {
    fn semantic_valid(&self) -> bool {
        self.command_id == self.acknowledgement.command_id
            && !self.command_id.is_empty()
            && Sha256Digest::try_from(self.fingerprint.clone()).is_ok()
            && self.acknowledgement.semantic_valid()
            && self.retain_until_epoch_seconds > 0
    }
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

    const fn sequence(&self) -> u64 {
        match self {
            Self::Ack { payload, .. } => payload.device_sequence,
            Self::ReportBlocked { payload, .. } | Self::ReportReady { payload, .. } => {
                payload.device_sequence
            }
        }
    }

    fn semantic_valid(&self) -> bool {
        let event_valid = match self {
            Self::Ack {
                event_id: actual,
                payload,
            } => {
                let kind = if payload.event_cause == payload.command_id {
                    "ack"
                } else {
                    "rejected"
                };
                *actual == event_id(kind, &payload.event_cause)
            }
            Self::ReportBlocked {
                event_id: actual,
                payload,
            }
            | Self::ReportReady {
                event_id: actual,
                payload,
            } => *actual == event_id("report", &payload.command_id),
        };
        event_valid
            && match self {
                Self::Ack { payload, .. } => payload.semantic_valid(),
                Self::ReportBlocked { payload, .. } | Self::ReportReady { payload, .. } => {
                    payload.semantic_valid()
                }
            }
    }

    const fn report_payload(&self) -> Option<&StoredReport> {
        match self {
            Self::ReportBlocked { payload, .. } | Self::ReportReady { payload, .. } => {
                Some(payload)
            }
            Self::Ack { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAck {
    command_id: String,
    event_cause: String,
    desired_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    observed_at: i64,
    rejection: Option<StoredRejection>,
    activates_revision: Option<u64>,
    settled_replay: bool,
}

impl StoredAck {
    fn semantic_valid(&self) -> bool {
        !self.command_id.is_empty()
            && !self.event_cause.is_empty()
            && self.desired_generation > 0
            && self.fence_epoch > 0
            && self.device_sequence > 0
            && self.observed_at >= 0
            && self.activates_revision.is_none_or(|revision| revision > 0)
            && matches!(
                (self.rejection, self.activates_revision, self.settled_replay),
                (Some(_), None, false) | (None, Some(_), false) | (None, None, true)
            )
    }
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
    command_id: String,
    observed_generation: u64,
    fence_epoch: u64,
    device_sequence: u64,
    observed_at: i64,
    state_hash: String,
    artifact_digest: String,
    expires_at: Option<i64>,
    credential_generation: u64,
    credential_revision: u64,
}

impl StoredReport {
    fn semantic_valid(&self) -> bool {
        !self.command_id.is_empty()
            && self.observed_generation > 0
            && self.fence_epoch > 0
            && self.device_sequence > 0
            && self.observed_at >= 0
            && self.expires_at.is_some_and(|expires_at| expires_at > 0)
            && self.credential_generation > 0
            && self.credential_revision > 0
            && Sha256Digest::try_from(self.artifact_digest.clone()).is_ok()
            && Sha256Digest::try_from(self.state_hash.clone()).is_ok()
    }
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

fn settlement_token(topic: &str, command_id: &str, fingerprint: &str) -> String {
    let mut source = topic.to_owned();
    source.push('\0');
    source.push_str(command_id);
    source.push('\0');
    source.push_str(fingerprint);
    event_id("settlement", &source)
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
