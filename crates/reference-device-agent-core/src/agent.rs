use std::num::NonZeroU32;
use std::path::PathBuf;

use rotation_model::{CredentialRevision, InstalledCredentialPosition};
use sha2::{Digest as _, Sha256};

use crate::RecoveryCommandScope;
use crate::catalog::{CatalogError, ResolvedArtifact};
use crate::material::{CredentialError, validate_credential};
use crate::state::{AcceptedCommand, RejectedCommand, StateStore, StateV1, next_revision};
use crate::{
    ApplyOutcome, ArtifactCatalog, CommandRejection, CredentialFiles, DeviceCommand,
    DeviceIdentity, OutboundFact, StoreError, TopicSet, compute_artifact_digest,
};

/// Required bootstrap configuration. There is no insecure or clean-session variant.
#[derive(Debug)]
pub struct AgentConfig {
    identity: DeviceIdentity,
    state_directory: PathBuf,
    catalog: ArtifactCatalog,
    initial_position: InstalledCredentialPosition,
    initial_credentials: CredentialFiles,
    command_retention_seconds: NonZeroU32,
}

impl AgentConfig {
    #[must_use]
    pub fn new(
        identity: DeviceIdentity,
        state_directory: impl Into<PathBuf>,
        catalog: ArtifactCatalog,
        initial_position: InstalledCredentialPosition,
        initial_credentials: CredentialFiles,
        command_retention_seconds: NonZeroU32,
    ) -> Self {
        Self {
            identity,
            state_directory: state_directory.into(),
            catalog,
            initial_position,
            initial_credentials,
            command_retention_seconds,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error("initial credential artifact is unavailable")]
    InitialArtifactUnavailable,
    #[error("outbound event does not exist or is not publishable")]
    UnknownOutbound,
    #[error("reconnect does not match the committed credential revision")]
    UnexpectedReconnect,
    #[error("MQTT delivery is outside the current or pending settlement scope")]
    UnexpectedDelivery,
    #[error("credential rotation is in flight; command intake is backpressured")]
    RotationInFlight,
}

/// Product-specific device state machine and durable credential store.
pub struct ReferenceDeviceAgent {
    store: StateStore,
    state: StateV1,
    catalog: ArtifactCatalog,
    command_retention_seconds: NonZeroU32,
}

impl std::fmt::Debug for ReferenceDeviceAgent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReferenceDeviceAgent(<durable>)")
    }
}

impl ReferenceDeviceAgent {
    /// Opens strict version-1 state or initializes it from the validated bootstrap credential.
    ///
    /// # Errors
    ///
    /// Returns an error when state or credential material is unavailable, invalid, or inconsistent.
    pub fn open(config: AgentConfig, now_epoch_seconds: u64) -> Result<Self, AgentError> {
        let state_path = config.state_directory.join("state.v1.json");
        let (store, state) = if state_path.exists() {
            let (store, state) = StateStore::load(&config.state_directory, &config.identity)?;
            let current_identity = state.current_identity()?;
            let current_files = store.credential_files(state.current_revision());
            validate_credential(&current_files, &current_identity, now_epoch_seconds)?;
            let digest = compute_artifact_digest(&current_files)
                .map_err(|_| AgentError::InitialArtifactUnavailable)?;
            if digest.expose() != state.current_artifact_digest() {
                return Err(AgentError::Store(StoreError::InvalidState));
            }
            (store, state)
        } else {
            let initial = validate_credential(
                &config.initial_credentials,
                &config.identity,
                now_epoch_seconds,
            )?;
            let digest = compute_artifact_digest(&config.initial_credentials)
                .map_err(|_| AgentError::InitialArtifactUnavailable)?;
            StateStore::open_or_initialize(
                &config.state_directory,
                &config.identity,
                config.initial_position,
                &initial,
                &digest,
            )?
        };
        Ok(Self {
            store,
            state,
            catalog: config.catalog,
            command_retention_seconds: config.command_retention_seconds,
        })
    }

    /// Applies one authenticated canonical command and durably records its resulting facts.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be reserved or persisted.
    pub fn apply_command(
        &mut self,
        topic: &str,
        command: &DeviceCommand,
        now_epoch_seconds: u64,
    ) -> Result<ApplyOutcome, AgentError> {
        let observed_at = i64::try_from(now_epoch_seconds).unwrap_or(i64::MAX);
        let fingerprint = command_fingerprint(command);
        if let Some(same_payload) = self.state.command_match(
            command.command_id().expose(),
            &fingerprint,
            now_epoch_seconds,
        ) {
            if same_payload {
                if !self.state.has_command_ack(command.command_id().expose()) {
                    let mut candidate = self.state.clone();
                    candidate.reserve_outbox(1)?;
                    candidate.replay_command(command.command_id().expose(), &fingerprint)?;
                    self.persist_candidate(candidate)?;
                }
                return Ok(ApplyOutcome::Duplicate);
            }
            if self
                .state
                .has_conflicting_replay(command.command_id().expose(), &fingerprint)
            {
                return Ok(ApplyOutcome::Rejected(CommandRejection::MalformedCommand));
            }
            let mut candidate = self.state.clone();
            candidate.reserve_outbox(1)?;
            candidate.reject_conflicting_replay(
                command.command_id().expose().to_owned(),
                &fingerprint,
                command.desired_generation().get(),
                command.fence_epoch().get(),
                observed_at,
            );
            self.persist_candidate(candidate)?;
            return Ok(ApplyOutcome::Rejected(CommandRejection::MalformedCommand));
        }
        if self.rotation_in_flight() {
            return Err(AgentError::RotationInFlight);
        }
        if !TopicSet::new(&self.current_identity()?).accepts_command(topic)
            || command.device_id() != self.current_identity()?.device()
        {
            return self.persist_rejection(
                command,
                fingerprint,
                CommandRejection::MalformedCommand,
                observed_at,
            );
        }
        if command.deadline_epoch_seconds().get() <= now_epoch_seconds {
            return self.persist_rejection(
                command,
                fingerprint,
                CommandRejection::PolicyRejected,
                observed_at,
            );
        }
        let artifact =
            match self
                .catalog
                .resolve(&self.current_identity()?, command, now_epoch_seconds)
            {
                Ok(artifact) => artifact,
                Err(error) => {
                    let rejection = catalog_rejection(&error);
                    return self.persist_rejection(command, fingerprint, rejection, observed_at);
                }
            };
        if command.fence_epoch().get() < self.state.current_fence() {
            return self.persist_rejection(
                command,
                fingerprint,
                CommandRejection::FenceEpochStale,
                observed_at,
            );
        }
        let generation = command.desired_generation().get();
        if generation < self.state.current_generation() {
            return self.persist_rejection(
                command,
                fingerprint,
                CommandRejection::GenerationStale,
                observed_at,
            );
        }
        if generation == self.state.current_generation()
            || artifact.credential_generation.get() <= self.state.current_credential_generation()
        {
            return self.persist_rejection(
                command,
                fingerprint,
                CommandRejection::MalformedCommand,
                observed_at,
            );
        }
        self.commit(command, fingerprint, &artifact, observed_at)
    }

    /// Durably classifies one broker-authenticated but undecodable command before PUBACK.
    ///
    /// # Errors
    ///
    /// Returns an error when the delivery scope is invalid or its terminal ACK cannot be persisted.
    pub fn reject_malformed_delivery(
        &mut self,
        topic: &str,
        command_id: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<ApplyOutcome, AgentError> {
        if !TopicSet::new(&self.current_identity()?).accepts_command(topic)
            && self.pending_command_topic() != Some(topic)
        {
            return Err(AgentError::UnexpectedDelivery);
        }
        let fingerprint = malformed_fingerprint(topic, command_id, payload);
        if let Some(same_payload) =
            self.state
                .command_match(command_id, &fingerprint, now_epoch_seconds)
        {
            if same_payload {
                if !self.state.has_command_ack(command_id) {
                    let mut candidate = self.state.clone();
                    candidate.reserve_outbox(1)?;
                    candidate.replay_command(command_id, &fingerprint)?;
                    self.persist_candidate(candidate)?;
                }
                return Ok(ApplyOutcome::Duplicate);
            }
            let mut candidate = self.state.clone();
            if !candidate.has_conflicting_replay(command_id, &fingerprint) {
                candidate.reserve_outbox(1)?;
                candidate.reject_conflicting_replay(
                    command_id.to_owned(),
                    &fingerprint,
                    self.state.current_generation(),
                    self.state.current_fence(),
                    i64::try_from(now_epoch_seconds).unwrap_or(i64::MAX),
                );
                self.persist_candidate(candidate)?;
            }
            return Ok(ApplyOutcome::Rejected(CommandRejection::MalformedCommand));
        }
        self.persist_raw_rejection(command_id, fingerprint, now_epoch_seconds)
    }

    #[must_use]
    pub fn next_outbound(&self) -> Option<OutboundFact> {
        self.state.next_outbound()
    }

    /// Records the broker `PUBACK` for one durable outbound fact.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown event or a persistence failure.
    pub fn confirm_outbound(&mut self, event_id: &str) -> Result<(), AgentError> {
        let mut candidate = self.state.clone();
        if !candidate.confirm_outbound(event_id) {
            return Err(AgentError::UnknownOutbound);
        }
        self.persist_candidate(candidate)?;
        Ok(())
    }

    /// Returns the committed revision that must establish the next MQTT session.
    ///
    /// # Errors
    ///
    /// Returns an error if durable state contains an invalid revision.
    pub fn reconnect_revision(&self) -> Result<Option<CredentialRevision>, AgentError> {
        self.state
            .reconnect_revision()
            .map(CredentialRevision::try_from)
            .transpose()
            .map_err(|_| AgentError::Store(StoreError::InvalidState))
    }

    /// Reports whether an accepted rotation is waiting for ACK settlement or reconnect.
    #[must_use]
    pub fn rotation_in_flight(&self) -> bool {
        self.state.rotation_in_flight()
    }

    /// Whether a newly delivered command can reserve the worst-case durable state transition.
    #[must_use]
    pub fn command_intake_open(&self, now_epoch_seconds: u64) -> bool {
        self.state.reserve_outbox(2).is_ok()
            && self.state.command_journal_has_capacity(now_epoch_seconds)
    }

    /// Returns the exact old command scope that may be redelivered during recovery.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted identity is invalid.
    pub fn pending_command_scope(&self) -> Result<Option<RecoveryCommandScope>, AgentError> {
        let Some((topic, command_id, generation, _, _)) = self.state.pending_inbound() else {
            return Ok(None);
        };
        let current = self.current_identity()?;
        let generation = crate::CredentialGeneration::try_from(generation)
            .map_err(|_| AgentError::Store(StoreError::InvalidState))?;
        let identity = DeviceIdentity::try_new(current.tenant(), current.device(), generation)
            .map_err(|_| AgentError::Store(StoreError::InvalidState))?;
        Ok(Some(RecoveryCommandScope::new(
            identity,
            topic.to_owned(),
            command_id.to_owned(),
        )))
    }

    #[must_use]
    pub fn pending_command_topic(&self) -> Option<&str> {
        self.state
            .pending_inbound()
            .map(|(topic, _, _, _, _)| topic)
    }

    #[must_use]
    pub fn pending_command_id(&self) -> Option<&str> {
        self.state
            .pending_inbound()
            .map(|(_, command_id, _, _, _)| command_id)
    }

    #[must_use]
    pub fn pending_inbound_settled(&self) -> bool {
        self.state
            .pending_inbound()
            .is_none_or(|(_, _, _, _, settled)| settled)
    }

    #[must_use]
    pub fn pending_settlement_token(&self, command: &DeviceCommand) -> Option<&str> {
        let fingerprint = command_fingerprint(command);
        self.state
            .pending_settlement_token(command.command_id().expose(), &fingerprint)
    }

    /// Returns the settlement token for the exact durable recovery delivery.
    #[must_use]
    pub fn pending_delivery_settlement_token(&self, topic: &str, command_id: &str) -> Option<&str> {
        self.state
            .pending_inbound()
            .and_then(|(pending_topic, pending_command, _, token, _)| {
                (pending_topic == topic && pending_command == command_id).then_some(token)
            })
    }

    /// Persists the exact outgoing PUBACK fact for the pending old delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when the token does not identify the durable pending delivery or state
    /// persistence fails.
    pub fn mark_pending_inbound_settled(&mut self, token: &str) -> Result<(), AgentError> {
        self.persist_inbound_settlement(Some(token))
    }

    /// Persists that the recovery unsubscribe barrier completed without a redelivery.
    ///
    /// # Errors
    ///
    /// Returns an error when no delivery is pending or state persistence fails.
    pub fn mark_pending_inbound_absent(&mut self) -> Result<(), AgentError> {
        self.persist_inbound_settlement(None)
    }

    /// Selects the exact identity permitted to decode a current or recovery delivery.
    ///
    /// # Errors
    ///
    /// Returns an error unless the topic and command identify the current scope or the single
    /// durable delivery awaiting broker settlement.
    pub fn delivery_identity(
        &self,
        topic: &str,
        command_id: &str,
    ) -> Result<DeviceIdentity, AgentError> {
        let current = self.current_identity()?;
        if TopicSet::new(&current).accepts_command(topic) {
            return Ok(current);
        }
        let Some((pending_topic, pending_command, generation, _, _)) = self.state.pending_inbound()
        else {
            return Err(AgentError::UnexpectedDelivery);
        };
        if pending_topic != topic || pending_command != command_id {
            return Err(AgentError::UnexpectedDelivery);
        }
        let generation = crate::CredentialGeneration::try_from(generation)
            .map_err(|_| AgentError::Store(StoreError::InvalidState))?;
        DeviceIdentity::try_new(current.tenant(), current.device(), generation)
            .map_err(|_| AgentError::Store(StoreError::InvalidState))
    }

    /// Records that the committed credential revision established its MQTT session.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is not awaiting reconnect or persistence fails.
    pub fn mark_current_credential_connected(
        &mut self,
        revision: CredentialRevision,
    ) -> Result<(), AgentError> {
        let mut candidate = self.state.clone();
        if !candidate.mark_reconnected(revision.get()) {
            return Err(AgentError::UnexpectedReconnect);
        }
        self.persist_candidate(candidate)?;
        Ok(())
    }

    /// Returns the current installed device identity.
    ///
    /// # Errors
    ///
    /// Returns an error if persisted identity coordinates violate version-1 invariants.
    pub fn current_identity(&self) -> Result<DeviceIdentity, AgentError> {
        self.state.current_identity().map_err(Into::into)
    }

    #[must_use]
    pub fn current_credentials(&self) -> CredentialFiles {
        self.store.credential_files(self.state.current_revision())
    }

    fn commit(
        &mut self,
        command: &DeviceCommand,
        fingerprint: String,
        artifact: &ResolvedArtifact,
        observed_at: i64,
    ) -> Result<ApplyOutcome, AgentError> {
        let mut candidate = self.state.clone();
        candidate.expire_command_journal(u64::try_from(observed_at).unwrap_or(u64::MAX));
        candidate.reserve_outbox(2)?;
        candidate.reserve_command_journal()?;
        let revision = next_revision(&candidate)?;
        self.store
            .install_revision(revision, &artifact.credential)?;
        candidate.accept(AcceptedCommand {
            command_id: command.command_id().expose().to_owned(),
            fingerprint,
            generation: command.desired_generation().get(),
            fence: command.fence_epoch().get(),
            credential_generation: artifact.credential_generation.get(),
            revision: revision.get(),
            artifact_digest: artifact.digest.expose().to_owned(),
            expires_at: artifact.credential.expires_at,
            observed_at,
            retain_until_epoch_seconds: self.retention_deadline(observed_at),
        })?;
        self.persist_candidate(candidate)?;
        Ok(ApplyOutcome::Accepted)
    }

    fn persist_rejection(
        &mut self,
        command: &DeviceCommand,
        fingerprint: String,
        rejection: CommandRejection,
        observed_at: i64,
    ) -> Result<ApplyOutcome, AgentError> {
        let mut candidate = self.state.clone();
        candidate.expire_command_journal(u64::try_from(observed_at).unwrap_or(u64::MAX));
        candidate.reserve_outbox(1)?;
        candidate.reserve_command_journal()?;
        candidate.reject(RejectedCommand {
            command_id: command.command_id().expose().to_owned(),
            fingerprint,
            generation: command.desired_generation().get(),
            fence: command.fence_epoch().get(),
            rejection,
            observed_at,
            retain_until_epoch_seconds: self.retention_deadline(observed_at),
        });
        self.persist_candidate(candidate)?;
        Ok(ApplyOutcome::Rejected(rejection))
    }

    fn persist_candidate(&mut self, candidate: StateV1) -> Result<(), AgentError> {
        candidate.validate()?;
        self.store.persist(&candidate)?;
        self.state = candidate;
        Ok(())
    }

    fn persist_inbound_settlement(&mut self, token: Option<&str>) -> Result<(), AgentError> {
        let mut candidate = self.state.clone();
        if !candidate.mark_inbound_settled(token) {
            return Err(AgentError::UnexpectedDelivery);
        }
        self.persist_candidate(candidate)
    }

    fn persist_raw_rejection(
        &mut self,
        command_id: &str,
        fingerprint: String,
        now_epoch_seconds: u64,
    ) -> Result<ApplyOutcome, AgentError> {
        let observed_at = i64::try_from(now_epoch_seconds).unwrap_or(i64::MAX);
        let mut candidate = self.state.clone();
        candidate.expire_command_journal(now_epoch_seconds);
        candidate.reserve_outbox(1)?;
        candidate.reserve_command_journal()?;
        candidate.reject(RejectedCommand {
            command_id: command_id.to_owned(),
            fingerprint,
            generation: self.state.current_generation(),
            fence: self.state.current_fence(),
            rejection: CommandRejection::MalformedCommand,
            observed_at,
            retain_until_epoch_seconds: self.retention_deadline(observed_at),
        });
        self.persist_candidate(candidate)?;
        Ok(ApplyOutcome::Rejected(CommandRejection::MalformedCommand))
    }

    fn retention_deadline(&self, observed_at: i64) -> u64 {
        u64::try_from(observed_at)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(self.command_retention_seconds.get()))
    }
}

fn command_fingerprint(command: &DeviceCommand) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rss.reference-device-agent.command.v1\0");
    for value in [
        command.command_id().expose(),
        command.artifact_id().expose(),
        command.artifact_digest().expose(),
        command.intent_digest().expose(),
        command.policy_hash().expose(),
    ] {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    hasher.update(command.device_id().as_bytes());
    hasher.update(command.authorization_receipt_id().as_bytes());
    for value in [
        command.deadline_epoch_seconds().get(),
        command.desired_generation().get(),
        command.fence_epoch().get(),
    ] {
        hasher.update(value.to_be_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn malformed_fingerprint(topic: &str, command_id: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rss.reference-device-agent.malformed-command.v1\0");
    hasher.update(topic.as_bytes());
    hasher.update([0]);
    hasher.update(command_id.as_bytes());
    hasher.update([0]);
    hasher.update(Sha256::digest(payload));
    format!("sha256:{:x}", hasher.finalize())
}

fn catalog_rejection(error: &CatalogError) -> CommandRejection {
    match error {
        CatalogError::NotFound | CatalogError::Unavailable => CommandRejection::ArtifactUnavailable,
        CatalogError::DigestMismatch => CommandRejection::ArtifactDigestMismatch,
        CatalogError::BindingMismatch
        | CatalogError::Revoked
        | CatalogError::Credential(
            CredentialError::Untrusted | CredentialError::IdentityMismatch,
        ) => CommandRejection::PolicyRejected,
        CatalogError::Malformed => CommandRejection::MalformedCommand,
        CatalogError::Credential(
            CredentialError::Unavailable
            | CredentialError::Malformed
            | CredentialError::InsecurePrivateKey,
        ) => CommandRejection::DeviceFailure,
    }
}
