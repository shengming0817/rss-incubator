use std::path::PathBuf;

use rotation_model::{CredentialRevision, InstalledCredentialPosition};
use sha2::{Digest as _, Sha256};

use crate::catalog::{CatalogError, ResolvedArtifact};
use crate::material::{CredentialError, validate_credential};
use crate::state::{StateStore, StateV1, next_revision};
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
}

impl AgentConfig {
    #[must_use]
    pub fn new(
        identity: DeviceIdentity,
        state_directory: impl Into<PathBuf>,
        catalog: ArtifactCatalog,
        initial_position: InstalledCredentialPosition,
        initial_credentials: CredentialFiles,
    ) -> Self {
        Self {
            identity,
            state_directory: state_directory.into(),
            catalog,
            initial_position,
            initial_credentials,
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
}

/// Product-specific device state machine and durable credential store.
pub struct ReferenceDeviceAgent {
    store: StateStore,
    state: StateV1,
    catalog: ArtifactCatalog,
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
        if let Some(same_payload) = self
            .state
            .last_command()
            .and_then(|last| last.matches(command.command_id().expose(), &fingerprint))
        {
            if same_payload {
                if !self.state.has_command_ack(command.command_id().expose()) {
                    let mut candidate = self.state.clone();
                    candidate.reserve_outbox(1)?;
                    candidate.replay_last()?;
                    self.persist_candidate(candidate)?;
                }
                return Ok(ApplyOutcome::Duplicate);
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
        candidate.reserve_outbox(2)?;
        let revision = next_revision(&candidate)?;
        self.store
            .install_revision(revision, &artifact.credential)?;
        candidate.accept(
            command.command_id().expose(),
            fingerprint,
            command.desired_generation().get(),
            command.fence_epoch().get(),
            artifact.credential_generation.get(),
            revision.get(),
            artifact.digest.expose().to_owned(),
            artifact.credential.expires_at,
            observed_at,
        );
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
        candidate.reserve_outbox(1)?;
        candidate.reject(
            command.command_id().expose(),
            fingerprint,
            command.desired_generation().get(),
            command.fence_epoch().get(),
            rejection,
            observed_at,
        );
        self.persist_candidate(candidate)?;
        Ok(ApplyOutcome::Rejected(rejection))
    }

    fn persist_candidate(&mut self, candidate: StateV1) -> Result<(), AgentError> {
        self.store.persist(&candidate)?;
        self.state = candidate;
        Ok(())
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
