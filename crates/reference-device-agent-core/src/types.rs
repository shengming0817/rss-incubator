use std::fmt;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use rotation_model::{FenceEpoch, Generation};

const COMMAND_CONTRACT: &str = "identity.commands.apply-device-certificate";
const ACK_CONTRACT: &str = "identity.device-command-acked";
const REPORT_CONTRACT: &str = "identity.device-certificate-reported";

/// Failure to construct a security-sensitive reference-agent value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValueError {
    #[error("value must be greater than zero")]
    Zero,
    #[error("artifact id is invalid")]
    InvalidArtifactId,
    #[error("MQTT client id is invalid")]
    InvalidClientId,
    #[error("MQTT host is invalid")]
    InvalidHost,
    #[error("MQTT port is invalid")]
    InvalidPort,
    #[error("command id is invalid")]
    InvalidCommandId,
    #[error("SHA-256 digest is invalid")]
    InvalidDigest,
}

/// Monotonic generation embedded in the authenticated MQTT credential scope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialGeneration(NonZeroU64);

impl CredentialGeneration {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for CredentialGeneration {
    type Error = ValueError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value).map(Self).ok_or(ValueError::Zero)
    }
}

/// Exact peer-authenticated device coordinates for one MQTT session.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceIdentity {
    tenant: Uuid,
    device: Uuid,
    credential_generation: CredentialGeneration,
}

impl DeviceIdentity {
    #[must_use]
    pub const fn new(
        tenant: Uuid,
        device: Uuid,
        credential_generation: CredentialGeneration,
    ) -> Self {
        Self {
            tenant,
            device,
            credential_generation,
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> Uuid {
        self.tenant
    }

    #[must_use]
    pub const fn device(&self) -> Uuid {
        self.device
    }

    #[must_use]
    pub const fn credential_generation(&self) -> CredentialGeneration {
        self.credential_generation
    }

    #[must_use]
    pub fn principal_urn(&self) -> String {
        format!(
            "urn:rss:mqtt-device:v1:{}:{}:{}",
            self.tenant.hyphenated(),
            self.device.hyphenated(),
            self.credential_generation.get()
        )
    }

    /// Stable persistent-session identity bound to tenant and device coordinates.
    #[must_use]
    pub fn mqtt_client_id(&self) -> String {
        format!("rss-reference-device-{}-{}", self.tenant, self.device)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceIdentity(<redacted>)")
    }
}

/// Canonical, exact topic set for one authenticated device session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicSet {
    command: String,
    command_acknowledged: String,
    certificate_reported: String,
}

impl TopicSet {
    #[must_use]
    pub fn new(identity: &DeviceIdentity) -> Self {
        let prefix = format!(
            "rss/v1/{}/{}/{}/",
            identity.tenant.hyphenated(),
            identity.device.hyphenated(),
            identity.credential_generation.get()
        );
        Self {
            command: format!("{prefix}downlink/{COMMAND_CONTRACT}"),
            command_acknowledged: format!("{prefix}uplink/{ACK_CONTRACT}"),
            certificate_reported: format!("{prefix}uplink/{REPORT_CONTRACT}"),
        }
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    #[must_use]
    pub fn command_acknowledged(&self) -> &str {
        &self.command_acknowledged
    }

    #[must_use]
    pub fn certificate_reported(&self) -> &str {
        &self.certificate_reported
    }

    #[must_use]
    pub fn accepts_command(&self, topic: &str) -> bool {
        topic == self.command
    }
}

/// Opaque catalog key. It can never be interpreted as a filesystem path.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactId(String);

impl ArtifactId {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ArtifactId {
    type Error = ValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valid_length = (16..=256).contains(&value.chars().count());
        let invalid_character = value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'));
        if !valid_length || invalid_character || value.contains("..") {
            return Err(ValueError::InvalidArtifactId);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for ArtifactId {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Debug for ArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactId(<redacted>)")
    }
}

/// Exact lowercase SHA-256 identifier used by the public command contract.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = ValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valid = value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        valid
            .then(|| Self(value.to_owned()))
            .ok_or(ValueError::InvalidDigest)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

/// Payload-external command envelope identity carried as MQTT correlation data.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommandId(String);

impl CommandId {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for CommandId {
    type Error = ValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valid =
            (1..=256).contains(&value.chars().count()) && !value.chars().any(char::is_control);
        valid
            .then(|| Self(value.to_owned()))
            .ok_or(ValueError::InvalidCommandId)
    }
}

impl TryFrom<String> for CommandId {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Debug for CommandId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandId(<redacted>)")
    }
}

/// Canonical command values after exact RSS DTO decoding and device correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCommand {
    command_id: CommandId,
    device_id: Uuid,
    artifact_id: ArtifactId,
    artifact_digest: Sha256Digest,
    authorization_receipt_id: Uuid,
    deadline_epoch_seconds: NonZeroU64,
    desired_generation: Generation,
    fence_epoch: FenceEpoch,
    intent_digest: Sha256Digest,
    policy_hash: Sha256Digest,
}

impl DeviceCommand {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        command_id: CommandId,
        device_id: Uuid,
        artifact_id: ArtifactId,
        artifact_digest: Sha256Digest,
        authorization_receipt_id: Uuid,
        deadline_epoch_seconds: NonZeroU64,
        desired_generation: Generation,
        fence_epoch: FenceEpoch,
        intent_digest: Sha256Digest,
        policy_hash: Sha256Digest,
    ) -> Self {
        Self {
            command_id,
            device_id,
            artifact_id,
            artifact_digest,
            authorization_receipt_id,
            deadline_epoch_seconds,
            desired_generation,
            fence_epoch,
            intent_digest,
            policy_hash,
        }
    }

    #[must_use]
    pub const fn command_id(&self) -> &CommandId {
        &self.command_id
    }
    #[must_use]
    pub const fn device_id(&self) -> Uuid {
        self.device_id
    }
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> Uuid {
        self.authorization_receipt_id
    }
    #[must_use]
    pub const fn deadline_epoch_seconds(&self) -> NonZeroU64 {
        self.deadline_epoch_seconds
    }
    #[must_use]
    pub const fn desired_generation(&self) -> Generation {
        self.desired_generation
    }
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }
    #[must_use]
    pub const fn intent_digest(&self) -> &Sha256Digest {
        &self.intent_digest
    }
    #[must_use]
    pub const fn policy_hash(&self) -> &Sha256Digest {
        &self.policy_hash
    }
}

/// Closed device rejection space mapped one-to-one to the public ACK contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRejection {
    ArtifactUnavailable,
    ArtifactDigestMismatch,
    PolicyRejected,
    GenerationStale,
    FenceEpochStale,
    MalformedCommand,
    DeviceFailure,
}

/// Durable command application result. Broker settlement is a separate operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Accepted,
    Duplicate,
    Rejected(CommandRejection),
}

/// ACK payload values for the canonical wire adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckFact {
    pub command_id: String,
    pub desired_generation: u64,
    pub fence_epoch: u64,
    pub device_sequence: u64,
    pub observed_at: i64,
    pub rejection: Option<CommandRejection>,
}

/// Report payload values for the canonical wire adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportFact {
    pub observed_generation: u64,
    pub fence_epoch: u64,
    pub device_sequence: u64,
    pub observed_at: i64,
    pub state_hash: String,
    pub artifact_digest: String,
    pub expires_at: Option<i64>,
}

/// A durable outbound fact. The stable event identity is MQTT correlation data, not payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundFact {
    CommandAcknowledged {
        event_id: String,
        payload: AckFact,
    },
    CertificateReported {
        event_id: String,
        payload: ReportFact,
    },
}

impl OutboundFact {
    #[must_use]
    pub fn event_id(&self) -> &str {
        match self {
            Self::CommandAcknowledged { event_id, .. }
            | Self::CertificateReported { event_id, .. } => event_id,
        }
    }
}

/// Concrete certificate material required for every MQTT connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialFiles {
    ca_certificate: PathBuf,
    certificate_chain: PathBuf,
    private_key: PathBuf,
}

impl CredentialFiles {
    #[must_use]
    pub fn new(
        ca_certificate: impl Into<PathBuf>,
        certificate_chain: impl Into<PathBuf>,
        private_key: impl Into<PathBuf>,
    ) -> Self {
        Self {
            ca_certificate: ca_certificate.into(),
            certificate_chain: certificate_chain.into(),
            private_key: private_key.into(),
        }
    }

    #[must_use]
    pub fn ca_certificate(&self) -> &Path {
        &self.ca_certificate
    }

    #[must_use]
    pub fn certificate_chain(&self) -> &Path {
        &self.certificate_chain
    }

    #[must_use]
    pub fn private_key(&self) -> &Path {
        &self.private_key
    }
}

/// Mandatory concrete MQTT v5 session configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MqttConnectionConfig {
    host: String,
    port: u16,
    client_id: String,
    session_expiry_seconds: NonZeroU32,
    request_capacity: NonZeroUsize,
}

impl MqttConnectionConfig {
    /// Constructs the mandatory persistent-session MQTT coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when host, client ID, or port is invalid.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        client_id: impl Into<String>,
        session_expiry_seconds: NonZeroU32,
        request_capacity: NonZeroUsize,
    ) -> Result<Self, ValueError> {
        let host = host.into();
        let client_id = client_id.into();
        if host.trim().is_empty() || host.chars().any(char::is_control) {
            return Err(ValueError::InvalidHost);
        }
        if port == 0 {
            return Err(ValueError::InvalidPort);
        }
        if client_id.is_empty() || client_id.chars().any(char::is_control) {
            return Err(ValueError::InvalidClientId);
        }
        Ok(Self {
            host,
            port,
            client_id,
            session_expiry_seconds,
            request_capacity,
        })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub const fn session_expiry_seconds(&self) -> NonZeroU32 {
        self.session_expiry_seconds
    }

    #[must_use]
    pub const fn request_capacity(&self) -> NonZeroUsize {
        self.request_capacity
    }
}
