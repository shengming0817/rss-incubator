#![doc = "Transport-neutral product model for secure device credential rotation."]

use std::fmt;
use std::num::NonZeroU64;

/// Validation failure for a product-owned rotation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationModelError {
    /// An opaque reference was empty or contained only whitespace.
    EmptyReference { kind: &'static str },
    /// An opaque reference contained a control character.
    ControlCharacter { kind: &'static str },
    /// A generation must be greater than zero.
    ZeroGeneration,
    /// A fence epoch must be greater than zero.
    ZeroFenceEpoch,
    /// A device-local credential revision must be greater than zero.
    ZeroCredentialRevision,
    /// A policy duration or collection violates the closed product constraints.
    InvalidPolicy,
}

impl fmt::Display for RotationModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReference { kind } => write!(formatter, "{kind} must not be empty"),
            Self::ControlCharacter { kind } => {
                write!(formatter, "{kind} must not contain control characters")
            }
            Self::ZeroGeneration => formatter.write_str("generation must be greater than zero"),
            Self::ZeroFenceEpoch => formatter.write_str("fence epoch must be greater than zero"),
            Self::ZeroCredentialRevision => {
                formatter.write_str("credential revision must be greater than zero")
            }
            Self::InvalidPolicy => {
                formatter.write_str("rotation policy violates product constraints")
            }
        }
    }
}

impl std::error::Error for RotationModelError {}

macro_rules! opaque_reference {
    ($name:ident, $kind:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Explicitly exposes the value to a controlled mapping or serialization boundary.
            #[must_use]
            pub fn expose(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = RotationModelError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                validate_reference(value, $kind)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = RotationModelError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_reference(&value, $kind)?;
                Ok(Self(value))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_reference!(
    RotationId,
    "rotation_id",
    "Product-owned correlation ID for one rotation request."
);
opaque_reference!(
    RequestId,
    "request_id",
    "Opaque request correlation returned by the public API."
);
opaque_reference!(
    CorrelationId,
    "correlation_id",
    "Opaque correlation identifier for one CLI operation."
);
opaque_reference!(
    TenantRef,
    "tenant_ref",
    "Opaque tenant reference that does not establish a verified tenant."
);
opaque_reference!(
    DeviceRef,
    "device_ref",
    "Opaque device reference that does not establish device identity."
);
opaque_reference!(
    PrincipalRef,
    "principal_ref",
    "Opaque requester reference that does not establish authentication."
);
opaque_reference!(
    AuthorizationReceiptRef,
    "authorization_receipt_ref",
    "Authority-free correlation reference for one durable authorization decision."
);
opaque_reference!(
    CommandRef,
    "command_ref",
    "Opaque reference to a device command issued outside this model."
);
opaque_reference!(
    EventRef,
    "event_ref",
    "Opaque identity of an event envelope observed outside this model."
);
opaque_reference!(
    IngressEnvelopeRef,
    "ingress_envelope_ref",
    "Opaque correlation reference for a receipted inbound envelope."
);
opaque_reference!(
    StateHash,
    "state_hash",
    "Opaque state hash observed through the public contract boundary."
);
opaque_reference!(
    ArtifactDigest,
    "artifact_digest",
    "Opaque non-secret artifact digest observed through the public contract boundary."
);

fn validate_reference(value: &str, kind: &'static str) -> Result<(), RotationModelError> {
    if value.trim().is_empty() {
        return Err(RotationModelError::EmptyReference { kind });
    }
    if value.chars().any(char::is_control) {
        return Err(RotationModelError::ControlCharacter { kind });
    }
    Ok(())
}

/// Closed certificate key usage vocabulary accepted by the rotation product.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyUsage {
    ClientAuth,
    ServerAuth,
}

impl KeyUsage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientAuth => "clientAuth",
            Self::ServerAuth => "serverAuth",
        }
    }
}

/// Validated, transport-neutral certificate rotation policy.
#[derive(Clone, Eq, PartialEq)]
pub struct RotationPolicy {
    key_usages: Vec<KeyUsage>,
    renew_before_seconds: u64,
    sans: Vec<String>,
    validity_seconds: u64,
}

impl fmt::Debug for RotationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationPolicy")
            .field("key_usages", &self.key_usages)
            .field("renew_before_seconds", &self.renew_before_seconds)
            .field("sans", &format_args!("[REDACTED; {}]", self.sans.len()))
            .field("validity_seconds", &self.validity_seconds)
            .finish()
    }
}

impl RotationPolicy {
    /// Creates a policy only when it obeys the public contract's closed constraints.
    ///
    /// # Errors
    ///
    /// Returns [`RotationModelError::InvalidPolicy`] when a duration, usage, or SAN violates the
    /// closed product constraints.
    pub fn try_new(
        key_usages: Vec<KeyUsage>,
        renew_before_seconds: u64,
        sans: Vec<String>,
        validity_seconds: u64,
    ) -> Result<Self, RotationModelError> {
        let unique_usages = key_usages.iter().collect::<std::collections::BTreeSet<_>>();
        let unique_sans = sans.iter().collect::<std::collections::BTreeSet<_>>();
        if key_usages.is_empty()
            || unique_usages.len() != key_usages.len()
            || !(300..=31_536_000).contains(&validity_seconds)
            || !(60..validity_seconds).contains(&renew_before_seconds)
            || sans.len() > 32
            || unique_sans.len() != sans.len()
            || sans.iter().any(|san| {
                san.is_empty() || san.chars().count() > 253 || san.chars().any(char::is_control)
            })
        {
            return Err(RotationModelError::InvalidPolicy);
        }
        Ok(Self {
            key_usages,
            renew_before_seconds,
            sans,
            validity_seconds,
        })
    }

    #[must_use]
    pub fn key_usages(&self) -> &[KeyUsage] {
        &self.key_usages
    }
    #[must_use]
    pub const fn renew_before_seconds(&self) -> u64 {
        self.renew_before_seconds
    }
    #[must_use]
    pub fn sans(&self) -> &[String] {
        &self.sans
    }
    #[must_use]
    pub const fn validity_seconds(&self) -> u64 {
        self.validity_seconds
    }
}

/// Correlation emitted for one control operation; it does not grant authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationCorrelation {
    request_id: RequestId,
    correlation_id: CorrelationId,
}

impl OperationCorrelation {
    #[must_use]
    pub const fn new(request_id: RequestId, correlation_id: CorrelationId) -> Self {
        Self {
            request_id,
            correlation_id,
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }
}

/// Positive generation observed at the public product boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// Returns the positive generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for Generation {
    type Error = RotationModelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RotationModelError::ZeroGeneration)
    }
}

/// Positive device-local fence epoch; it does not grant server authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FenceEpoch(NonZeroU64);

impl FenceEpoch {
    /// Returns the positive fence epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for FenceEpoch {
    type Error = RotationModelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RotationModelError::ZeroFenceEpoch)
    }
}

/// Positive device-local credential revision.
///
/// This is deliberately distinct from desired generation and MQTT credential generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialRevision(NonZeroU64);

impl CredentialRevision {
    /// Returns the positive local revision value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for CredentialRevision {
    type Error = RotationModelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RotationModelError::ZeroCredentialRevision)
    }
}

/// The three monotonic coordinates committed with an installed credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledCredentialPosition {
    desired_generation: Generation,
    fence_epoch: FenceEpoch,
    credential_revision: CredentialRevision,
}

impl InstalledCredentialPosition {
    /// Creates a committed device-local credential position.
    #[must_use]
    pub const fn new(
        desired_generation: Generation,
        fence_epoch: FenceEpoch,
        credential_revision: CredentialRevision,
    ) -> Self {
        Self {
            desired_generation,
            fence_epoch,
            credential_revision,
        }
    }

    /// Returns the authoritative desired generation observed by this device.
    #[must_use]
    pub const fn desired_generation(self) -> Generation {
        self.desired_generation
    }

    /// Returns the committed fence epoch.
    #[must_use]
    pub const fn fence_epoch(self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Returns the independent local credential revision.
    #[must_use]
    pub const fn credential_revision(self) -> CredentialRevision {
        self.credential_revision
    }
}

/// Monotonic device sequence from an ACK or reported observation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceSequence(u64);

impl DeviceSequence {
    /// Creates a sequence value. Zero is valid at the public contract boundary.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the sequence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Contract timestamp represented as signed Unix time without transport encoding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixTimestamp(i64);

impl UnixTimestamp {
    /// Creates a timestamp value.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the signed Unix timestamp.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Stable product coordinates shared by correlated rotation observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationCoordinates {
    rotation_id: RotationId,
    tenant: TenantRef,
    device: DeviceRef,
}

impl RotationCoordinates {
    /// Creates product coordinates without asserting identity or authorization.
    #[must_use]
    pub const fn new(rotation_id: RotationId, tenant: TenantRef, device: DeviceRef) -> Self {
        Self {
            rotation_id,
            tenant,
            device,
        }
    }

    /// Returns the product-owned rotation correlation ID.
    #[must_use]
    pub const fn rotation_id(&self) -> &RotationId {
        &self.rotation_id
    }

    /// Returns the unverified tenant reference.
    #[must_use]
    pub const fn tenant(&self) -> &TenantRef {
        &self.tenant
    }

    /// Returns the unverified device reference.
    #[must_use]
    pub const fn device(&self) -> &DeviceRef {
        &self.device
    }
}

/// Product request intent before any authoritative acceptance is observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationIntent {
    coordinates: RotationCoordinates,
    requested_by: PrincipalRef,
}

impl RotationIntent {
    /// Creates an intent without performing authentication or authorization.
    #[must_use]
    pub const fn new(coordinates: RotationCoordinates, requested_by: PrincipalRef) -> Self {
        Self {
            coordinates,
            requested_by,
        }
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns the unverified requester reference.
    #[must_use]
    pub const fn requested_by(&self) -> &PrincipalRef {
        &self.requested_by
    }
}

/// Closed condition returned when desired policy is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceCondition {
    /// Upstream reconciliation is in progress.
    Reconciling,
    /// Upstream is waiting for the device.
    PendingDevice,
}

/// Product projection of the public policy acceptance response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationAccepted {
    coordinates: RotationCoordinates,
    authorization_receipt: AuthorizationReceiptRef,
    accepted_generation: Generation,
    condition: AcceptanceCondition,
}

impl RotationAccepted {
    /// Creates a shape-validated projection without establishing authenticated provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        authorization_receipt: AuthorizationReceiptRef,
        accepted_generation: Generation,
        condition: AcceptanceCondition,
    ) -> Self {
        Self {
            coordinates,
            authorization_receipt,
            accepted_generation,
            condition,
        }
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns correlation to the durable authorization decision.
    #[must_use]
    pub const fn authorization_receipt(&self) -> &AuthorizationReceiptRef {
        &self.authorization_receipt
    }

    /// Returns the accepted desired generation.
    #[must_use]
    pub const fn accepted_generation(&self) -> Generation {
        self.accepted_generation
    }

    /// Returns the upstream acceptance condition.
    #[must_use]
    pub const fn condition(&self) -> AcceptanceCondition {
        self.condition
    }
}

/// Rejection reasons preserved from the public command acknowledgement contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRejectionReason {
    /// The referenced artifact was unavailable.
    ArtifactUnavailable,
    /// The artifact digest did not match.
    ArtifactDigestMismatch,
    /// Device policy rejected the command.
    PolicyRejected,
    /// The desired generation was stale.
    GenerationStale,
    /// The fence epoch was stale.
    FenceEpochStale,
    /// The command was malformed.
    MalformedCommand,
    /// The device failed while handling the command.
    DeviceFailure,
}

/// Closed result of a device command acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAcknowledgementOutcome {
    /// The device received the command.
    Received,
    /// The device rejected the command for the attached reason.
    Rejected(CommandRejectionReason),
}

/// Position fields carried by the command acknowledgement contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandAckPosition {
    desired_generation: Generation,
    fence_epoch: FenceEpoch,
    device_sequence: DeviceSequence,
    observed_at: UnixTimestamp,
}

impl CommandAckPosition {
    /// Creates the preserved ACK position without advancing authoritative state.
    #[must_use]
    pub const fn new(
        desired_generation: Generation,
        fence_epoch: FenceEpoch,
        device_sequence: DeviceSequence,
        observed_at: UnixTimestamp,
    ) -> Self {
        Self {
            desired_generation,
            fence_epoch,
            device_sequence,
            observed_at,
        }
    }
}

/// A command acknowledgement is not interchangeable with a report or receipt.
///
/// ```compile_fail
/// use rotation_model::{ApplicationReceiptObservation, CommandAcknowledgement};
///
/// fn requires_receipt(_: ApplicationReceiptObservation) {}
/// fn cannot_substitute(acknowledgement: CommandAcknowledgement) {
///     requires_receipt(acknowledgement);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAcknowledgement {
    coordinates: RotationCoordinates,
    event: EventRef,
    command: CommandRef,
    position: CommandAckPosition,
    outcome: CommandAcknowledgementOutcome,
}

impl CommandAcknowledgement {
    /// Creates an ACK projection without deriving readiness or trusted provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        event: EventRef,
        command: CommandRef,
        position: CommandAckPosition,
        outcome: CommandAcknowledgementOutcome,
    ) -> Self {
        Self {
            coordinates,
            event,
            command,
            position,
            outcome,
        }
    }

    /// Returns the independent ACK event-envelope identity.
    #[must_use]
    pub const fn event(&self) -> &EventRef {
        &self.event
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns the opaque command reference.
    #[must_use]
    pub const fn command(&self) -> &CommandRef {
        &self.command
    }

    /// Returns the desired generation carried by the ACK.
    #[must_use]
    pub const fn desired_generation(&self) -> Generation {
        self.position.desired_generation
    }

    /// Returns the fence epoch carried by the ACK.
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.position.fence_epoch
    }

    /// Returns the device sequence carried by the ACK.
    #[must_use]
    pub const fn device_sequence(&self) -> DeviceSequence {
        self.position.device_sequence
    }

    /// Returns the closed ACK outcome.
    #[must_use]
    pub const fn outcome(&self) -> CommandAcknowledgementOutcome {
        self.outcome
    }

    /// Returns the ACK observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixTimestamp {
        self.position.observed_at
    }
}

/// Position fields carried by the reported-state contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportPosition {
    observed_generation: Generation,
    fence_epoch: FenceEpoch,
    device_sequence: DeviceSequence,
    observed_at: UnixTimestamp,
}

impl ReportPosition {
    /// Creates a reported position without advancing authoritative state.
    #[must_use]
    pub const fn new(
        observed_generation: Generation,
        fence_epoch: FenceEpoch,
        device_sequence: DeviceSequence,
        observed_at: UnixTimestamp,
    ) -> Self {
        Self {
            observed_generation,
            fence_epoch,
            device_sequence,
            observed_at,
        }
    }
}

/// Product projection of a device credential report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReport {
    coordinates: RotationCoordinates,
    event: EventRef,
    position: ReportPosition,
    state_hash: StateHash,
    artifact_digest: ArtifactDigest,
    expires_at: Option<UnixTimestamp>,
}

impl CredentialReport {
    /// Creates a report projection without advancing authoritative state.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        event: EventRef,
        position: ReportPosition,
        state_hash: StateHash,
        artifact_digest: ArtifactDigest,
        expires_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            coordinates,
            event,
            position,
            state_hash,
            artifact_digest,
            expires_at,
        }
    }

    /// Returns the independent report event-envelope identity.
    #[must_use]
    pub const fn event(&self) -> &EventRef {
        &self.event
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns the observed generation.
    #[must_use]
    pub const fn observed_generation(&self) -> Generation {
        self.position.observed_generation
    }

    /// Returns the observed fence epoch.
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.position.fence_epoch
    }

    /// Returns the observed device sequence.
    #[must_use]
    pub const fn device_sequence(&self) -> DeviceSequence {
        self.position.device_sequence
    }

    /// Returns the opaque state hash.
    #[must_use]
    pub const fn state_hash(&self) -> &StateHash {
        &self.state_hash
    }

    /// Returns the opaque artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &ArtifactDigest {
        &self.artifact_digest
    }

    /// Returns the optional upstream expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixTimestamp> {
        self.expires_at
    }

    /// Returns the report observation time.
    #[must_use]
    pub const fn observed_at(&self) -> UnixTimestamp {
        self.position.observed_at
    }
}

/// Reasons paired with a stale application receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationStaleReason {
    /// The desired generation was stale.
    GenerationStale,
    /// The fence epoch was stale.
    FenceEpochStale,
    /// The device sequence was stale.
    DeviceSequenceStale,
}

/// Reasons paired with a rejected application receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationRejectionReason {
    /// Desired policy had not been accepted.
    NotAccepted,
    /// The inbound payload failed schema validation.
    SchemaRejected,
    /// The inbound payload violated the protocol.
    ProtocolViolation,
}

/// Authorization lineage required for an accepted application outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptLineage {
    authorization_receipt: AuthorizationReceiptRef,
    desired_generation: Generation,
}

impl ReceiptLineage {
    /// Creates lineage without treating the correlation reference as an authorization capability.
    #[must_use]
    pub const fn new(
        authorization_receipt: AuthorizationReceiptRef,
        desired_generation: Generation,
    ) -> Self {
        Self {
            authorization_receipt,
            desired_generation,
        }
    }

    /// Returns correlation to the durable authorization decision.
    #[must_use]
    pub const fn authorization_receipt(&self) -> &AuthorizationReceiptRef {
        &self.authorization_receipt
    }

    /// Returns the desired generation bound to the decision.
    #[must_use]
    pub const fn desired_generation(&self) -> Generation {
        self.desired_generation
    }
}

/// Closed application ingress outcome with only valid reason pairings.
///
/// A rejected outcome cannot carry accepted authorization lineage.
///
/// ```compile_fail
/// use rotation_model::{
///     ApplicationReceiptOutcome, ApplicationRejectionReason, ReceiptLineage,
/// };
///
/// fn rejected_cannot_carry_lineage(lineage: ReceiptLineage) {
///     let _ = ApplicationReceiptOutcome::Rejected(
///         lineage,
///         ApplicationRejectionReason::NotAccepted,
///     );
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationReceiptOutcome {
    /// The inbound observation was committed with accepted lineage.
    Committed(ReceiptLineage),
    /// The inbound observation was already committed with the same accepted lineage.
    Duplicate(ReceiptLineage),
    /// The inbound observation was stale for the attached reason and accepted lineage.
    Stale {
        lineage: ReceiptLineage,
        reason: ApplicationStaleReason,
    },
    /// The inbound observation was rejected before accepted lineage was available.
    Rejected(ApplicationRejectionReason),
}

/// Product projection of an application ingress receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationReceiptObservation {
    coordinates: RotationCoordinates,
    event: EventRef,
    ingress_envelope: IngressEnvelopeRef,
    outcome: ApplicationReceiptOutcome,
    committed_at: UnixTimestamp,
}

impl ApplicationReceiptObservation {
    /// Creates a receipt projection without deriving readiness or trusted provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        event: EventRef,
        ingress_envelope: IngressEnvelopeRef,
        outcome: ApplicationReceiptOutcome,
        committed_at: UnixTimestamp,
    ) -> Self {
        Self {
            coordinates,
            event,
            ingress_envelope,
            outcome,
            committed_at,
        }
    }

    /// Returns the independent receipt event-envelope identity.
    #[must_use]
    pub const fn event(&self) -> &EventRef {
        &self.event
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns correlation to the receipted inbound envelope.
    #[must_use]
    pub const fn ingress_envelope(&self) -> &IngressEnvelopeRef {
        &self.ingress_envelope
    }

    /// Returns the closed application outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ApplicationReceiptOutcome {
        &self.outcome
    }

    /// Returns the durable ingress commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UnixTimestamp {
        self.committed_at
    }
}
