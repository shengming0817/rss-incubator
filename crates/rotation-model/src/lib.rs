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
    CommandRef,
    "command_ref",
    "Opaque reference to a device command issued outside this model."
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
    accepted_generation: Generation,
    condition: AcceptanceCondition,
}

impl RotationAccepted {
    /// Creates a shape-validated projection without establishing authenticated provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        accepted_generation: Generation,
        condition: AcceptanceCondition,
    ) -> Self {
        Self {
            coordinates,
            accepted_generation,
            condition,
        }
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
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
    command: CommandRef,
    position: CommandAckPosition,
    outcome: CommandAcknowledgementOutcome,
}

impl CommandAcknowledgement {
    /// Creates an ACK projection without deriving readiness or trusted provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        command: CommandRef,
        position: CommandAckPosition,
        outcome: CommandAcknowledgementOutcome,
    ) -> Self {
        Self {
            coordinates,
            command,
            position,
            outcome,
        }
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
        position: ReportPosition,
        state_hash: StateHash,
        artifact_digest: ArtifactDigest,
        expires_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            coordinates,
            position,
            state_hash,
            artifact_digest,
            expires_at,
        }
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

/// Closed application ingress outcome with only valid reason pairings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationReceiptOutcome {
    /// The inbound observation was committed.
    Committed,
    /// The inbound observation was already committed.
    Duplicate,
    /// The inbound observation was stale for the attached reason.
    Stale(ApplicationStaleReason),
    /// The inbound observation was rejected for the attached reason.
    Rejected(ApplicationRejectionReason),
}

/// Product projection of an application ingress receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationReceiptObservation {
    coordinates: RotationCoordinates,
    ingress_envelope: IngressEnvelopeRef,
    outcome: ApplicationReceiptOutcome,
    committed_at: UnixTimestamp,
}

impl ApplicationReceiptObservation {
    /// Creates a receipt projection without deriving readiness or trusted provenance.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        ingress_envelope: IngressEnvelopeRef,
        outcome: ApplicationReceiptOutcome,
        committed_at: UnixTimestamp,
    ) -> Self {
        Self {
            coordinates,
            ingress_envelope,
            outcome,
            committed_at,
        }
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
    pub const fn outcome(&self) -> ApplicationReceiptOutcome {
        self.outcome
    }

    /// Returns the durable ingress commit time.
    #[must_use]
    pub const fn committed_at(&self) -> UnixTimestamp {
        self.committed_at
    }
}
