#![doc = "Pure mappings from the canonical device-security contract to product facts."]

use std::fmt;

use rotation_model::{
    AcceptanceCondition, ApplicationReceiptObservation, ApplicationReceiptOutcome,
    ApplicationRejectionReason, ApplicationStaleReason, ArtifactDigest, AuthorizationReceiptRef,
    CommandAckPosition, CommandAcknowledgement, CommandAcknowledgementOutcome, CommandRef,
    CommandRejectionReason, CredentialReport, DeviceSequence, EventRef, FenceEpoch, Generation,
    IngressEnvelopeRef, ReceiptLineage, ReportPosition, RotationAccepted, RotationCoordinates,
    RotationModelError, StateHash, UnixTimestamp,
};
use rss_device_security_contracts::{
    AuthorizationReceiptId,
    apply_device_certificate::IdentityApplyDeviceCertificateRequest,
    device_certificate_reported::IdentityDeviceCertificateReportedPayload,
    device_command_acked::{
        IdentityDeviceCommandAckedPayload, IdentityDeviceCommandAckedReceivedPayloadReason,
        IdentityDeviceCommandAckedReceivedPayloadResult,
        IdentityDeviceCommandAckedRejectedPayloadReason,
        IdentityDeviceCommandAckedRejectedPayloadResult,
    },
    device_ingress_receipted::{
        IdentityDeviceIngressCommittedPayloadOutcome, IdentityDeviceIngressCommittedPayloadReason,
        IdentityDeviceIngressDuplicatePayloadOutcome, IdentityDeviceIngressDuplicatePayloadReason,
        IdentityDeviceIngressReceiptedPayload, IdentityDeviceIngressRejectedPayloadOutcome,
        IdentityDeviceIngressRejectedPayloadReason, IdentityDeviceIngressStalePayloadOutcome,
        IdentityDeviceIngressStalePayloadReason,
    },
    policy_put::{
        IdentityDeviceCertificatePolicyPutConflictResponse,
        IdentityDeviceCertificatePolicyPutDataCondition,
        IdentityDeviceCertificatePolicyPutNotFoundResponse,
        IdentityDeviceCertificatePolicyPutResponse,
    },
    status_get::IdentityDeviceCertificateStatusGetResponse,
};
use uuid::Uuid;

/// Product correlation plus the public device UUID expected at this mapping boundary.
///
/// This is shape context only; it does not authenticate a tenant or device.
#[derive(Clone, Eq, PartialEq)]
pub struct MappingContext {
    coordinates: RotationCoordinates,
    expected_device_id: Uuid,
}

impl fmt::Debug for MappingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappingContext")
            .field("coordinates", &self.coordinates)
            .field("expected_device_id", &"[REDACTED]")
            .finish()
    }
}

impl MappingContext {
    #[must_use]
    pub const fn new(coordinates: RotationCoordinates, expected_device_id: Uuid) -> Self {
        Self {
            coordinates,
            expected_device_id,
        }
    }

    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    #[must_use]
    pub const fn expected_device_id(&self) -> Uuid {
        self.expected_device_id
    }

    fn require_device(&self, actual: Uuid) -> Result<(), MappingError> {
        if actual == self.expected_device_id {
            Ok(())
        } else {
            Err(MappingError::DeviceMismatch {
                expected: self.expected_device_id,
                actual,
            })
        }
    }
}

/// A canonical policy PUT failure, preserved without copying its code space.
pub enum PolicyPutFailure {
    NotFound(IdentityDeviceCertificatePolicyPutNotFoundResponse),
    Conflict(IdentityDeviceCertificatePolicyPutConflictResponse),
}

/// A canonical status DTO correlated with product coordinates.
pub struct StatusObservation {
    context: MappingContext,
    response: IdentityDeviceCertificateStatusGetResponse,
}

impl StatusObservation {
    #[must_use]
    pub const fn new(
        context: MappingContext,
        response: IdentityDeviceCertificateStatusGetResponse,
    ) -> Self {
        Self { context, response }
    }

    #[must_use]
    pub const fn context(&self) -> &MappingContext {
        &self.context
    }

    #[must_use]
    pub const fn response(&self) -> &IdentityDeviceCertificateStatusGetResponse {
        &self.response
    }

    #[must_use]
    pub fn into_parts(self) -> (MappingContext, IdentityDeviceCertificateStatusGetResponse) {
        (self.context, self.response)
    }
}

/// A command DTO correlated with its payload-external envelope identity.
pub struct CorrelatedCommand {
    context: MappingContext,
    envelope: CommandRef,
    request: IdentityApplyDeviceCertificateRequest,
}

impl CorrelatedCommand {
    #[must_use]
    pub const fn context(&self) -> &MappingContext {
        &self.context
    }

    #[must_use]
    pub const fn envelope(&self) -> &CommandRef {
        &self.envelope
    }

    #[must_use]
    pub const fn request(&self) -> &IdentityApplyDeviceCertificateRequest {
        &self.request
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        MappingContext,
        CommandRef,
        IdentityApplyDeviceCertificateRequest,
    ) {
        (self.context, self.envelope, self.request)
    }
}

/// Mapping rejection for invalid boundary correlations or product references.
#[derive(Clone, Eq, PartialEq)]
pub enum MappingError {
    DeviceMismatch { expected: Uuid, actual: Uuid },
    NegativeDeviceSequence(i64),
    InvalidProductReference(RotationModelError),
}

impl fmt::Debug for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceMismatch { .. } => {
                formatter.write_str("MappingError::DeviceMismatch([REDACTED])")
            }
            Self::NegativeDeviceSequence(_) => {
                formatter.write_str("MappingError::NegativeDeviceSequence([REDACTED])")
            }
            Self::InvalidProductReference(_) => {
                formatter.write_str("MappingError::InvalidProductReference([REDACTED])")
            }
        }
    }
}

impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceMismatch { .. } => formatter.write_str("device mismatch"),
            Self::NegativeDeviceSequence(_) => formatter.write_str("negative device sequence"),
            Self::InvalidProductReference(_) => formatter.write_str("invalid product reference"),
        }
    }
}

impl std::error::Error for MappingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProductReference(error) => Some(error),
            Self::DeviceMismatch { .. } | Self::NegativeDeviceSequence(_) => None,
        }
    }
}

impl From<RotationModelError> for MappingError {
    fn from(value: RotationModelError) -> Self {
        Self::InvalidProductReference(value)
    }
}

/// Maps canonical policy acceptance directly into the product model.
///
/// # Errors
///
/// Returns [`MappingError`] when a canonical correlation cannot form a valid product reference.
pub fn map_policy_success(
    context: &MappingContext,
    response: &IdentityDeviceCertificatePolicyPutResponse,
) -> Result<RotationAccepted, MappingError> {
    let condition = match response.data.condition {
        IdentityDeviceCertificatePolicyPutDataCondition::Reconciling => {
            AcceptanceCondition::Reconciling
        }
        IdentityDeviceCertificatePolicyPutDataCondition::PendingDevice => {
            AcceptanceCondition::PendingDevice
        }
    };
    Ok(RotationAccepted::new(
        context.coordinates.clone(),
        receipt_ref(response.data.authorization_receipt_id)?,
        Generation::try_from(response.data.accepted_generation.get())?,
        condition,
    ))
}

#[must_use]
pub const fn map_policy_not_found(
    response: IdentityDeviceCertificatePolicyPutNotFoundResponse,
) -> PolicyPutFailure {
    PolicyPutFailure::NotFound(response)
}

#[must_use]
pub const fn map_policy_conflict(
    response: IdentityDeviceCertificatePolicyPutConflictResponse,
) -> PolicyPutFailure {
    PolicyPutFailure::Conflict(response)
}

#[must_use]
pub const fn observe_status(
    context: MappingContext,
    response: IdentityDeviceCertificateStatusGetResponse,
) -> StatusObservation {
    StatusObservation::new(context, response)
}

/// Validates device correlation and keeps the command body separate from its envelope identity.
///
/// # Errors
///
/// Returns [`MappingError::DeviceMismatch`] when the payload names another public device UUID.
pub fn correlate_command(
    context: MappingContext,
    envelope: CommandRef,
    request: IdentityApplyDeviceCertificateRequest,
) -> Result<CorrelatedCommand, MappingError> {
    context.require_device(request.device_id)?;
    Ok(CorrelatedCommand {
        context,
        envelope,
        request,
    })
}

/// Maps an ACK event while preserving independent event and command identities.
///
/// # Errors
///
/// Returns [`MappingError`] for a device mismatch, negative sequence, or invalid product reference.
pub fn map_acknowledgement(
    context: &MappingContext,
    event: EventRef,
    payload: IdentityDeviceCommandAckedPayload,
) -> Result<CommandAcknowledgement, MappingError> {
    match payload {
        IdentityDeviceCommandAckedPayload::ReceivedPayload(payload) => {
            context.require_device(payload.device_id)?;
            let outcome = match (payload.result, payload.reason) {
                (
                    IdentityDeviceCommandAckedReceivedPayloadResult::Received,
                    IdentityDeviceCommandAckedReceivedPayloadReason::None,
                ) => CommandAcknowledgementOutcome::Received,
            };
            ack(
                context,
                event,
                AckProjection {
                    command: String::from(payload.command_id),
                    desired_generation: payload.desired_generation.get(),
                    fence_epoch: payload.fence_epoch.get(),
                    device_sequence: payload.device_sequence,
                    observed_at: payload.observed_at,
                    outcome,
                },
            )
        }
        IdentityDeviceCommandAckedPayload::RejectedPayload(payload) => {
            context.require_device(payload.device_id)?;
            let result = match payload.result {
                IdentityDeviceCommandAckedRejectedPayloadResult::Rejected => {
                    CommandAcknowledgementOutcome::Rejected(match payload.reason {
                        IdentityDeviceCommandAckedRejectedPayloadReason::ArtifactUnavailable => {
                            CommandRejectionReason::ArtifactUnavailable
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::ArtifactDigestMismatch => {
                            CommandRejectionReason::ArtifactDigestMismatch
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::PolicyRejected => {
                            CommandRejectionReason::PolicyRejected
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::GenerationStale => {
                            CommandRejectionReason::GenerationStale
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::FenceEpochStale => {
                            CommandRejectionReason::FenceEpochStale
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::MalformedCommand => {
                            CommandRejectionReason::MalformedCommand
                        }
                        IdentityDeviceCommandAckedRejectedPayloadReason::DeviceFailure => {
                            CommandRejectionReason::DeviceFailure
                        }
                    })
                }
            };
            ack(
                context,
                event,
                AckProjection {
                    command: String::from(payload.command_id),
                    desired_generation: payload.desired_generation.get(),
                    fence_epoch: payload.fence_epoch.get(),
                    device_sequence: payload.device_sequence,
                    observed_at: payload.observed_at,
                    outcome: result,
                },
            )
        }
    }
}

struct AckProjection {
    command: String,
    desired_generation: u64,
    fence_epoch: u64,
    device_sequence: i64,
    observed_at: i64,
    outcome: CommandAcknowledgementOutcome,
}

fn ack(
    context: &MappingContext,
    event: EventRef,
    projection: AckProjection,
) -> Result<CommandAcknowledgement, MappingError> {
    Ok(CommandAcknowledgement::new(
        context.coordinates.clone(),
        event,
        CommandRef::try_from(projection.command)?,
        CommandAckPosition::new(
            Generation::try_from(projection.desired_generation)?,
            FenceEpoch::try_from(projection.fence_epoch)?,
            sequence(projection.device_sequence)?,
            UnixTimestamp::new(projection.observed_at),
        ),
        projection.outcome,
    ))
}

/// Maps a reported-state event directly into the product model.
///
/// # Errors
///
/// Returns [`MappingError`] for a device mismatch, negative sequence, or invalid product reference.
pub fn map_report(
    context: &MappingContext,
    event: EventRef,
    payload: IdentityDeviceCertificateReportedPayload,
) -> Result<CredentialReport, MappingError> {
    context.require_device(payload.device_id)?;
    Ok(CredentialReport::new(
        context.coordinates.clone(),
        event,
        ReportPosition::new(
            Generation::try_from(payload.observed_generation.get())?,
            FenceEpoch::try_from(payload.fence_epoch.get())?,
            sequence(payload.device_sequence)?,
            UnixTimestamp::new(payload.observed_at),
        ),
        StateHash::try_from(String::from(payload.state_hash))?,
        ArtifactDigest::try_from(String::from(payload.artifact_digest))?,
        payload.expires_at.map(UnixTimestamp::new),
    ))
}

/// Maps all four canonical receipt branches into the closed product outcome.
///
/// # Errors
///
/// Returns [`MappingError`] for a device mismatch or invalid correlation reference.
pub fn map_receipt(
    context: &MappingContext,
    event: EventRef,
    payload: IdentityDeviceIngressReceiptedPayload,
) -> Result<ApplicationReceiptObservation, MappingError> {
    match payload {
        IdentityDeviceIngressReceiptedPayload::CommittedPayload(payload) => {
            context.require_device(payload.device_id)?;
            let outcome = match (payload.outcome, payload.reason) {
                (
                    IdentityDeviceIngressCommittedPayloadOutcome::Committed,
                    IdentityDeviceIngressCommittedPayloadReason::None,
                ) => ApplicationReceiptOutcome::Committed(lineage(
                    payload.authorization_receipt_id,
                    payload.desired_generation.get(),
                )?),
            };
            receipt(
                context,
                event,
                String::from(payload.ingress_envelope_id),
                outcome,
                payload.committed_at,
            )
        }
        IdentityDeviceIngressReceiptedPayload::DuplicatePayload(payload) => {
            context.require_device(payload.device_id)?;
            let outcome = match (payload.outcome, payload.reason) {
                (
                    IdentityDeviceIngressDuplicatePayloadOutcome::Duplicate,
                    IdentityDeviceIngressDuplicatePayloadReason::AlreadyCommitted,
                ) => ApplicationReceiptOutcome::Duplicate(lineage(
                    payload.authorization_receipt_id,
                    payload.desired_generation.get(),
                )?),
            };
            receipt(
                context,
                event,
                String::from(payload.ingress_envelope_id),
                outcome,
                payload.committed_at,
            )
        }
        IdentityDeviceIngressReceiptedPayload::StalePayload(payload) => {
            context.require_device(payload.device_id)?;
            match payload.outcome {
                IdentityDeviceIngressStalePayloadOutcome::Stale => (),
            }
            let reason = match payload.reason {
                IdentityDeviceIngressStalePayloadReason::GenerationStale => {
                    ApplicationStaleReason::GenerationStale
                }
                IdentityDeviceIngressStalePayloadReason::FenceEpochStale => {
                    ApplicationStaleReason::FenceEpochStale
                }
                IdentityDeviceIngressStalePayloadReason::DeviceSequenceStale => {
                    ApplicationStaleReason::DeviceSequenceStale
                }
            };
            let outcome = ApplicationReceiptOutcome::Stale {
                lineage: lineage(
                    payload.authorization_receipt_id,
                    payload.desired_generation.get(),
                )?,
                reason,
            };
            receipt(
                context,
                event,
                String::from(payload.ingress_envelope_id),
                outcome,
                payload.committed_at,
            )
        }
        IdentityDeviceIngressReceiptedPayload::RejectedPayload(payload) => {
            context.require_device(payload.device_id)?;
            match payload.outcome {
                IdentityDeviceIngressRejectedPayloadOutcome::Rejected => (),
            }
            let reason = match payload.reason {
                IdentityDeviceIngressRejectedPayloadReason::NotAccepted => {
                    ApplicationRejectionReason::NotAccepted
                }
                IdentityDeviceIngressRejectedPayloadReason::SchemaRejected => {
                    ApplicationRejectionReason::SchemaRejected
                }
                IdentityDeviceIngressRejectedPayloadReason::ProtocolViolation => {
                    ApplicationRejectionReason::ProtocolViolation
                }
            };
            receipt(
                context,
                event,
                String::from(payload.ingress_envelope_id),
                ApplicationReceiptOutcome::Rejected(reason),
                payload.committed_at,
            )
        }
    }
}

fn receipt(
    context: &MappingContext,
    event: EventRef,
    ingress_envelope: String,
    outcome: ApplicationReceiptOutcome,
    committed_at: i64,
) -> Result<ApplicationReceiptObservation, MappingError> {
    Ok(ApplicationReceiptObservation::new(
        context.coordinates.clone(),
        event,
        IngressEnvelopeRef::try_from(ingress_envelope)?,
        outcome,
        UnixTimestamp::new(committed_at),
    ))
}

fn receipt_ref(value: AuthorizationReceiptId) -> Result<AuthorizationReceiptRef, MappingError> {
    AuthorizationReceiptRef::try_from(value.as_uuid().to_string()).map_err(Into::into)
}

fn lineage(
    authorization_receipt: AuthorizationReceiptId,
    desired_generation: u64,
) -> Result<ReceiptLineage, MappingError> {
    Ok(ReceiptLineage::new(
        receipt_ref(authorization_receipt)?,
        Generation::try_from(desired_generation)?,
    ))
}

fn sequence(value: i64) -> Result<DeviceSequence, MappingError> {
    u64::try_from(value)
        .map(DeviceSequence::new)
        .map_err(|_| MappingError::NegativeDeviceSequence(value))
}
