//! External T2 trace verification for Secure Device Rotation.
//!
//! This fixture observes only public contract projections. It does not start RSS,
//! derive authorization, infer readiness, or claim durable server-side state.

use std::{error::Error, fmt};

use rotation_model::{
    ApplicationReceiptObservation, ApplicationReceiptOutcome, CommandAcknowledgement,
    CommandAcknowledgementOutcome, CommandRejectionReason, CredentialReport, RotationAccepted,
};
use rss_device_security_client::{
    ConditionReason, ConditionStatus, ConditionType, DiagnosticKind, PolicyResponse,
    StatusProjection,
};

/// Closed failures for the disposable external-consumer trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JourneyError {
    /// ACK, report, receipt, or status correlation did not match the accepted generation.
    LineageMismatch,
    /// An ACK was not the expected received outcome.
    ExpectedReceivedAck,
    /// A public Ready condition appeared before an application receipt.
    ReadyBeforeReceipt,
    /// The positive trace did not contain a committed application receipt.
    ExpectedCommittedReceipt,
    /// The final public status did not contain an exact Ready observation.
    MissingReadyObservation,
    /// A stale-fact fixture did not remain a closed non-retryable forbidden response.
    ExpectedForbidden,
    /// A revoked artifact did not surface as the public policy-rejected ACK.
    ExpectedRevokedRejection,
    /// A revoked artifact path nevertheless observed Ready.
    ReadyAfterRevocation,
    /// ACK, report, and receipt event identities were not independent.
    EventIdentityCollision,
}

impl fmt::Display for JourneyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LineageMismatch => "external trace lineage mismatch",
            Self::ExpectedReceivedAck => "external trace expected a received ACK",
            Self::ReadyBeforeReceipt => "external trace observed Ready before receipt",
            Self::ExpectedCommittedReceipt => "external trace expected a committed receipt",
            Self::MissingReadyObservation => "external trace has no matching Ready observation",
            Self::ExpectedForbidden => "external trace expected a closed forbidden response",
            Self::ExpectedRevokedRejection => "external trace expected a revoked policy rejection",
            Self::ReadyAfterRevocation => "external trace observed Ready after revocation",
            Self::EventIdentityCollision => "external trace event identities collide",
        })
    }
}

impl Error for JourneyError {}

/// Verifies one exact public-contract trace without deriving authoritative state.
///
/// # Errors
///
/// Returns a closed [`JourneyError`] when the consumer-visible events do not
/// preserve generation, receipt, ordering, or final public status correlation.
pub fn verify_positive_trace(
    accepted: &RotationAccepted,
    acknowledgement: &CommandAcknowledgement,
    status_after_ack: &StatusProjection,
    report: &CredentialReport,
    receipt: &ApplicationReceiptObservation,
    final_status: &StatusProjection,
) -> Result<(), JourneyError> {
    if acknowledgement.outcome() != CommandAcknowledgementOutcome::Received {
        return Err(JourneyError::ExpectedReceivedAck);
    }
    if is_ready(status_after_ack) {
        return Err(JourneyError::ReadyBeforeReceipt);
    }
    let generation = accepted.accepted_generation();
    if acknowledgement.coordinates() != accepted.coordinates()
        || report.coordinates() != accepted.coordinates()
        || receipt.coordinates() != accepted.coordinates()
        || acknowledgement.desired_generation() != generation
        || report.observed_generation() != generation
        || report.fence_epoch() != acknowledgement.fence_epoch()
        || status_after_ack.desired_generation() != Some(generation.get())
        || status_after_ack
            .authorization_receipt_id()
            .map(|value| value.to_string())
            != Some(accepted.authorization_receipt().expose().to_owned())
    {
        return Err(JourneyError::LineageMismatch);
    }
    let ApplicationReceiptOutcome::Committed(lineage) = receipt.outcome() else {
        return Err(JourneyError::ExpectedCommittedReceipt);
    };
    if lineage.desired_generation() != generation
        || lineage.authorization_receipt() != accepted.authorization_receipt()
        || final_status.desired_generation() != Some(generation.get())
        || final_status.observed_generation() != generation.get()
        || final_status
            .authorization_receipt_id()
            .map(|value| value.to_string())
            != Some(accepted.authorization_receipt().expose().to_owned())
    {
        return Err(JourneyError::LineageMismatch);
    }
    if acknowledgement.event().expose() == report.event().expose()
        || acknowledgement.event().expose() == receipt.event().expose()
        || report.event().expose() == receipt.event().expose()
    {
        return Err(JourneyError::EventIdentityCollision);
    }
    if !is_ready(final_status) {
        return Err(JourneyError::MissingReadyObservation);
    }
    Ok(())
}

/// Verifies the closed public response used by the stale-fact fixture.
///
/// # Errors
///
/// Returns [`JourneyError::ExpectedForbidden`] for any accepted, retryable, or
/// differently classified response.
pub fn verify_forbidden(response: &PolicyResponse) -> Result<(), JourneyError> {
    match response {
        PolicyResponse::Rejected(diagnostic)
            if diagnostic.kind() == DiagnosticKind::Forbidden && !diagnostic.retryable() =>
        {
            Ok(())
        }
        PolicyResponse::Accepted(_) | PolicyResponse::Rejected(_) => {
            Err(JourneyError::ExpectedForbidden)
        }
    }
}

/// Verifies that the public result of a fixture-revoked credential cannot advance.
///
/// The reference-agent component test separately proves that a revoked catalog
/// entry maps to `PolicyRejected`; this function verifies only the public trace.
///
/// # Errors
///
/// Returns a closed [`JourneyError`] when the ACK is not policy-rejected or a
/// Ready/current-generation status is observed.
pub fn verify_revoked_no_advance(
    acknowledgement: &CommandAcknowledgement,
    status: &StatusProjection,
) -> Result<(), JourneyError> {
    if acknowledgement.outcome()
        != CommandAcknowledgementOutcome::Rejected(CommandRejectionReason::PolicyRejected)
    {
        return Err(JourneyError::ExpectedRevokedRejection);
    }
    if is_ready(status) {
        return Err(JourneyError::ReadyAfterRevocation);
    }
    if status.observed_generation() >= acknowledgement.desired_generation().get() {
        return Err(JourneyError::LineageMismatch);
    }
    Ok(())
}

fn is_ready(status: &StatusProjection) -> bool {
    status.conditions().iter().any(|condition| {
        condition.type_() == ConditionType::Ready
            && condition.status() == ConditionStatus::True
            && condition.reason() == ConditionReason::StateMatches
            && condition.observed_generation() == status.observed_generation()
    })
}
