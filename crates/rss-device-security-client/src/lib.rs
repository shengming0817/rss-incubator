#![doc = "Pure mappings from the canonical device-security contract to product facts."]

use std::fmt;

use rotation_model::{
    AcceptanceCondition, ApplicationReceiptObservation, ApplicationReceiptOutcome,
    ApplicationRejectionReason, ApplicationStaleReason, ArtifactDigest, AuthorizationReceiptRef,
    CommandAckPosition, CommandAcknowledgement, CommandAcknowledgementOutcome, CommandRef,
    CommandRejectionReason, CredentialReport, DeviceSequence, EventRef, FenceEpoch, Generation,
    IngressEnvelopeRef, KeyUsage, ReceiptLineage, ReportPosition, RotationAccepted,
    RotationCoordinates, RotationModelError, RotationPolicy, StateHash, UnixTimestamp,
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
        IdentityDeviceCertificatePolicyPutPolicy,
        IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem,
        IdentityDeviceCertificatePolicyPutPolicySansItem,
        IdentityDeviceCertificatePolicyPutRequest, IdentityDeviceCertificatePolicyPutResponse,
        IdentityDeviceCertificatePolicyPutValidationResponse,
    },
    status_get::{
        ActiveCommandState as CanonicalActiveCommandState,
        ConditionReason as CanonicalConditionReason, ConditionStatus as CanonicalConditionStatus,
        ConditionType as CanonicalConditionType, IdentityDeviceCertificateStatusGetResponse,
    },
};
use uuid::Uuid;

/// Canonical operation descriptor independent of any HTTP implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    pub method: &'static str,
    pub path_template: &'static str,
}

impl OperationDescriptor {
    fn path_for(self, device_id: Uuid) -> String {
        self.path_template
            .replace("{deviceId}", &device_id.to_string())
    }
}

pub const POLICY_PUT_OPERATION: OperationDescriptor = OperationDescriptor {
    method: "PUT",
    path_template: "/api/v2/identity/devices/{deviceId}/certificate-policy",
};

pub const STATUS_GET_OPERATION: OperationDescriptor = OperationDescriptor {
    method: "GET",
    path_template: "/api/v2/identity/devices/{deviceId}/certificate-status",
};

/// A fully prepared canonical request. Its body is intentionally redacted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRequest {
    method: &'static str,
    path: String,
    body: Option<Vec<u8>>,
}

impl fmt::Debug for PreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRequest")
            .field("method", &self.method)
            .field("path", &"[REDACTED]")
            .field("body", &self.body.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl PreparedRequest {
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

/// Payload-free construction or decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacadeError {
    InvalidInput,
    Serialization,
}

impl fmt::Display for FacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid canonical request input",
            Self::Serialization => "canonical request serialization failed",
        })
    }
}

impl std::error::Error for FacadeError {}

/// Builds the exact canonical policy PUT DTO and serializes it at the sole RSS edge.
///
/// # Errors
///
/// Returns [`FacadeError`] when product values cannot be represented by the canonical DTO or its
/// serialization fails.
pub fn prepare_policy_put(
    device_id: Uuid,
    expected_generation: u64,
    idempotency_key: Uuid,
    policy: &RotationPolicy,
) -> Result<PreparedRequest, FacadeError> {
    let key_usages = policy
        .key_usages()
        .iter()
        .map(|usage| match usage {
            KeyUsage::ClientAuth => {
                IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem::ClientAuth
            }
            KeyUsage::ServerAuth => {
                IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem::ServerAuth
            }
        })
        .collect();
    let sans = policy
        .sans()
        .iter()
        .map(|san| IdentityDeviceCertificatePolicyPutPolicySansItem::try_from(san.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FacadeError::InvalidInput)?;
    let renew =
        i64::try_from(policy.renew_before_seconds()).map_err(|_| FacadeError::InvalidInput)?;
    let validity =
        i64::try_from(policy.validity_seconds()).map_err(|_| FacadeError::InvalidInput)?;
    let expected = i64::try_from(expected_generation).map_err(|_| FacadeError::InvalidInput)?;
    let canonical_policy = IdentityDeviceCertificatePolicyPutPolicy::try_new(
        key_usages,
        renew,
        (!sans.is_empty()).then_some(sans),
        validity,
    )
    .map_err(|_| FacadeError::InvalidInput)?;
    let request = IdentityDeviceCertificatePolicyPutRequest::try_new(
        expected,
        idempotency_key,
        canonical_policy,
    )
    .map_err(|_| FacadeError::InvalidInput)?;
    let body = serde_json::to_vec(&request).map_err(|_| FacadeError::Serialization)?;
    Ok(PreparedRequest {
        method: POLICY_PUT_OPERATION.method,
        path: POLICY_PUT_OPERATION.path_for(device_id),
        body: Some(body),
    })
}

#[must_use]
pub fn prepare_status_get(device_id: Uuid) -> PreparedRequest {
    PreparedRequest {
        method: STATUS_GET_OPERATION.method,
        path: STATUS_GET_OPERATION.path_for(device_id),
        body: None,
    }
}

/// Closed diagnostic categories exposed to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticKind {
    Validation,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden,
    RateLimited,
    Upstream,
    Malformed,
    UnknownStatus,
}

impl DiagnosticKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Validation => "validation_failed",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
            Self::Upstream => "upstream_failure",
            Self::Malformed => "malformed_response",
            Self::UnknownStatus => "unknown_status",
        }
    }

    const fn retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Upstream)
    }
}

/// Sanitized diagnostic; upstream payloads and provider messages are never retained.
#[derive(Clone, Eq, PartialEq)]
pub struct Diagnostic {
    kind: DiagnosticKind,
    request_id: Option<String>,
    retryable: bool,
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Diagnostic")
            .field("kind", &self.kind)
            .field(
                "request_id",
                &self.request_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("retryable", &self.retryable)
            .finish()
    }
}

impl Diagnostic {
    #[must_use]
    pub const fn kind(&self) -> DiagnosticKind {
        self.kind
    }
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }
    fn new(kind: DiagnosticKind, request_id: Option<String>) -> Self {
        Self {
            kind,
            request_id,
            retryable: kind.retryable(),
        }
    }

    fn conflict(request_id: String, retryable: bool) -> Self {
        Self {
            kind: DiagnosticKind::Conflict,
            request_id: Some(request_id),
            retryable,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAcceptedProjection {
    receipt_id: Uuid,
    generation: u64,
    condition: PolicyCondition,
}
impl PolicyAcceptedProjection {
    #[must_use]
    pub const fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn condition(&self) -> PolicyCondition {
        self.condition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyResponse {
    Accepted(PolicyAcceptedProjection),
    Rejected(Diagnostic),
}

/// Decodes only documented policy status/body pairs into a closed projection.
#[must_use]
pub fn decode_policy_response(status: u16, body: &[u8]) -> PolicyResponse {
    let malformed = || PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::Malformed, None));
    match status {
        200 => serde_json::from_slice::<IdentityDeviceCertificatePolicyPutResponse>(body).map_or_else(
            |_| malformed(),
            |value| PolicyResponse::Accepted(PolicyAcceptedProjection {
                receipt_id: value.data.authorization_receipt_id.as_uuid(),
                generation: value.data.accepted_generation.get(),
                condition: match value.data.condition {
                    IdentityDeviceCertificatePolicyPutDataCondition::Reconciling => PolicyCondition::Reconciling,
                    IdentityDeviceCertificatePolicyPutDataCondition::PendingDevice => PolicyCondition::PendingDevice,
                },
            }),
        ),
        400 => serde_json::from_slice::<IdentityDeviceCertificatePolicyPutValidationResponse>(body)
            .map_or_else(|_| malformed(), |value| PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::Validation, Some(value.error.request_id)))),
        404 => serde_json::from_slice::<IdentityDeviceCertificatePolicyPutNotFoundResponse>(body)
            .map_or_else(|_| malformed(), |value| PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::NotFound, Some(value.error.request_id)))),
        409 => serde_json::from_slice::<IdentityDeviceCertificatePolicyPutConflictResponse>(body)
            .map_or_else(|_| malformed(), |value| {
                use rss_device_security_contracts::policy_put::IdentityDeviceCertificatePolicyPutConflictError;
                let (request_id, retryable) = match value.error {
                    IdentityDeviceCertificatePolicyPutConflictError::ErrCoreVersionConflict { request_id, retryable, .. }
                    | IdentityDeviceCertificatePolicyPutConflictError::ErrCoreConflict { request_id, retryable, .. } => (request_id, retryable),
                };
                PolicyResponse::Rejected(Diagnostic::conflict(request_id, retryable))
            }),
        401 => PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::Unauthorized, None)),
        403 => PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::Forbidden, None)),
        429 => PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::RateLimited, None)),
        500..=599 => PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::Upstream, None)),
        _ => PolicyResponse::Rejected(Diagnostic::new(DiagnosticKind::UnknownStatus, None)),
    }
}

macro_rules! closed_text_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $($variant),+ }
        impl $name {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
    };
}

closed_text_enum!(PolicyCondition { Reconciling => "Reconciling", PendingDevice => "PendingDevice" });
closed_text_enum!(ActiveCommandState { Queued => "queued", Published => "published", Received => "received" });
closed_text_enum!(ConditionStatus { True => "True", False => "False", Unknown => "Unknown" });
closed_text_enum!(ConditionType { Ready => "Ready", Reconciling => "Reconciling", PendingDevice => "PendingDevice", Degraded => "Degraded", Quarantined => "Quarantined", Deleting => "Deleting" });
closed_text_enum!(ConditionReason {
    DesiredAccepted => "DesiredAccepted", CommandQueued => "CommandQueued",
    AwaitingDevice => "AwaitingDevice", DeviceReported => "DeviceReported",
    StateMatches => "StateMatches", StateDrift => "StateDrift",
    CommandRejected => "CommandRejected", CommandTimedOut => "CommandTimedOut",
    ProtocolViolation => "ProtocolViolation", QuarantinedByOperator => "QuarantinedByOperator",
    DeletionPending => "DeletionPending", DeletionComplete => "DeletionComplete",
    ArtifactUnavailable => "ArtifactUnavailable", TransportUnavailable => "TransportUnavailable"
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveCommandProjection {
    fence_epoch: u64,
    state: ActiveCommandState,
}
impl ActiveCommandProjection {
    #[must_use]
    pub const fn fence_epoch(&self) -> u64 {
        self.fence_epoch
    }
    #[must_use]
    pub const fn state(&self) -> ActiveCommandState {
        self.state
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionProjection {
    observed_generation: u64,
    reason: ConditionReason,
    status: ConditionStatus,
    type_: ConditionType,
    last_transition_at: i64,
}
impl ConditionProjection {
    #[must_use]
    pub const fn observed_generation(&self) -> u64 {
        self.observed_generation
    }
    #[must_use]
    pub const fn reason(&self) -> ConditionReason {
        self.reason
    }
    #[must_use]
    pub const fn status(&self) -> ConditionStatus {
        self.status
    }
    #[must_use]
    pub const fn type_(&self) -> ConditionType {
        self.type_
    }
    #[must_use]
    pub const fn last_transition_at(&self) -> i64 {
        self.last_transition_at
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusProjection {
    desired_generation: Option<u64>,
    authorization_receipt_id: Option<Uuid>,
    observed_generation: u64,
    active_command: Option<ActiveCommandProjection>,
    conditions: Vec<ConditionProjection>,
}
impl StatusProjection {
    #[must_use]
    pub const fn desired_generation(&self) -> Option<u64> {
        self.desired_generation
    }
    #[must_use]
    pub const fn authorization_receipt_id(&self) -> Option<Uuid> {
        self.authorization_receipt_id
    }
    #[must_use]
    pub const fn observed_generation(&self) -> u64 {
        self.observed_generation
    }
    #[must_use]
    pub const fn active_command(&self) -> Option<&ActiveCommandProjection> {
        self.active_command.as_ref()
    }
    #[must_use]
    pub fn conditions(&self) -> &[ConditionProjection] {
        &self.conditions
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusResponse {
    Observed(StatusProjection),
    Rejected(Diagnostic),
}

#[must_use]
pub fn decode_status_response(status: u16, body: &[u8]) -> StatusResponse {
    if status != 200 {
        let kind = match status {
            401 => DiagnosticKind::Unauthorized,
            403 => DiagnosticKind::Forbidden,
            404 => DiagnosticKind::NotFound,
            429 => DiagnosticKind::RateLimited,
            500..=599 => DiagnosticKind::Upstream,
            _ => DiagnosticKind::UnknownStatus,
        };
        return StatusResponse::Rejected(Diagnostic::new(kind, None));
    }
    let Ok(value) = serde_json::from_slice::<IdentityDeviceCertificateStatusGetResponse>(body)
    else {
        return StatusResponse::Rejected(Diagnostic::new(DiagnosticKind::Malformed, None));
    };
    let desired_generation = value
        .data
        .desired
        .as_ref()
        .map(|desired| desired.generation.get());
    let authorization_receipt_id = value
        .data
        .desired
        .as_ref()
        .map(|desired| desired.authorization_receipt_id.as_uuid());
    let active_command = value
        .data
        .desired
        .as_ref()
        .and_then(|desired| desired.active_command.as_ref())
        .map(|command| ActiveCommandProjection {
            fence_epoch: command.fence_epoch.get(),
            state: match command.state {
                CanonicalActiveCommandState::Queued => ActiveCommandState::Queued,
                CanonicalActiveCommandState::Published => ActiveCommandState::Published,
                CanonicalActiveCommandState::Received => ActiveCommandState::Received,
            },
        });
    let Ok(observed_generation) = u64::try_from(value.data.observed_generation) else {
        return StatusResponse::Rejected(Diagnostic::new(DiagnosticKind::Malformed, None));
    };
    let mut conditions = Vec::with_capacity(value.data.conditions.len());
    for condition in value.data.conditions {
        let Ok(generation) = u64::try_from(condition.observed_generation) else {
            return StatusResponse::Rejected(Diagnostic::new(DiagnosticKind::Malformed, None));
        };
        conditions.push(ConditionProjection {
            observed_generation: generation,
            reason: match condition.reason {
                CanonicalConditionReason::DesiredAccepted => ConditionReason::DesiredAccepted,
                CanonicalConditionReason::CommandQueued => ConditionReason::CommandQueued,
                CanonicalConditionReason::AwaitingDevice => ConditionReason::AwaitingDevice,
                CanonicalConditionReason::DeviceReported => ConditionReason::DeviceReported,
                CanonicalConditionReason::StateMatches => ConditionReason::StateMatches,
                CanonicalConditionReason::StateDrift => ConditionReason::StateDrift,
                CanonicalConditionReason::CommandRejected => ConditionReason::CommandRejected,
                CanonicalConditionReason::CommandTimedOut => ConditionReason::CommandTimedOut,
                CanonicalConditionReason::ProtocolViolation => ConditionReason::ProtocolViolation,
                CanonicalConditionReason::QuarantinedByOperator => {
                    ConditionReason::QuarantinedByOperator
                }
                CanonicalConditionReason::DeletionPending => ConditionReason::DeletionPending,
                CanonicalConditionReason::DeletionComplete => ConditionReason::DeletionComplete,
                CanonicalConditionReason::ArtifactUnavailable => {
                    ConditionReason::ArtifactUnavailable
                }
                CanonicalConditionReason::TransportUnavailable => {
                    ConditionReason::TransportUnavailable
                }
            },
            status: match condition.status {
                CanonicalConditionStatus::True => ConditionStatus::True,
                CanonicalConditionStatus::False => ConditionStatus::False,
                CanonicalConditionStatus::Unknown => ConditionStatus::Unknown,
            },
            type_: match condition.type_ {
                CanonicalConditionType::Ready => ConditionType::Ready,
                CanonicalConditionType::Reconciling => ConditionType::Reconciling,
                CanonicalConditionType::PendingDevice => ConditionType::PendingDevice,
                CanonicalConditionType::Degraded => ConditionType::Degraded,
                CanonicalConditionType::Quarantined => ConditionType::Quarantined,
                CanonicalConditionType::Deleting => ConditionType::Deleting,
            },
            last_transition_at: condition.last_transition_at,
        });
    }
    StatusResponse::Observed(StatusProjection {
        desired_generation,
        authorization_receipt_id,
        observed_generation,
        active_command,
        conditions,
    })
}

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
