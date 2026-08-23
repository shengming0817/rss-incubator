use std::{collections::HashMap, error::Error as _, fmt::Debug, num::NonZeroU64, str::FromStr};

use rotation_model::{
    AcceptanceCondition, ApplicationReceiptOutcome, ApplicationRejectionReason,
    ApplicationStaleReason, CommandAcknowledgementOutcome, CommandRef, CommandRejectionReason,
    DeviceRef, EventRef, RotationCoordinates, RotationId, TenantRef,
};
use rss_device_security_client::{
    MappingContext, MappingError, PolicyPutFailure, correlate_command, map_acknowledgement,
    map_policy_conflict, map_policy_not_found, map_policy_success, map_receipt, map_report,
    observe_status,
};
use rss_device_security_contracts::{
    AuthorizationReceiptId,
    apply_device_certificate::{
        IdentityApplyDeviceCertificateRequest as ApplyRequest,
        IdentityApplyDeviceCertificateRequestArtifactDigest as ApplyDigest,
        IdentityApplyDeviceCertificateRequestArtifactId as ArtifactId,
        IdentityApplyDeviceCertificateRequestIntentDigest as IntentDigest,
        IdentityApplyDeviceCertificateRequestPolicyHash as PolicyHash,
    },
    device_certificate_reported::{
        IdentityDeviceCertificateReportedPayload as ReportPayload,
        IdentityDeviceCertificateReportedPayloadArtifactDigest as ReportDigest,
        IdentityDeviceCertificateReportedPayloadStateHash as ReportHash,
    },
    device_command_acked::{
        IdentityDeviceCommandAckedPayload as AckPayload,
        IdentityDeviceCommandAckedReceivedPayload as ReceivedAck,
        IdentityDeviceCommandAckedReceivedPayloadCommandId as ReceivedCommandId,
        IdentityDeviceCommandAckedReceivedPayloadReason as ReceivedReason,
        IdentityDeviceCommandAckedReceivedPayloadResult as ReceivedResult,
        IdentityDeviceCommandAckedRejectedPayload as RejectedAck,
        IdentityDeviceCommandAckedRejectedPayloadCommandId as RejectedCommandId,
        IdentityDeviceCommandAckedRejectedPayloadReason as RejectedReason,
        IdentityDeviceCommandAckedRejectedPayloadResult as RejectedResult,
    },
    device_ingress_receipted::{
        IdentityDeviceIngressCommittedPayload as CommittedReceipt,
        IdentityDeviceIngressCommittedPayloadIngressEnvelopeId as CommittedIngress,
        IdentityDeviceIngressCommittedPayloadOutcome as CommittedOutcome,
        IdentityDeviceIngressCommittedPayloadReason as CommittedReason,
        IdentityDeviceIngressDuplicatePayload as DuplicateReceipt,
        IdentityDeviceIngressDuplicatePayloadIngressEnvelopeId as DuplicateIngress,
        IdentityDeviceIngressDuplicatePayloadOutcome as DuplicateOutcome,
        IdentityDeviceIngressDuplicatePayloadReason as DuplicateReason,
        IdentityDeviceIngressReceiptedPayload as ReceiptPayload,
        IdentityDeviceIngressRejectedPayload as RejectedReceipt,
        IdentityDeviceIngressRejectedPayloadIngressEnvelopeId as RejectedIngress,
        IdentityDeviceIngressRejectedPayloadOutcome as RejectedReceiptOutcome,
        IdentityDeviceIngressRejectedPayloadReason as ReceiptRejectionReason,
        IdentityDeviceIngressStalePayload as StaleReceipt,
        IdentityDeviceIngressStalePayloadIngressEnvelopeId as StaleIngress,
        IdentityDeviceIngressStalePayloadOutcome as StaleOutcome,
        IdentityDeviceIngressStalePayloadReason as StaleReason,
    },
    policy_put::{
        IdentityDeviceCertificatePolicyPutConflictError as ConflictError,
        IdentityDeviceCertificatePolicyPutConflictResponse as ConflictResponse,
        IdentityDeviceCertificatePolicyPutConflictResponseErrorMessage as ConflictMessage,
        IdentityDeviceCertificatePolicyPutData as PolicyData,
        IdentityDeviceCertificatePolicyPutDataCondition as PolicyCondition,
        IdentityDeviceCertificatePolicyPutNotFoundError as NotFoundError,
        IdentityDeviceCertificatePolicyPutNotFoundErrorCode as NotFoundCode,
        IdentityDeviceCertificatePolicyPutNotFoundErrorMessage as NotFoundMessage,
        IdentityDeviceCertificatePolicyPutNotFoundResponse as NotFoundResponse,
        IdentityDeviceCertificatePolicyPutResponse as PolicyResponse,
    },
    status_get::{
        IdentityDeviceCertificateStatusGetData as StatusData,
        IdentityDeviceCertificateStatusGetResponse as StatusResponse,
    },
};
use uuid::Uuid;

const DEVICE: &str = "0198d5f2-70de-7a2d-b3f4-012345678901";
const OTHER_DEVICE: &str = "0198d5f2-70de-7a2d-b3f4-012345678902";
const RECEIPT: &str = "0198d5f2-70de-7a2d-b3f4-0123456789ab";
const HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn policy_success_preserves_receipt_generation_and_closed_condition() {
    for (canonical, expected) in [
        (
            PolicyCondition::Reconciling,
            AcceptanceCondition::Reconciling,
        ),
        (
            PolicyCondition::PendingDevice,
            AcceptanceCondition::PendingDevice,
        ),
    ] {
        let response = PolicyResponse {
            data: PolicyData {
                accepted_generation: nz(8),
                authorization_receipt_id: parsed(RECEIPT),
                condition: canonical,
            },
        };
        let accepted = map_policy_success(&context(), &response).expect("valid acceptance");
        assert_eq!(accepted.authorization_receipt().expose(), RECEIPT);
        assert_eq!(accepted.accepted_generation().get(), 8);
        assert_eq!(accepted.condition(), expected);
    }
}

#[test]
fn policy_failures_preserve_canonical_404_and_both_409_variants() {
    let response = NotFoundResponse {
        error: NotFoundError {
            code: NotFoundCode::ErrCoreNotFound,
            details: Vec::new(),
            message: NotFoundMessage::NotFound,
            request_id: "request-404".to_owned(),
            retryable: false,
        },
    };
    match map_policy_not_found(response) {
        PolicyPutFailure::NotFound(response) => {
            assert!(response.error.code == NotFoundCode::ErrCoreNotFound);
            assert_eq!(response.error.request_id, "request-404");
            assert!(!response.error.retryable);
        }
        PolicyPutFailure::Conflict(_) => panic!("expected not found"),
    }

    for error in [
        ConflictError::ErrCoreVersionConflict {
            details: Vec::<HashMap<String, String>>::new(),
            message: ConflictMessage::VersionConflict,
            request_id: "request-409-version".to_owned(),
            retryable: false,
        },
        ConflictError::ErrCoreConflict {
            details: Vec::<HashMap<String, String>>::new(),
            message: ConflictMessage::VersionConflict,
            request_id: "request-409-conflict".to_owned(),
            retryable: false,
        },
    ] {
        match map_policy_conflict(ConflictResponse { error }) {
            PolicyPutFailure::Conflict(_) => {}
            PolicyPutFailure::NotFound(_) => panic!("expected conflict"),
        }
    }
}

#[test]
fn status_and_command_preserve_canonical_dtos_and_external_envelope() {
    let observation = observe_status(
        context(),
        StatusResponse {
            data: StatusData {
                conditions: Vec::new(),
                desired: None,
                observed_generation: 3,
            },
        },
    );
    assert_eq!(observation.context().expected_device_id(), device_id());
    assert_eq!(observation.response().data.observed_generation, 3);
    let (status_context, status_response) = observation.into_parts();
    assert_eq!(status_context.expected_device_id(), device_id());
    assert_eq!(status_response.data.observed_generation, 3);

    let correlated = correlate_command(
        context(),
        CommandRef::try_from("command-envelope-1").expect("fixed envelope"),
        command(device_id()),
    )
    .expect("matching device");
    assert_eq!(correlated.envelope().expose(), "command-envelope-1");
    assert_eq!(correlated.request().device_id, device_id());
    let (command_context, envelope, request) = correlated.into_parts();
    assert_eq!(command_context.expected_device_id(), device_id());
    assert_eq!(envelope.expose(), "command-envelope-1");
    assert_eq!(request.device_id, device_id());
}

#[test]
fn boundary_formatting_is_redacted_and_invalid_reference_keeps_its_source() {
    let context = context();
    assert!(!format!("{context:?}").contains(DEVICE));

    let mismatch = MappingError::DeviceMismatch {
        expected: device_id(),
        actual: parsed(OTHER_DEVICE),
    };
    for rendered in [format!("{mismatch:?}"), mismatch.to_string()] {
        assert!(!rendered.contains(DEVICE));
        assert!(!rendered.contains(OTHER_DEVICE));
    }

    let negative = MappingError::NegativeDeviceSequence(-73);
    for rendered in [format!("{negative:?}"), negative.to_string()] {
        assert!(!rendered.contains("-73"));
    }

    let lower = rotation_model::RotationModelError::ControlCharacter {
        kind: "command_ref",
    };
    let wrapped = MappingError::InvalidProductReference(lower);
    assert_eq!(wrapped.to_string(), "invalid product reference");
    let source = wrapped
        .source()
        .expect("product validation remains the source");
    assert_eq!(source.to_string(), lower.to_string());
    assert!(
        source
            .downcast_ref::<rotation_model::RotationModelError>()
            .is_some()
    );
}

#[test]
fn acknowledgement_maps_received_and_all_seven_rejection_reasons() {
    let received = map_acknowledgement(&context(), event("ack-event-1"), received_ack(9))
        .expect("valid received ACK");
    assert_eq!(received.event().expose(), "ack-event-1");
    assert_eq!(received.command().expose(), "command-1");
    assert_eq!(received.outcome(), CommandAcknowledgementOutcome::Received);

    for (canonical, expected) in [
        (
            RejectedReason::ArtifactUnavailable,
            CommandRejectionReason::ArtifactUnavailable,
        ),
        (
            RejectedReason::ArtifactDigestMismatch,
            CommandRejectionReason::ArtifactDigestMismatch,
        ),
        (
            RejectedReason::PolicyRejected,
            CommandRejectionReason::PolicyRejected,
        ),
        (
            RejectedReason::GenerationStale,
            CommandRejectionReason::GenerationStale,
        ),
        (
            RejectedReason::FenceEpochStale,
            CommandRejectionReason::FenceEpochStale,
        ),
        (
            RejectedReason::MalformedCommand,
            CommandRejectionReason::MalformedCommand,
        ),
        (
            RejectedReason::DeviceFailure,
            CommandRejectionReason::DeviceFailure,
        ),
    ] {
        let acknowledged =
            map_acknowledgement(&context(), event("ack-event-2"), rejected_ack(canonical))
                .expect("valid rejected ACK");
        assert_eq!(
            acknowledged.outcome(),
            CommandAcknowledgementOutcome::Rejected(expected)
        );
    }
}

#[test]
fn report_preserves_every_public_field() {
    let report = map_report(
        &context(),
        event("report-event-1"),
        report_payload(device_id(), 11),
    )
    .expect("valid report");
    assert_eq!(report.event().expose(), "report-event-1");
    assert_eq!(report.device_sequence().get(), 11);
    assert_eq!(report.observed_generation().get(), 8);
    assert_eq!(report.fence_epoch().get(), 4);
    assert_eq!(report.state_hash().expose(), HASH);
    assert_eq!(report.artifact_digest().expose(), HASH);
    assert_eq!(report.observed_at().get(), 1700);
    assert_eq!(report.expires_at().expect("expiry").get(), 1800);
}

#[test]
fn receipts_map_committed_duplicate_all_stale_and_all_rejected_branches() {
    for payload in [committed_receipt(), duplicate_receipt()] {
        let receipt = map_receipt(&context(), event("receipt-event-1"), payload)
            .expect("valid lineaged receipt");
        let (ApplicationReceiptOutcome::Committed(lineage)
        | ApplicationReceiptOutcome::Duplicate(lineage)) = receipt.outcome()
        else {
            panic!("expected committed or duplicate");
        };
        assert_eq!(lineage.authorization_receipt().expose(), RECEIPT);
        assert_eq!(lineage.desired_generation().get(), 8);
        assert_eq!(receipt.ingress_envelope().expose(), "ingress-1");
        assert_eq!(receipt.event().expose(), "receipt-event-1");
    }

    for (canonical, expected) in [
        (
            StaleReason::GenerationStale,
            ApplicationStaleReason::GenerationStale,
        ),
        (
            StaleReason::FenceEpochStale,
            ApplicationStaleReason::FenceEpochStale,
        ),
        (
            StaleReason::DeviceSequenceStale,
            ApplicationStaleReason::DeviceSequenceStale,
        ),
    ] {
        let receipt = map_receipt(
            &context(),
            event("receipt-event-2"),
            stale_receipt(canonical),
        )
        .expect("valid stale receipt");
        match receipt.outcome() {
            ApplicationReceiptOutcome::Stale { lineage, reason } => {
                assert_eq!(*reason, expected);
                assert_eq!(lineage.authorization_receipt().expose(), RECEIPT);
            }
            _ => panic!("expected stale"),
        }
    }

    for (canonical, expected) in [
        (
            ReceiptRejectionReason::NotAccepted,
            ApplicationRejectionReason::NotAccepted,
        ),
        (
            ReceiptRejectionReason::SchemaRejected,
            ApplicationRejectionReason::SchemaRejected,
        ),
        (
            ReceiptRejectionReason::ProtocolViolation,
            ApplicationRejectionReason::ProtocolViolation,
        ),
    ] {
        let receipt = map_receipt(
            &context(),
            event("receipt-event-3"),
            rejected_receipt(canonical),
        )
        .expect("valid rejected receipt");
        assert_eq!(
            receipt.outcome(),
            &ApplicationReceiptOutcome::Rejected(expected)
        );
    }
}

#[test]
fn boundary_rejects_device_mismatch_negative_sequence_and_invalid_reference() {
    assert!(matches!(
        correlate_command(
            context(),
            CommandRef::try_from("command-envelope-2").expect("fixed envelope"),
            command(parsed(OTHER_DEVICE))
        ),
        Err(MappingError::DeviceMismatch { .. })
    ));
    assert_eq!(
        map_acknowledgement(&context(), event("ack-event-3"), received_ack(-1)),
        Err(MappingError::NegativeDeviceSequence(-1))
    );
    let invalid = AckPayload::ReceivedPayload(ReceivedAck {
        command_id: parsed("command\u{0001}"),
        ..received_ack_payload(1)
    });
    assert!(matches!(
        map_acknowledgement(&context(), event("ack-event-4"), invalid),
        Err(MappingError::InvalidProductReference(_))
    ));

    let mut mismatched_ack = received_ack_payload(1);
    mismatched_ack.device_id = parsed(OTHER_DEVICE);
    assert!(matches!(
        map_acknowledgement(
            &context(),
            event("ack-event-mismatch"),
            AckPayload::ReceivedPayload(mismatched_ack)
        ),
        Err(MappingError::DeviceMismatch { .. })
    ));
    assert!(matches!(
        map_report(
            &context(),
            event("report-event-mismatch"),
            report_payload(parsed(OTHER_DEVICE), 1)
        ),
        Err(MappingError::DeviceMismatch { .. })
    ));
    assert_eq!(
        map_report(
            &context(),
            event("report-event-negative"),
            report_payload(device_id(), -1)
        ),
        Err(MappingError::NegativeDeviceSequence(-1))
    );

    for mut receipt in [
        committed_receipt(),
        duplicate_receipt(),
        stale_receipt(StaleReason::GenerationStale),
        rejected_receipt(ReceiptRejectionReason::NotAccepted),
    ] {
        match &mut receipt {
            ReceiptPayload::CommittedPayload(payload) => payload.device_id = parsed(OTHER_DEVICE),
            ReceiptPayload::DuplicatePayload(payload) => payload.device_id = parsed(OTHER_DEVICE),
            ReceiptPayload::StalePayload(payload) => payload.device_id = parsed(OTHER_DEVICE),
            ReceiptPayload::RejectedPayload(payload) => payload.device_id = parsed(OTHER_DEVICE),
        }
        assert!(matches!(
            map_receipt(&context(), event("receipt-event-mismatch"), receipt),
            Err(MappingError::DeviceMismatch { .. })
        ));
    }
}

fn context() -> MappingContext {
    MappingContext::new(
        RotationCoordinates::new(
            RotationId::try_from("rotation-1").expect("fixed rotation"),
            TenantRef::try_from("tenant-1").expect("fixed tenant"),
            DeviceRef::try_from("product-device-1").expect("fixed product device"),
        ),
        device_id(),
    )
}

fn device_id() -> Uuid {
    parsed(DEVICE)
}
fn event(value: &str) -> EventRef {
    EventRef::try_from(value).expect("fixed event reference")
}
fn nz(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("positive fixture")
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value.parse().expect("valid canonical fixture")
}

fn command(device: Uuid) -> ApplyRequest {
    ApplyRequest {
        artifact_digest: parsed::<ApplyDigest>(HASH),
        artifact_id: parsed::<ArtifactId>("artifact-id-00001"),
        authorization_receipt_id: parsed::<AuthorizationReceiptId>(RECEIPT),
        deadline_epoch_seconds: nz(1900),
        desired_generation: nz(8),
        device_id: device,
        fence_epoch: nz(4),
        intent_digest: parsed::<IntentDigest>(HASH),
        policy_hash: parsed::<PolicyHash>(HASH),
    }
}

fn received_ack_payload(sequence: i64) -> ReceivedAck {
    ReceivedAck {
        command_id: parsed::<ReceivedCommandId>("command-1"),
        desired_generation: nz(8),
        device_id: device_id(),
        device_sequence: sequence,
        fence_epoch: nz(4),
        observed_at: 1700,
        reason: ReceivedReason::None,
        result: ReceivedResult::Received,
    }
}

fn received_ack(sequence: i64) -> AckPayload {
    AckPayload::ReceivedPayload(received_ack_payload(sequence))
}

fn rejected_ack(reason: RejectedReason) -> AckPayload {
    AckPayload::RejectedPayload(RejectedAck {
        command_id: parsed::<RejectedCommandId>("command-1"),
        desired_generation: nz(8),
        device_id: device_id(),
        device_sequence: 10,
        fence_epoch: nz(4),
        observed_at: 1700,
        reason,
        result: RejectedResult::Rejected,
    })
}

fn report_payload(device: Uuid, sequence: i64) -> ReportPayload {
    ReportPayload {
        artifact_digest: parsed::<ReportDigest>(HASH),
        device_id: device,
        device_sequence: sequence,
        expires_at: Some(1800),
        fence_epoch: nz(4),
        observed_at: 1700,
        observed_generation: nz(8),
        state_hash: parsed::<ReportHash>(HASH),
    }
}

fn committed_receipt() -> ReceiptPayload {
    ReceiptPayload::CommittedPayload(CommittedReceipt {
        authorization_receipt_id: parsed(RECEIPT),
        committed_at: 1701,
        desired_generation: nz(8),
        device_id: device_id(),
        ingress_envelope_id: parsed::<CommittedIngress>("ingress-1"),
        outcome: CommittedOutcome::Committed,
        reason: CommittedReason::None,
    })
}

fn duplicate_receipt() -> ReceiptPayload {
    ReceiptPayload::DuplicatePayload(DuplicateReceipt {
        authorization_receipt_id: parsed(RECEIPT),
        committed_at: 1701,
        desired_generation: nz(8),
        device_id: device_id(),
        ingress_envelope_id: parsed::<DuplicateIngress>("ingress-1"),
        outcome: DuplicateOutcome::Duplicate,
        reason: DuplicateReason::AlreadyCommitted,
    })
}

fn stale_receipt(reason: StaleReason) -> ReceiptPayload {
    ReceiptPayload::StalePayload(StaleReceipt {
        authorization_receipt_id: parsed(RECEIPT),
        committed_at: 1701,
        desired_generation: nz(8),
        device_id: device_id(),
        ingress_envelope_id: parsed::<StaleIngress>("ingress-1"),
        outcome: StaleOutcome::Stale,
        reason,
    })
}

fn rejected_receipt(reason: ReceiptRejectionReason) -> ReceiptPayload {
    ReceiptPayload::RejectedPayload(RejectedReceipt {
        committed_at: 1701,
        device_id: device_id(),
        ingress_envelope_id: parsed::<RejectedIngress>("ingress-rejected"),
        outcome: RejectedReceiptOutcome::Rejected,
        reason,
    })
}
