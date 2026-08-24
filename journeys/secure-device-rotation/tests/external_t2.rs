use std::{fmt::Debug, num::NonZeroU64, str::FromStr};

use rotation_model::{DeviceRef, EventRef, RotationCoordinates, RotationId, TenantRef};
use rss_device_security_client::{
    MappingContext, StatusProjection, StatusResponse, decode_policy_response,
    decode_status_response, map_acknowledgement, map_policy_success, map_receipt, map_report,
};
use rss_device_security_contracts::{
    AuthorizationReceiptId,
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
    },
    policy_put::{
        IdentityDeviceCertificatePolicyPutData as PolicyData,
        IdentityDeviceCertificatePolicyPutDataCondition as PolicyCondition,
        IdentityDeviceCertificatePolicyPutResponse as CanonicalPolicyResponse,
    },
};
use secure_device_rotation_t2_journey::{
    JourneyError, verify_forbidden, verify_positive_trace, verify_revoked_no_advance,
};

const DEVICE: &str = "0198d5f2-70de-7a2d-b3f4-012345678901";
const RECEIPT: &str = "0198d5f2-70de-7a2d-b3f4-0123456789ab";
const HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn exact_public_trace_requires_receipt_before_an_upstream_ready_observation() {
    let context = context();
    let accepted = map_policy_success(&context, &policy_response(8)).expect("accepted");
    let ack =
        map_acknowledgement(&context, event("ack-event"), received_ack()).expect("received ACK");
    let after_ack = status(&after_ack_status());
    let report =
        map_report(&context, event("report-event"), report_payload(11)).expect("matching report");
    let receipt = map_receipt(&context, event("receipt-event"), committed_receipt(8))
        .expect("matching receipt");
    let ready = status(&ready_status());

    verify_positive_trace(&accepted, &ack, &after_ack, &report, &receipt, &ready)
        .expect("closed public trace");

    let premature_ready = status(&ready_status());
    assert_eq!(
        verify_positive_trace(&accepted, &ack, &premature_ready, &report, &receipt, &ready,),
        Err(JourneyError::ReadyBeforeReceipt)
    );
    let wrong_receipt = map_receipt(&context, event("wrong-receipt"), committed_receipt(9))
        .expect("well-shaped mismatched receipt");
    assert_eq!(
        verify_positive_trace(&accepted, &ack, &after_ack, &report, &wrong_receipt, &ready),
        Err(JourneyError::LineageMismatch)
    );
}

#[test]
fn positive_trace_binds_pending_command_and_device_sequence_order() {
    let context = context();
    let accepted = map_policy_success(&context, &policy_response(8)).expect("accepted");
    let ack =
        map_acknowledgement(&context, event("ack-event"), received_ack()).expect("received ACK");
    let report =
        map_report(&context, event("report-event"), report_payload(11)).expect("matching report");
    let stale_report = map_report(&context, event("stale-report"), report_payload(10))
        .expect("well-shaped stale report");
    let receipt = map_receipt(&context, event("receipt-event"), committed_receipt(8))
        .expect("matching receipt");
    let ready = status(&ready_status());

    for pending in [
        pending_status("null", 8),
        pending_status(r#"{"fenceEpoch":4,"state":"queued"}"#, 8),
        pending_status(r#"{"fenceEpoch":5,"state":"received"}"#, 8),
    ] {
        assert_eq!(
            verify_positive_trace(
                &accepted,
                &ack,
                &status(&pending),
                &report,
                &receipt,
                &ready,
            ),
            Err(JourneyError::LineageMismatch)
        );
    }
    assert_eq!(
        verify_positive_trace(
            &accepted,
            &ack,
            &status(&after_ack_status()),
            &stale_report,
            &receipt,
            &ready,
        ),
        Err(JourneyError::LineageMismatch)
    );
}

#[test]
fn positive_trace_rejects_every_ready_true_and_incomplete_final_lineage() {
    let context = context();
    let accepted = map_policy_success(&context, &policy_response(8)).expect("accepted");
    let ack =
        map_acknowledgement(&context, event("ack-event"), received_ack()).expect("received ACK");
    let report =
        map_report(&context, event("report-event"), report_payload(11)).expect("matching report");
    let receipt = map_receipt(&context, event("receipt-event"), committed_receipt(8))
        .expect("matching receipt");
    let nonmatching_ready = status(&nonmatching_ready_status(7));
    let final_nonmatching_ready = status(&nonmatching_ready_status(8));

    assert_eq!(
        verify_positive_trace(
            &accepted,
            &ack,
            &nonmatching_ready,
            &report,
            &receipt,
            &status(&ready_status()),
        ),
        Err(JourneyError::ReadyBeforeReceipt)
    );
    assert_eq!(
        verify_positive_trace(
            &accepted,
            &ack,
            &status(&after_ack_status()),
            &report,
            &receipt,
            &final_nonmatching_ready,
        ),
        Err(JourneyError::MissingReadyObservation)
    );
}

#[test]
fn positive_trace_rejects_wrong_outcomes_and_colliding_events() {
    let context = context();
    let accepted = map_policy_success(&context, &policy_response(8)).expect("accepted");
    let received =
        map_acknowledgement(&context, event("ack-event"), received_ack()).expect("received ACK");
    let rejected = map_acknowledgement(&context, event("rejected-event"), revoked_ack())
        .expect("rejected ACK");
    let report =
        map_report(&context, event("report-event"), report_payload(11)).expect("matching report");
    let colliding_report = map_report(&context, event("ack-event"), report_payload(11))
        .expect("matching report with colliding event");
    let committed = map_receipt(&context, event("receipt-event"), committed_receipt(8))
        .expect("matching receipt");
    let duplicate = map_receipt(&context, event("duplicate-event"), duplicate_receipt())
        .expect("duplicate receipt");
    let after_ack = status(&after_ack_status());
    let ready = status(&ready_status());

    assert_eq!(
        verify_positive_trace(
            &accepted, &rejected, &after_ack, &report, &committed, &ready
        ),
        Err(JourneyError::ExpectedReceivedAck)
    );
    assert_eq!(
        verify_positive_trace(
            &accepted, &received, &after_ack, &report, &duplicate, &ready
        ),
        Err(JourneyError::ExpectedCommittedReceipt)
    );
    assert_eq!(
        verify_positive_trace(
            &accepted,
            &received,
            &after_ack,
            &colliding_report,
            &committed,
            &ready,
        ),
        Err(JourneyError::EventIdentityCollision)
    );
}

#[test]
fn stale_fact_is_a_closed_forbidden_without_an_acceptance() {
    let rejected = decode_policy_response(403, b"provider-secret-bait");
    verify_forbidden(&rejected).expect("closed forbidden");
    let accepted_body = format!(
        r#"{{"data":{{"acceptedGeneration":8,"authorizationReceiptId":"{RECEIPT}","condition":"Reconciling"}}}}"#
    );
    assert_eq!(
        verify_forbidden(&decode_policy_response(200, accepted_body.as_bytes())),
        Err(JourneyError::ExpectedForbidden)
    );
}

#[test]
fn revoked_credential_rejection_cannot_advance_or_observe_ready() {
    let context = context();
    let rejected = map_acknowledgement(&context, event("revoked-ack"), revoked_ack())
        .expect("closed policy rejection");
    let pending = status(&after_ack_status());
    verify_revoked_no_advance(&rejected, &pending).expect("no advance");

    let received =
        map_acknowledgement(&context, event("received-ack"), received_ack()).expect("received");
    assert_eq!(
        verify_revoked_no_advance(&received, &pending),
        Err(JourneyError::ExpectedRevokedRejection)
    );
    assert_eq!(
        verify_revoked_no_advance(&rejected, &status(&ready_status())),
        Err(JourneyError::ReadyAfterRevocation)
    );
    assert_eq!(
        verify_revoked_no_advance(
            &rejected,
            &status(&pending_status(r#"{"fenceEpoch":4,"state":"received"}"#, 9,)),
        ),
        Err(JourneyError::LineageMismatch)
    );
    assert_eq!(
        verify_revoked_no_advance(&rejected, &status(&nonmatching_ready_status(7))),
        Err(JourneyError::ReadyAfterRevocation)
    );
}

fn context() -> MappingContext {
    MappingContext::new(
        RotationCoordinates::new(
            RotationId::try_from("rotation-1").expect("rotation"),
            TenantRef::try_from("tenant-1").expect("tenant"),
            DeviceRef::try_from("device-1").expect("device"),
        ),
        parsed(DEVICE),
    )
}

fn event(value: &str) -> EventRef {
    EventRef::try_from(value).expect("event")
}

fn nz(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("positive")
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value.parse().expect("canonical fixture")
}

fn policy_response(generation: u64) -> CanonicalPolicyResponse {
    CanonicalPolicyResponse {
        data: PolicyData {
            accepted_generation: nz(generation),
            authorization_receipt_id: parsed::<AuthorizationReceiptId>(RECEIPT),
            condition: PolicyCondition::Reconciling,
        },
    }
}

fn received_ack() -> AckPayload {
    AckPayload::ReceivedPayload(ReceivedAck {
        command_id: parsed::<ReceivedCommandId>("command-1"),
        desired_generation: nz(8),
        device_id: parsed(DEVICE),
        device_sequence: 10,
        fence_epoch: nz(4),
        observed_at: 1700,
        reason: ReceivedReason::None,
        result: ReceivedResult::Received,
    })
}

fn revoked_ack() -> AckPayload {
    AckPayload::RejectedPayload(RejectedAck {
        command_id: parsed::<RejectedCommandId>("command-1"),
        desired_generation: nz(8),
        device_id: parsed(DEVICE),
        device_sequence: 10,
        fence_epoch: nz(4),
        observed_at: 1700,
        reason: RejectedReason::PolicyRejected,
        result: RejectedResult::Rejected,
    })
}

fn report_payload(device_sequence: i64) -> ReportPayload {
    ReportPayload {
        artifact_digest: parsed::<ReportDigest>(HASH),
        device_id: parsed(DEVICE),
        device_sequence,
        expires_at: Some(1800),
        fence_epoch: nz(4),
        observed_at: 1701,
        observed_generation: nz(8),
        state_hash: parsed::<ReportHash>(HASH),
    }
}

fn duplicate_receipt() -> ReceiptPayload {
    ReceiptPayload::DuplicatePayload(DuplicateReceipt {
        authorization_receipt_id: parsed(RECEIPT),
        committed_at: 1702,
        desired_generation: nz(8),
        device_id: parsed(DEVICE),
        ingress_envelope_id: parsed::<DuplicateIngress>("ingress-1"),
        outcome: DuplicateOutcome::Duplicate,
        reason: DuplicateReason::AlreadyCommitted,
    })
}

fn committed_receipt(generation: u64) -> ReceiptPayload {
    ReceiptPayload::CommittedPayload(CommittedReceipt {
        authorization_receipt_id: parsed(RECEIPT),
        committed_at: 1702,
        desired_generation: nz(generation),
        device_id: parsed(DEVICE),
        ingress_envelope_id: parsed::<CommittedIngress>("ingress-1"),
        outcome: CommittedOutcome::Committed,
        reason: CommittedReason::None,
    })
}

fn status(body: &str) -> StatusProjection {
    match decode_status_response(200, body.as_bytes()) {
        StatusResponse::Observed(value) => value,
        StatusResponse::Rejected(value) => panic!("unexpected status diagnostic: {value:?}"),
    }
}

fn after_ack_status() -> String {
    pending_status(r#"{"fenceEpoch":4,"state":"received"}"#, 8)
}

fn pending_status(active_command: &str, desired_generation: u64) -> String {
    format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":1700,"observedGeneration":7,"reason":"AwaitingDevice","status":"Unknown","type":"PendingDevice"}}],"desired":{{"activeCommand":{active_command},"authorizationReceiptId":"{RECEIPT}","generation":{desired_generation}}},"observedGeneration":7}}}}"#
    )
}

fn nonmatching_ready_status(observed_generation: u64) -> String {
    format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":1701,"observedGeneration":7,"reason":"StateDrift","status":"True","type":"Ready"}}],"desired":{{"activeCommand":{{"fenceEpoch":4,"state":"received"}},"authorizationReceiptId":"{RECEIPT}","generation":8}},"observedGeneration":{observed_generation}}}}}"#
    )
}

fn ready_status() -> String {
    format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":1703,"observedGeneration":8,"reason":"StateMatches","status":"True","type":"Ready"}}],"desired":{{"activeCommand":null,"authorizationReceiptId":"{RECEIPT}","generation":8}},"observedGeneration":8}}}}"#
    )
}
