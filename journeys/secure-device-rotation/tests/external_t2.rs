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
    let after_ack = status(&queued_status());
    let report =
        map_report(&context, event("report-event"), report_payload()).expect("matching report");
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
    let pending = status(&queued_status());
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

fn report_payload() -> ReportPayload {
    ReportPayload {
        artifact_digest: parsed::<ReportDigest>(HASH),
        device_id: parsed(DEVICE),
        device_sequence: 11,
        expires_at: Some(1800),
        fence_epoch: nz(4),
        observed_at: 1701,
        observed_generation: nz(8),
        state_hash: parsed::<ReportHash>(HASH),
    }
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

fn queued_status() -> String {
    format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":1700,"observedGeneration":7,"reason":"AwaitingDevice","status":"Unknown","type":"PendingDevice"}}],"desired":{{"activeCommand":{{"fenceEpoch":4,"state":"received"}},"authorizationReceiptId":"{RECEIPT}","generation":8}},"observedGeneration":7}}}}"#
    )
}

fn ready_status() -> String {
    format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":1703,"observedGeneration":8,"reason":"StateMatches","status":"True","type":"Ready"}}],"desired":{{"activeCommand":null,"authorizationReceiptId":"{RECEIPT}","generation":8}},"observedGeneration":8}}}}"#
    )
}
