use rotation_model::{KeyUsage, RotationPolicy};
use rss_device_security_client::{
    DiagnosticKind, POLICY_PUT_OPERATION, PolicyResponse, STATUS_GET_OPERATION, StatusResponse,
    decode_policy_response, decode_status_response, prepare_policy_put, prepare_status_get,
};
use uuid::Uuid;

const DEVICE: &str = "0198d5f2-70de-7a2d-b3f4-012345678901";
const RECEIPT: &str = "0198d5f2-70de-7a2d-b3f4-0123456789ab";

fn policy() -> RotationPolicy {
    RotationPolicy::try_new(
        vec![KeyUsage::ClientAuth],
        600,
        vec!["private.device.example".to_owned()],
        3600,
    )
    .expect("valid policy")
}

#[test]
fn descriptors_and_prepared_requests_are_canonical_and_redacted() {
    assert_eq!(POLICY_PUT_OPERATION.method, "PUT");
    assert_eq!(STATUS_GET_OPERATION.method, "GET");
    let device = Uuid::parse_str(DEVICE).expect("device");
    let request = prepare_policy_put(device, 7, Uuid::nil(), &policy()).expect("request");
    assert_eq!(
        request.path(),
        format!("/api/v2/identity/devices/{DEVICE}/certificate-policy")
    );
    let body: serde_json::Value =
        serde_json::from_slice(request.body().expect("body")).expect("JSON");
    assert_eq!(body["expectedGeneration"], 7);
    assert_eq!(body["policy"]["sans"][0], "private.device.example");
    let debug = format!("{request:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(DEVICE));
    assert!(!debug.contains("private.device.example"));
    let status = prepare_status_get(device);
    assert_eq!(status.method(), "GET");
    assert!(status.body().is_none());
}

#[test]
fn policy_decode_is_typed_and_closed_for_all_status_classes() {
    let success = format!(
        r#"{{"data":{{"acceptedGeneration":8,"authorizationReceiptId":"{RECEIPT}","condition":"Reconciling"}}}}"#
    );
    match decode_policy_response(200, success.as_bytes()) {
        PolicyResponse::Accepted(value) => {
            assert_eq!(value.generation(), 8);
            assert_eq!(value.condition(), "Reconciling");
        }
        other @ PolicyResponse::Rejected(_) => panic!("unexpected {other:?}"),
    }
    let validation = br#"{"error":{"code":"ERR_CORE_VALIDATION","details":[],"message":"validation failed","requestId":"request-400","retryable":false}}"#;
    let not_found = br#"{"error":{"code":"ERR_CORE_NOT_FOUND","details":[],"message":"not found","requestId":"request-404","retryable":false}}"#;
    let conflict = br#"{"error":{"code":"ERR_CORE_VERSION_CONFLICT","details":[],"message":"version conflict","requestId":"request-409","retryable":true}}"#;
    for (status, body, kind) in [
        (400, validation.as_slice(), DiagnosticKind::Validation),
        (404, not_found.as_slice(), DiagnosticKind::NotFound),
        (409, conflict.as_slice(), DiagnosticKind::Conflict),
        (
            403,
            b"secret provider reason".as_slice(),
            DiagnosticKind::Forbidden,
        ),
        (429, b"bait".as_slice(), DiagnosticKind::RateLimited),
        (503, b"bait".as_slice(), DiagnosticKind::Upstream),
    ] {
        match decode_policy_response(status, body) {
            PolicyResponse::Rejected(value) => {
                assert_eq!(value.kind(), kind);
                assert!(!format!("{value:?}").contains("bait"));
            }
            other @ PolicyResponse::Accepted(_) => panic!("unexpected {other:?}"),
        }
    }
    match decode_policy_response(200, b"not-json") {
        PolicyResponse::Rejected(value) => assert_eq!(value.kind(), DiagnosticKind::Malformed),
        other @ PolicyResponse::Accepted(_) => panic!("unexpected {other:?}"),
    }
}

#[test]
fn status_decode_preserves_canonical_fields_without_ready_inference() {
    let body = format!(
        r#"{{"data":{{"conditions":[{{"lastTransitionAt":10,"observedGeneration":4,"reason":"AwaitingDevice","status":"Unknown","type":"PendingDevice"}}],"desired":{{"activeCommand":{{"fenceEpoch":2,"state":"queued"}},"authorizationReceiptId":"{RECEIPT}","generation":5}},"observedGeneration":4}}}}"#
    );
    match decode_status_response(200, body.as_bytes()) {
        StatusResponse::Observed(value) => {
            assert_eq!(value.desired_generation, Some(5));
            assert_eq!(value.observed_generation, 4);
            assert_eq!(value.conditions[0].type_, "PendingDevice");
        }
        other @ StatusResponse::Rejected(_) => panic!("unexpected {other:?}"),
    }
}
