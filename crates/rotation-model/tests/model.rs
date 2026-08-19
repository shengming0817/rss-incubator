use std::any::TypeId;

use rotation_model::{
    AcceptanceCondition, ApplicationReceiptObservation, ApplicationReceiptOutcome,
    ApplicationStaleReason, ArtifactDigest, CommandAckPosition, CommandAcknowledgement,
    CommandAcknowledgementOutcome, CommandRef, CommandRejectionReason, CredentialReport, DeviceRef,
    DeviceSequence, FenceEpoch, Generation, IngressEnvelopeRef, PrincipalRef, ReportPosition,
    RotationAccepted, RotationCoordinates, RotationId, RotationIntent, RotationModelError,
    StateHash, TenantRef, UnixTimestamp,
};

#[test]
fn opaque_references_reject_blank_and_control_characters() {
    assert_eq!(
        RotationId::try_from("   "),
        Err(RotationModelError::EmptyReference {
            kind: "rotation_id"
        })
    );
    assert_eq!(
        TenantRef::try_from("tenant\nother"),
        Err(RotationModelError::ControlCharacter { kind: "tenant_ref" })
    );
}

#[test]
fn opaque_references_require_explicit_exposure_and_redact_debug_output() {
    let coordinates = coordinates();
    let intent = RotationIntent::new(
        coordinates.clone(),
        PrincipalRef::try_from("operator-9").expect("fixed principal reference"),
    );

    assert_eq!(intent.requested_by().expose(), "operator-9");
    assert_eq!(coordinates.rotation_id().expose(), "rotation-17");
    assert_eq!(coordinates.tenant().expose(), "tenant-a");
    assert_eq!(coordinates.device().expose(), "device-42");

    let formatted = format!("{intent:?}");
    for secret in ["operator-9", "rotation-17", "tenant-a", "device-42"] {
        assert!(!formatted.contains(secret));
    }
    assert!(formatted.contains("[REDACTED]"));
}

#[test]
fn generation_and_fence_epoch_are_positive() {
    assert_eq!(
        Generation::try_from(0),
        Err(RotationModelError::ZeroGeneration)
    );
    assert_eq!(
        FenceEpoch::try_from(0),
        Err(RotationModelError::ZeroFenceEpoch)
    );
    assert_eq!(
        Generation::try_from(7).expect("positive generation").get(),
        7
    );
    assert_eq!(FenceEpoch::try_from(3).expect("positive fence").get(), 3);
}

#[test]
fn accepted_rotation_matches_the_public_acceptance_shape() {
    let accepted = RotationAccepted::new(
        coordinates(),
        Generation::try_from(8).expect("positive generation"),
        AcceptanceCondition::PendingDevice,
    );

    assert_eq!(accepted.coordinates(), &coordinates());
    assert_eq!(accepted.accepted_generation().get(), 8);
    assert_eq!(accepted.condition(), AcceptanceCondition::PendingDevice);
}

#[test]
fn acknowledgement_preserves_fence_sequence_outcome_and_time() {
    let acknowledged = CommandAcknowledgement::new(
        coordinates(),
        CommandRef::try_from("command-3").expect("fixed command reference"),
        CommandAckPosition::new(
            Generation::try_from(8).expect("positive generation"),
            FenceEpoch::try_from(2).expect("positive fence"),
            DeviceSequence::new(13),
            UnixTimestamp::new(1_725_000_000),
        ),
        CommandAcknowledgementOutcome::Rejected(CommandRejectionReason::FenceEpochStale),
    );

    assert_eq!(acknowledged.command().expose(), "command-3");
    assert_eq!(acknowledged.desired_generation().get(), 8);
    assert_eq!(acknowledged.fence_epoch().get(), 2);
    assert_eq!(acknowledged.device_sequence().get(), 13);
    assert_eq!(
        acknowledged.outcome(),
        CommandAcknowledgementOutcome::Rejected(CommandRejectionReason::FenceEpochStale)
    );
    assert_eq!(acknowledged.observed_at().get(), 1_725_000_000);
}

#[test]
fn credential_report_preserves_observed_state_discriminants() {
    let report = CredentialReport::new(
        coordinates(),
        ReportPosition::new(
            Generation::try_from(8).expect("positive generation"),
            FenceEpoch::try_from(2).expect("positive fence"),
            DeviceSequence::new(14),
            UnixTimestamp::new(1_725_000_010),
        ),
        StateHash::try_from("sha256:state").expect("fixed state hash"),
        ArtifactDigest::try_from("sha256:artifact").expect("fixed artifact digest"),
        Some(UnixTimestamp::new(1_725_100_000)),
    );

    assert_eq!(report.observed_generation().get(), 8);
    assert_eq!(report.fence_epoch().get(), 2);
    assert_eq!(report.device_sequence().get(), 14);
    assert_eq!(report.state_hash().expose(), "sha256:state");
    assert_eq!(report.artifact_digest().expose(), "sha256:artifact");
    assert_eq!(
        report.expires_at().map(UnixTimestamp::get),
        Some(1_725_100_000)
    );
    assert_eq!(report.observed_at().get(), 1_725_000_010);
}

#[test]
fn application_receipt_has_no_generation_and_preserves_its_outcome() {
    let receipt = ApplicationReceiptObservation::new(
        coordinates(),
        IngressEnvelopeRef::try_from("envelope-5").expect("fixed ingress envelope"),
        ApplicationReceiptOutcome::Stale(ApplicationStaleReason::DeviceSequenceStale),
        UnixTimestamp::new(1_725_000_020),
    );

    assert_eq!(receipt.ingress_envelope().expose(), "envelope-5");
    assert_eq!(
        receipt.outcome(),
        ApplicationReceiptOutcome::Stale(ApplicationStaleReason::DeviceSequenceStale)
    );
    assert_eq!(receipt.committed_at().get(), 1_725_000_020);
}

#[test]
fn acknowledgement_report_and_receipt_are_distinct_fact_types() {
    assert_ne!(
        TypeId::of::<CommandAcknowledgement>(),
        TypeId::of::<CredentialReport>()
    );
    assert_ne!(
        TypeId::of::<CommandAcknowledgement>(),
        TypeId::of::<ApplicationReceiptObservation>()
    );
    assert_ne!(
        TypeId::of::<CredentialReport>(),
        TypeId::of::<ApplicationReceiptObservation>()
    );
}

fn coordinates() -> RotationCoordinates {
    RotationCoordinates::new(
        RotationId::try_from("rotation-17").expect("fixed rotation ID"),
        TenantRef::try_from("tenant-a").expect("fixed tenant reference"),
        DeviceRef::try_from("device-42").expect("fixed device reference"),
    )
}
