use std::any::TypeId;

use rotation_model::{
    AcceptanceCondition, ApplicationReceiptObservation, ApplicationReceiptOutcome,
    ApplicationRejectionReason, ApplicationStaleReason, ArtifactDigest, AuthorizationReceiptRef,
    CommandAckPosition, CommandAcknowledgement, CommandAcknowledgementOutcome, CommandRef,
    CommandRejectionReason, CredentialReport, DeviceRef, DeviceSequence, EventRef, FenceEpoch,
    Generation, IngressEnvelopeRef, PrincipalRef, ReceiptLineage, ReportPosition, RotationAccepted,
    RotationCoordinates, RotationId, RotationIntent, RotationModelError, StateHash, TenantRef,
    UnixTimestamp,
};

#[test]
fn rotation_policy_is_closed_validated_and_redacted() {
    use rotation_model::{KeyUsage, RotationPolicy};
    let policy = RotationPolicy::try_new(
        vec![KeyUsage::ClientAuth, KeyUsage::ServerAuth],
        600,
        vec!["secret.device.example".to_owned()],
        3600,
    )
    .expect("valid policy");
    assert_eq!(policy.key_usages().len(), 2);
    assert_eq!(policy.sans().len(), 1);
    let debug = format!("{policy:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("secret.device.example"));
    assert!(RotationPolicy::try_new(vec![], 600, vec![], 3600).is_err());
    assert!(
        RotationPolicy::try_new(
            vec![KeyUsage::ClientAuth, KeyUsage::ClientAuth],
            600,
            vec![],
            3600
        )
        .is_err()
    );
}

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
        authorization_receipt(),
        Generation::try_from(8).expect("positive generation"),
        AcceptanceCondition::PendingDevice,
    );

    assert_eq!(accepted.coordinates(), &coordinates());
    assert_eq!(
        accepted.authorization_receipt().expose(),
        "0198d5f2-70de-7a2d-b3f4-0123456789ab"
    );
    assert_eq!(accepted.accepted_generation().get(), 8);
    assert_eq!(accepted.condition(), AcceptanceCondition::PendingDevice);

    let formatted = format!("{accepted:?}");
    assert!(!formatted.contains("0198d5f2-70de-7a2d-b3f4-0123456789ab"));
    assert!(formatted.contains("[REDACTED]"));
}

#[test]
fn acknowledgement_preserves_fence_sequence_outcome_and_time() {
    let acknowledged = CommandAcknowledgement::new(
        coordinates(),
        EventRef::try_from("ack-event-11").expect("fixed ACK event reference"),
        CommandRef::try_from("command-3").expect("fixed command reference"),
        CommandAckPosition::new(
            Generation::try_from(8).expect("positive generation"),
            FenceEpoch::try_from(2).expect("positive fence"),
            DeviceSequence::new(13),
            UnixTimestamp::new(1_725_000_000),
        ),
        CommandAcknowledgementOutcome::Rejected(CommandRejectionReason::FenceEpochStale),
    );

    assert_eq!(acknowledged.event().expose(), "ack-event-11");
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
        EventRef::try_from("report-event-12").expect("fixed report event reference"),
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

    assert_eq!(report.event().expose(), "report-event-12");
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
fn lineaged_application_receipts_preserve_receipt_generation_and_reason() {
    let outcomes = [
        ApplicationReceiptOutcome::Committed(application_lineage()),
        ApplicationReceiptOutcome::Duplicate(application_lineage()),
        ApplicationReceiptOutcome::Stale {
            lineage: application_lineage(),
            reason: ApplicationStaleReason::DeviceSequenceStale,
        },
    ];

    for outcome in outcomes {
        let receipt = ApplicationReceiptObservation::new(
            coordinates(),
            EventRef::try_from("receipt-event-13").expect("fixed receipt event reference"),
            IngressEnvelopeRef::try_from("envelope-5").expect("fixed ingress envelope"),
            outcome,
            UnixTimestamp::new(1_725_000_020),
        );

        let lineage = match receipt.outcome() {
            ApplicationReceiptOutcome::Committed(lineage)
            | ApplicationReceiptOutcome::Duplicate(lineage) => lineage,
            ApplicationReceiptOutcome::Stale { lineage, reason } => {
                assert_eq!(*reason, ApplicationStaleReason::DeviceSequenceStale);
                lineage
            }
            ApplicationReceiptOutcome::Rejected(_) => panic!("expected lineaged outcome"),
        };
        assert_eq!(
            lineage.authorization_receipt().expose(),
            "0198d5f2-70de-7a2d-b3f4-0123456789ab"
        );
        assert_eq!(lineage.desired_generation().get(), 8);
        assert_eq!(receipt.ingress_envelope().expose(), "envelope-5");
        assert_eq!(receipt.event().expose(), "receipt-event-13");
        assert_eq!(receipt.committed_at().get(), 1_725_000_020);

        let formatted = format!("{receipt:?}");
        assert!(!formatted.contains("0198d5f2-70de-7a2d-b3f4-0123456789ab"));
        assert!(formatted.contains("[REDACTED]"));
    }
}

#[test]
fn rejected_application_receipt_carries_only_its_rejection_reason() {
    let receipt = ApplicationReceiptObservation::new(
        coordinates(),
        EventRef::try_from("receipt-event-14").expect("fixed receipt event reference"),
        IngressEnvelopeRef::try_from("envelope-6").expect("fixed ingress envelope"),
        ApplicationReceiptOutcome::Rejected(ApplicationRejectionReason::NotAccepted),
        UnixTimestamp::new(1_725_000_030),
    );

    match receipt.outcome() {
        ApplicationReceiptOutcome::Rejected(reason) => {
            assert_eq!(*reason, ApplicationRejectionReason::NotAccepted);
        }
        ApplicationReceiptOutcome::Committed(_)
        | ApplicationReceiptOutcome::Duplicate(_)
        | ApplicationReceiptOutcome::Stale { .. } => panic!("expected rejected outcome"),
    }
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

#[test]
fn event_command_and_ingress_envelope_identities_are_distinct_types() {
    assert_ne!(TypeId::of::<EventRef>(), TypeId::of::<CommandRef>());
    assert_ne!(TypeId::of::<EventRef>(), TypeId::of::<IngressEnvelopeRef>());
    assert_ne!(
        TypeId::of::<CommandRef>(),
        TypeId::of::<IngressEnvelopeRef>()
    );
}

#[test]
fn event_identities_are_redacted_with_their_facts() {
    let acknowledged = CommandAcknowledgement::new(
        coordinates(),
        EventRef::try_from("secret-ack-event").expect("fixed event reference"),
        CommandRef::try_from("secret-command").expect("fixed command reference"),
        CommandAckPosition::new(
            Generation::try_from(8).expect("positive generation"),
            FenceEpoch::try_from(2).expect("positive fence"),
            DeviceSequence::new(13),
            UnixTimestamp::new(1_725_000_000),
        ),
        CommandAcknowledgementOutcome::Received,
    );

    let formatted = format!("{acknowledged:?}");
    assert!(!formatted.contains("secret-ack-event"));
    assert!(!formatted.contains("secret-command"));
    assert!(formatted.contains("[REDACTED]"));
}

fn coordinates() -> RotationCoordinates {
    RotationCoordinates::new(
        RotationId::try_from("rotation-17").expect("fixed rotation ID"),
        TenantRef::try_from("tenant-a").expect("fixed tenant reference"),
        DeviceRef::try_from("device-42").expect("fixed device reference"),
    )
}

fn authorization_receipt() -> AuthorizationReceiptRef {
    AuthorizationReceiptRef::try_from("0198d5f2-70de-7a2d-b3f4-0123456789ab")
        .expect("fixed authorization receipt reference")
}

fn application_lineage() -> ReceiptLineage {
    ReceiptLineage::new(
        authorization_receipt(),
        Generation::try_from(8).expect("positive generation"),
    )
}
