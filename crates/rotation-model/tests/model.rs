use std::any::TypeId;

use rotation_model::{
    ApplicationReceiptObservation, ApplicationReceiptRef, AuthorizationReceiptRef,
    CommandAcknowledgement, CommandRef, CredentialReport, CredentialRevision, DeviceRef,
    FenceEpoch, Generation, PrincipalRef, RotationAccepted, RotationCoordinates, RotationId,
    RotationIntent, RotationModelError, TenantRef,
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
fn opaque_references_preserve_product_correlation() {
    let coordinates = coordinates();
    let intent = RotationIntent::new(
        coordinates.clone(),
        PrincipalRef::try_from("operator-9").expect("fixed principal reference"),
    );

    assert_eq!(intent.coordinates(), &coordinates);
    assert_eq!(intent.requested_by().as_str(), "operator-9");
    assert_eq!(coordinates.rotation_id().as_str(), "rotation-17");
    assert_eq!(coordinates.tenant().as_str(), "tenant-a");
    assert_eq!(coordinates.device().as_str(), "device-42");
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
fn product_facts_preserve_scope_and_their_specific_evidence() {
    let coordinates = coordinates();
    let generation = Generation::try_from(8).expect("positive generation");
    let accepted = RotationAccepted::new(
        coordinates.clone(),
        generation,
        AuthorizationReceiptRef::try_from("authorization-receipt-1")
            .expect("fixed receipt reference"),
    );
    let acknowledged = CommandAcknowledgement::new(
        coordinates.clone(),
        generation,
        CommandRef::try_from("command-3").expect("fixed command reference"),
    );
    let reported = CredentialReport::new(
        coordinates.clone(),
        generation,
        CredentialRevision::try_from("credential-revision-4").expect("fixed credential revision"),
    );
    let receipted = ApplicationReceiptObservation::new(
        coordinates.clone(),
        generation,
        ApplicationReceiptRef::try_from("application-receipt-5").expect("fixed receipt reference"),
    );

    assert_eq!(accepted.coordinates(), &coordinates);
    assert_eq!(accepted.generation(), generation);
    assert_eq!(
        accepted.authorization_receipt().as_str(),
        "authorization-receipt-1"
    );
    assert_eq!(acknowledged.coordinates(), &coordinates);
    assert_eq!(acknowledged.generation(), generation);
    assert_eq!(acknowledged.command().as_str(), "command-3");
    assert_eq!(reported.coordinates(), &coordinates);
    assert_eq!(reported.generation(), generation);
    assert_eq!(
        reported.credential_revision().as_str(),
        "credential-revision-4"
    );
    assert_eq!(receipted.coordinates(), &coordinates);
    assert_eq!(receipted.generation(), generation);
    assert_eq!(receipted.receipt().as_str(), "application-receipt-5");
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
