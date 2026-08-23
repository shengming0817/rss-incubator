use std::path::PathBuf;

use reference_device_agent_core::{CredentialGeneration, DeviceIdentity, TopicSet};
use uuid::Uuid;

#[test]
fn exact_topics_bind_tenant_device_and_credential_generation() {
    let identity = DeviceIdentity::new(
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("tenant"),
        Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("device"),
        CredentialGeneration::try_from(7).expect("generation"),
    );
    let topics = TopicSet::new(&identity);

    assert_eq!(
        topics.command(),
        "rss/v1/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000101/7/downlink/identity.commands.apply-device-certificate"
    );
    assert_eq!(
        topics.command_acknowledged(),
        "rss/v1/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000101/7/uplink/identity.device-command-acked"
    );
    assert!(
        !topics
            .command()
            .contains("/identity.apply-device-certificate")
    );
}

#[test]
fn credential_generation_cannot_be_zero() {
    assert!(CredentialGeneration::try_from(0).is_err());
}

#[test]
fn credential_paths_are_not_accepted_as_artifact_ids() {
    assert!(reference_device_agent_core::ArtifactId::try_from("../../private.key").is_err());
    assert!(
        reference_device_agent_core::ArtifactId::try_from("fixture-device-certificate-0001")
            .is_ok()
    );
    let _ = PathBuf::from("unused");
}
