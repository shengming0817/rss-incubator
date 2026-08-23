use std::num::{NonZeroU32, NonZeroUsize};

use reference_device_agent_core::{
    CredentialGeneration, DeviceIdentity, MqttConnectionConfig, TopicSet, ValueError,
};
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
}

#[test]
fn mqtt_coordinates_reject_invalid_host_port_and_client_id() {
    let expiry = NonZeroU32::new(60).expect("expiry");
    let capacity = NonZeroUsize::new(1).expect("capacity");
    assert_eq!(
        MqttConnectionConfig::new("", 8883, "client", expiry, capacity),
        Err(ValueError::InvalidHost)
    );
    assert_eq!(
        MqttConnectionConfig::new("localhost", 0, "client", expiry, capacity),
        Err(ValueError::InvalidPort)
    );
    assert_eq!(
        MqttConnectionConfig::new("localhost", 8883, "", expiry, capacity),
        Err(ValueError::InvalidClientId)
    );
}
