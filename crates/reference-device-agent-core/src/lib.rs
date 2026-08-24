#![doc = "Device-local durability and concrete MQTT transport for the reference rotation agent."]

mod agent;
mod assertion;
mod catalog;
mod material;
mod mqtt;
mod state;
mod types;

pub use agent::{AgentConfig, AgentError, ReferenceDeviceAgent};
pub use assertion::{BrokerAssertionError, BrokerAssertionVerifier};
pub use catalog::{ArtifactCatalog, CatalogError, compute_artifact_digest};
pub use material::CredentialError;
pub use mqtt::{
    CommandDelivery, MqttError, MqttEvent, MqttOutbound, MqttOutboundKind, MqttSession,
};
pub use state::StoreError;
pub use types::{
    AckFact, ApplyOutcome, ArtifactId, CommandId, CommandRejection, CredentialFiles,
    CredentialGeneration, DeviceCommand, DeviceIdentity, MqttConnectionConfig, OutboundFact,
    RecoveryCommandScope, ReportFact, Sha256Digest, TopicSet, ValueError,
};
