#![doc = "Device-local durability and concrete MQTT transport for the reference rotation agent."]

mod agent;
mod catalog;
mod material;
mod mqtt;
mod state;
mod types;

pub use agent::{AgentConfig, AgentError, ReferenceDeviceAgent};
pub use catalog::{ArtifactCatalog, CatalogError, compute_artifact_digest};
pub use material::CredentialError;
pub use mqtt::{CommandDelivery, MqttError, MqttEvent, MqttSession};
pub use state::StoreError;
pub use types::{
    AckFact, ApplyOutcome, ArtifactId, CommandId, CommandRejection, CredentialFiles,
    CredentialGeneration, DeviceCommand, DeviceIdentity, MqttConnectionConfig, OutboundFact,
    ReportFact, Sha256Digest, TopicSet, ValueError,
};
