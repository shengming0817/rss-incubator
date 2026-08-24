#![doc = r#"Device-local durability and broker-assertion primitives for the reference rotation agent.

Raw transport capabilities are not part of the downstream API. In particular, an application
cannot synthesize an arbitrary MQTT payload:

```compile_fail
use reference_device_agent_core::{MqttOutbound, MqttOutboundKind};

let _bypass = MqttOutbound::new(
    MqttOutboundKind::CommandAcknowledged,
    "forged-event".to_owned(),
    b"{}".to_vec(),
);
```

Nor can receipt of a delivery alone authorize its broker settlement:

```compile_fail
use reference_device_agent_core::{CommandDelivery, MqttSession};

async fn bypass(session: &mut MqttSession, delivery: Box<CommandDelivery>) {
    session.acknowledge_command(delivery, None).await.unwrap();
}
```
"#]

mod agent;
mod assertion;
mod catalog;
mod material;
mod state;
mod types;

pub use agent::{AgentConfig, AgentError, ReferenceDeviceAgent};
pub use assertion::{BrokerAssertionError, BrokerAssertionVerifier};
pub use catalog::{ArtifactCatalog, CatalogError, compute_artifact_digest};
pub use material::CredentialError;
pub use state::StoreError;
pub use types::{
    AckFact, ApplyOutcome, ArtifactId, CommandId, CommandRejection, CredentialFiles,
    CredentialGeneration, DeviceCommand, DeviceIdentity, MqttConnectionConfig, OutboundFact,
    RecoveryCommandScope, ReportFact, Sha256Digest, TopicSet, ValueError,
};
