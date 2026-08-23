mod config;
mod wire;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::RuntimeConfig;
use reference_device_agent_core::{MqttEvent, MqttSession, ReferenceDeviceAgent, TopicSet};
use wire::{OutboundKind, decode_command, encode_outbound};

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("usage: reference-device-agent /absolute/path/to/config.json")]
    Usage,
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error("reference device agent failed closed")]
    Agent,
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    let mut arguments = std::env::args_os().skip(1);
    let config_path = PathBuf::from(arguments.next().ok_or(MainError::Usage)?);
    if arguments.next().is_some() || !config_path.is_absolute() {
        return Err(MainError::Usage);
    }
    let runtime = RuntimeConfig::load(&config_path)?;
    let mut agent =
        ReferenceDeviceAgent::open(runtime.agent, now()).map_err(|_| MainError::Agent)?;

    loop {
        if run_session(&runtime.mqtt, &mut agent).await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn run_session(
    mqtt: &reference_device_agent_core::MqttConnectionConfig,
    agent: &mut ReferenceDeviceAgent,
) -> Result<(), MainError> {
    let session_identity = agent.current_identity().map_err(|_| MainError::Agent)?;
    let session_topics = TopicSet::new(&session_identity);
    let mut session = MqttSession::new(mqtt, &agent.current_credentials(), session_topics.clone())
        .map_err(|_| MainError::Agent)?;
    let mut publish_pending = false;
    let mut reconnect_after_unsubscribe = false;

    loop {
        if !publish_pending
            && !reconnect_after_unsubscribe
            && let Some(outbound) = agent.next_outbound()
        {
            let encoded =
                encode_outbound(&session_identity, outbound).map_err(|_| MainError::Agent)?;
            let topic = match encoded.kind {
                OutboundKind::Acknowledgement => session_topics.command_acknowledged(),
                OutboundKind::Report => session_topics.certificate_reported(),
            };
            session
                .publish(&encoded.event_id, topic, encoded.payload)
                .await
                .map_err(|_| MainError::Agent)?;
            publish_pending = true;
        }

        match session.poll().await.map_err(|_| MainError::Agent)? {
            MqttEvent::Connected { .. } => {
                if let Some(revision) = agent.reconnect_revision() {
                    agent
                        .mark_current_credential_connected(revision)
                        .map_err(|_| MainError::Agent)?;
                }
                session.subscribe().await.map_err(|_| MainError::Agent)?;
            }
            MqttEvent::Command(delivery) => {
                let identity = agent.current_identity().map_err(|_| MainError::Agent)?;
                let command = decode_command(&identity, delivery.command_id(), delivery.payload())
                    .map_err(|_| MainError::Agent)?;
                agent
                    .apply_command(delivery.topic(), &command, now())
                    .map_err(|_| MainError::Agent)?;
                session
                    .acknowledge_command(&delivery)
                    .await
                    .map_err(|_| MainError::Agent)?;
            }
            MqttEvent::OutboundAcknowledged { event_id } => {
                agent
                    .confirm_outbound(&event_id)
                    .map_err(|_| MainError::Agent)?;
                publish_pending = false;
                if agent.reconnect_revision().is_some() {
                    session
                        .unsubscribe_command()
                        .await
                        .map_err(|_| MainError::Agent)?;
                    reconnect_after_unsubscribe = true;
                }
            }
            MqttEvent::Unsubscribed if reconnect_after_unsubscribe => return Ok(()),
            MqttEvent::Subscribed | MqttEvent::Unsubscribed | MqttEvent::TransportProgress => {}
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
