mod config;
mod wire;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::RuntimeConfig;
use reference_device_agent_core::{
    AgentError, ApplyOutcome, MqttError, MqttEvent, MqttSession, ReferenceDeviceAgent, TopicSet,
};
use wire::{OutboundKind, decode_command, encode_outbound};

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("usage: reference-device-agent /absolute/path/to/config.json")]
    Usage,
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error(transparent)]
    Mqtt(#[from] MqttError),
    #[error(transparent)]
    Wire(#[from] wire::WireError),
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    let mut arguments = std::env::args_os().skip(1);
    let config_path = PathBuf::from(arguments.next().ok_or(MainError::Usage)?);
    if arguments.next().is_some() || !config_path.is_absolute() {
        return Err(MainError::Usage);
    }
    let runtime = RuntimeConfig::load(&config_path)?;
    let mut agent = ReferenceDeviceAgent::open(runtime.agent, now())?;
    let mut retry_delay = Duration::from_secs(1);

    loop {
        match run_session(&runtime.mqtt, &mut agent, &mut retry_delay).await {
            Ok(()) => retry_delay = Duration::from_secs(1),
            Err(SessionError::Mqtt(error)) if error.is_retryable() => {
                eprintln!(
                    "reference-device-agent event=mqtt_transport_retry kind={} delay_milliseconds={}",
                    error.kind(),
                    retry_delay.as_millis()
                );
                tokio::time::sleep(retry_delay + retry_jitter()).await;
                retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(30));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn run_session(
    mqtt: &reference_device_agent_core::MqttConnectionConfig,
    agent: &mut ReferenceDeviceAgent,
    retry_delay: &mut Duration,
) -> Result<(), SessionError> {
    let session_identity = agent.current_identity()?;
    let session_topics = TopicSet::new(&session_identity);
    let mut session = MqttSession::new(mqtt, &agent.current_credentials(), session_topics.clone())?;
    let mut publish_pending = None;
    let mut reconnect_after_unsubscribe = false;
    let mut subscribed = false;
    let mut pending_command_ack = None;

    loop {
        if publish_pending.is_none()
            && !reconnect_after_unsubscribe
            && let Some(outbound) = agent.next_outbound()
        {
            let encoded = encode_outbound(&session_identity, outbound)?;
            let topic = match encoded.kind {
                OutboundKind::Acknowledgement => session_topics.command_acknowledged(),
                OutboundKind::Report => session_topics.certificate_reported(),
            };
            session
                .publish(&encoded.event_id, topic, encoded.payload)
                .await?;
            publish_pending = Some(encoded.kind);
        }

        match session.poll().await? {
            MqttEvent::Connected { .. } => {
                *retry_delay = Duration::from_secs(1);
                let reconnecting = agent.reconnect_revision()?;
                if let Some(revision) = reconnecting {
                    agent.mark_current_credential_connected(revision)?;
                }
                if !agent.rotation_in_flight() {
                    session.subscribe().await?;
                }
            }
            MqttEvent::Subscribed => subscribed = true,
            MqttEvent::Command(delivery) => {
                let identity = agent.current_identity()?;
                let command = decode_command(&identity, delivery.command_id(), delivery.payload())?;
                let outcome = agent.apply_command(delivery.topic(), &command, now())?;
                if outcome == ApplyOutcome::Accepted {
                    session.unsubscribe_command().await?;
                    pending_command_ack = Some(delivery);
                } else {
                    session.acknowledge_command(&delivery).await?;
                }
            }
            MqttEvent::OutboundAcknowledged { event_id } => {
                let kind = publish_pending.take().ok_or(AgentError::UnknownOutbound)?;
                agent.confirm_outbound(&event_id)?;
                if agent.reconnect_revision()?.is_some() {
                    if subscribed {
                        session.unsubscribe_command().await?;
                        reconnect_after_unsubscribe = true;
                    } else {
                        return Ok(());
                    }
                } else if matches!(kind, OutboundKind::Report) && !subscribed {
                    session.subscribe().await?;
                }
            }
            MqttEvent::Unsubscribed if pending_command_ack.is_some() => {
                subscribed = false;
                let delivery = pending_command_ack.take().expect("checked pending ACK");
                session.acknowledge_command(&delivery).await?;
            }
            MqttEvent::Unsubscribed if reconnect_after_unsubscribe => return Ok(()),
            MqttEvent::Unsubscribed | MqttEvent::TransportProgress => {}
        }
    }
}

fn retry_jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    Duration::from_millis(u64::from(nanos % 251))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
