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
                    "reference-device-agent event=mqtt_transport_retry kind={} delay_milliseconds={} error={error}",
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

// Keeping the event ordering in one loop makes broker acknowledgements and reconnect exits auditable.
#[allow(clippy::too_many_lines)]
async fn run_session(
    mqtt: &reference_device_agent_core::MqttConnectionConfig,
    agent: &mut ReferenceDeviceAgent,
    retry_delay: &mut Duration,
) -> Result<(), SessionError> {
    let session_identity = agent.current_identity()?;
    let session_topics = TopicSet::new(&session_identity);
    let recovery_topic = agent.pending_command_topic().map(str::to_owned);
    let mut session = MqttSession::new(
        mqtt,
        &agent.current_credentials(),
        session_topics.clone(),
        recovery_topic.clone(),
    )?;
    let mut publish_pending = None;
    let mut subscribed = false;
    let mut connected = false;
    let mut connected_at = None;
    let mut unsubscribe_pending = false;
    let mut pending_command_ack = None;
    let mut recovery_delivery_observed = false;
    let mut reconnect_ready = false;

    loop {
        if connected
            && publish_pending.is_none()
            && !reconnect_ready
            && !unsubscribe_pending
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

        let event = session.poll().await;
        if connected_at.is_some_and(|connected_at: tokio::time::Instant| {
            connected_at.elapsed() >= Duration::from_mins(1)
        }) {
            *retry_delay = Duration::from_secs(1);
        }
        match event? {
            MqttEvent::Connected { session_present: _ } => {
                connected = true;
                connected_at = Some(tokio::time::Instant::now());
                subscribed = false;
                let reconnecting = agent.reconnect_revision()?;
                if let Some(revision) = reconnecting {
                    agent.mark_current_credential_connected(revision)?;
                }
                if let Some(topic) = recovery_topic.as_deref() {
                    session.unsubscribe_topic(topic).await?;
                    unsubscribe_pending = true;
                } else if !agent.rotation_in_flight() {
                    session.subscribe().await?;
                }
            }
            MqttEvent::Subscribed => subscribed = true,
            MqttEvent::Command(delivery) => {
                if recovery_topic.as_deref() == Some(delivery.topic()) {
                    recovery_delivery_observed = true;
                }
                let identity = agent.delivery_identity(delivery.topic(), delivery.command_id())?;
                let command = decode_command(&identity, delivery.command_id(), delivery.payload())?;
                let outcome = agent.apply_command(delivery.topic(), &command, now())?;
                let settlement_token = agent.pending_settlement_token(&command).map(str::to_owned);
                if outcome == ApplyOutcome::Accepted {
                    session.unsubscribe_command().await?;
                    unsubscribe_pending = true;
                    pending_command_ack = Some((delivery, settlement_token));
                } else {
                    session
                        .acknowledge_command(&delivery, settlement_token)
                        .await?;
                }
            }
            MqttEvent::OutboundAcknowledged { event_id } => {
                let kind = publish_pending.take().ok_or(AgentError::UnknownOutbound)?;
                agent.confirm_outbound(&event_id)?;
                if agent.reconnect_revision()?.is_some() {
                    if !unsubscribe_pending && agent.pending_inbound_settled() {
                        return Ok(());
                    }
                    reconnect_ready = true;
                    if subscribed && !unsubscribe_pending {
                        session.unsubscribe_command().await?;
                        unsubscribe_pending = true;
                    }
                } else if matches!(kind, OutboundKind::Report) && !subscribed {
                    session.subscribe().await?;
                }
            }
            MqttEvent::Unsubscribed if pending_command_ack.is_some() => {
                subscribed = false;
                unsubscribe_pending = false;
                let (delivery, settlement_token) =
                    pending_command_ack.take().expect("checked pending ACK");
                session
                    .acknowledge_command(&delivery, settlement_token)
                    .await?;
            }
            MqttEvent::Unsubscribed => {
                subscribed = false;
                unsubscribe_pending = false;
                if recovery_topic.is_some()
                    && !recovery_delivery_observed
                    && !agent.pending_inbound_settled()
                {
                    agent.mark_pending_inbound_absent()?;
                }
                match unsubscribe_completion(
                    reconnect_ready,
                    agent.pending_inbound_settled(),
                    agent.rotation_in_flight(),
                ) {
                    UnsubscribeCompletion::Exit => return Ok(()),
                    UnsubscribeCompletion::Subscribe => session.subscribe().await?,
                    UnsubscribeCompletion::Wait => {}
                }
            }
            MqttEvent::InboundAcknowledged { settlement_token } => {
                if let Some(settlement_token) = settlement_token {
                    agent.mark_pending_inbound_settled(&settlement_token)?;
                    if reconnect_ready && !unsubscribe_pending {
                        return Ok(());
                    }
                }
            }
            MqttEvent::TransportProgress => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnsubscribeCompletion {
    Exit,
    Subscribe,
    Wait,
}

const fn unsubscribe_completion(
    reconnect_ready: bool,
    inbound_flushed: bool,
    rotation_in_flight: bool,
) -> UnsubscribeCompletion {
    if reconnect_ready && inbound_flushed {
        UnsubscribeCompletion::Exit
    } else if !rotation_in_flight {
        UnsubscribeCompletion::Subscribe
    } else {
        UnsubscribeCompletion::Wait
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_unsubscribe_and_report_puback_orders_restore_intake() {
        // UnsubAck before report PUBACK: remain blocked; report PUBACK then subscribes in its arm.
        assert_eq!(
            unsubscribe_completion(false, true, true),
            UnsubscribeCompletion::Wait
        );
        // Report PUBACK before UnsubAck: the UnsubAck arm must restore the canonical subscription.
        assert_eq!(
            unsubscribe_completion(false, true, false),
            UnsubscribeCompletion::Subscribe
        );
    }

    #[test]
    fn accepted_command_ack_orders_exit_only_after_unsubscribe_and_inbound_puback() {
        // Outbound ACK PUBACK -> UnsubAck -> inbound PUBACK.
        assert_eq!(
            unsubscribe_completion(true, false, true),
            UnsubscribeCompletion::Wait
        );
        // UnsubAck -> inbound PUBACK -> outbound ACK PUBACK reaches the same closed exit state.
        assert_eq!(
            unsubscribe_completion(true, true, true),
            UnsubscribeCompletion::Exit
        );
    }
}
