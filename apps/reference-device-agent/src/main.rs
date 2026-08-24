mod config;
mod mqtt;
mod wire;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::RuntimeConfig;
use mqtt::{CommandDelivery, MqttError, MqttEvent, MqttSession};
use reference_device_agent_core::{
    AgentError, ApplyOutcome, RecoveryCommandScope, ReferenceDeviceAgent, TopicSet,
};
use tokio_util::sync::CancellationToken;
use wire::{decode_command, encode_outbound};

const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

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
    let shutdown = CancellationToken::new();
    let signal_task = tokio::spawn(wait_for_shutdown(shutdown.clone()));

    let result = loop {
        match run_session(&runtime.mqtt, &mut agent, &mut retry_delay, &shutdown).await {
            Ok(SessionCompletion::Reconnect) => retry_delay = Duration::from_secs(1),
            Ok(SessionCompletion::Shutdown) => break Ok(()),
            Err(SessionError::Mqtt(error)) if error.is_retryable() => {
                if shutdown.is_cancelled() {
                    break Ok(());
                }
                eprintln!(
                    "reference-device-agent event=mqtt_transport_retry kind={} delay_milliseconds={} error={error}",
                    error.kind(),
                    retry_delay.as_millis()
                );
                tokio::select! {
                    () = tokio::time::sleep(retry_delay + retry_jitter()) => {}
                    () = shutdown.cancelled() => break Ok(()),
                }
                retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(30));
            }
            Err(error) => break Err(error.into()),
        }
    };
    signal_task.abort();
    let _ = signal_task.await;
    result
}

async fn run_session(
    mqtt: &reference_device_agent_core::MqttConnectionConfig,
    agent: &mut ReferenceDeviceAgent,
    retry_delay: &mut Duration,
    shutdown: &CancellationToken,
) -> Result<SessionCompletion, SessionError> {
    let session_identity = agent.current_identity()?;
    let session_topics = TopicSet::new(&session_identity);
    let recovery_command = agent.pending_command_scope()?;
    let session = MqttSession::new(
        mqtt,
        &agent.current_credentials(),
        session_topics,
        recovery_command.clone(),
    )?;
    SessionDriver::new(agent, session, session_identity, recovery_command)
        .run(retry_delay, shutdown)
        .await
}

struct SessionDriver<'a> {
    agent: &'a mut ReferenceDeviceAgent,
    session: MqttSession,
    session_identity: reference_device_agent_core::DeviceIdentity,
    recovery_command: Option<RecoveryCommandScope>,
    state: SessionState,
}

impl<'a> SessionDriver<'a> {
    fn new(
        agent: &'a mut ReferenceDeviceAgent,
        session: MqttSession,
        session_identity: reference_device_agent_core::DeviceIdentity,
        recovery_command: Option<RecoveryCommandScope>,
    ) -> Self {
        Self {
            agent,
            session,
            session_identity,
            recovery_command,
            state: SessionState::default(),
        }
    }

    async fn run(
        &mut self,
        retry_delay: &mut Duration,
        shutdown: &CancellationToken,
    ) -> Result<SessionCompletion, SessionError> {
        loop {
            self.publish_next().await?;
            if self.state.shutdown_is_quiescent(self.agent) {
                self.session.disconnect().await?;
                return Ok(SessionCompletion::Shutdown);
            }
            let event = match self.poll_next(shutdown).await? {
                DriverPoll::Event(event) => event,
                DriverPoll::ShutdownStarted => continue,
                DriverPoll::ShutdownDeadline => return Ok(SessionCompletion::Shutdown),
            };
            if self.state.connection_is_stable() {
                *retry_delay = Duration::from_secs(1);
            }
            if self.handle_event(event).await? == DriverControl::Reconnect {
                return Ok(SessionCompletion::Reconnect);
            }
        }
    }

    async fn publish_next(&mut self) -> Result<(), SessionError> {
        if self.state.can_publish()
            && let Some(outbound) = self.agent.next_outbound()
        {
            let encoded = encode_outbound(&self.session_identity, outbound)?;
            self.session.publish(encoded).await?;
            self.state.publish = PublishState::Pending;
        }
        Ok(())
    }

    async fn poll_next(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<DriverPoll, SessionError> {
        if let Some(deadline) = self.state.shutdown_deadline {
            return tokio::select! {
                result = self.session.poll() => Ok(DriverPoll::Event(result?)),
                () = tokio::time::sleep_until(deadline) => Ok(DriverPoll::ShutdownDeadline),
            };
        }
        tokio::select! {
            result = self.session.poll() => Ok(DriverPoll::Event(result?)),
            () = shutdown.cancelled() => {
                self.start_shutdown().await?;
                Ok(DriverPoll::ShutdownStarted)
            }
        }
    }

    async fn start_shutdown(&mut self) -> Result<(), SessionError> {
        self.state.shutdown_deadline = Some(tokio::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT);
        if self.state.can_unsubscribe() {
            self.session.unsubscribe_command().await?;
            self.state.subscription = SubscriptionState::Unsubscribing;
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: MqttEvent) -> Result<DriverControl, SessionError> {
        match event {
            MqttEvent::Connected => self.on_connected().await?,
            MqttEvent::Subscribed => self.state.subscription = SubscriptionState::Active,
            MqttEvent::Command(delivery) => self.on_command(delivery).await?,
            MqttEvent::OutboundAcknowledged { event_id } => {
                return self.on_outbound_acknowledged(&event_id).await;
            }
            MqttEvent::Unsubscribed => return self.on_unsubscribed().await,
            MqttEvent::InboundAcknowledged { settlement_token } => {
                return self.on_inbound_acknowledged(settlement_token.as_deref());
            }
            MqttEvent::TransportProgress => {}
        }
        Ok(DriverControl::Continue)
    }

    async fn on_connected(&mut self) -> Result<(), SessionError> {
        self.state.connection = ConnectionState::Connected {
            at: tokio::time::Instant::now(),
        };
        self.state.subscription = SubscriptionState::Inactive;
        if let Some(revision) = self.agent.reconnect_revision()? {
            self.agent.mark_current_credential_connected(revision)?;
        }
        if self.recovery_command.is_some() {
            self.session.unsubscribe_recovery().await?;
            self.state.subscription = SubscriptionState::Unsubscribing;
        } else if self.state.shutdown_deadline.is_none()
            && !self.agent.rotation_in_flight()
            && self.agent.command_intake_open(now())
        {
            self.session.subscribe().await?;
        }
        Ok(())
    }

    async fn on_command(&mut self, delivery: Box<CommandDelivery>) -> Result<(), SessionError> {
        if self
            .recovery_command
            .as_ref()
            .is_some_and(|scope| scope.topic() == delivery.topic())
        {
            self.state.recovery_observation = RecoveryObservation::Observed;
        }
        let outcome = match decode_command(
            delivery.identity(),
            delivery.command_id(),
            delivery.payload(),
        ) {
            Ok(command) => self
                .agent
                .apply_command(delivery.topic(), &command, now())?,
            Err(_) => self.agent.reject_malformed_delivery(
                delivery.topic(),
                delivery.command_id(),
                delivery.payload(),
                now(),
            )?,
        };
        let settlement_token = self
            .agent
            .pending_delivery_settlement_token(delivery.topic(), delivery.command_id())
            .map(str::to_owned);
        if should_hold_command_ack(
            outcome == ApplyOutcome::Accepted,
            self.agent.command_intake_open(now()),
            self.state.shutdown_deadline.is_some(),
        ) {
            self.session.unsubscribe_command().await?;
            self.state.subscription = SubscriptionState::Unsubscribing;
            self.state.pending_command_ack = Some((delivery, settlement_token));
        } else {
            self.session
                .acknowledge_command(delivery, settlement_token)
                .await?;
        }
        Ok(())
    }

    async fn on_outbound_acknowledged(
        &mut self,
        event_id: &str,
    ) -> Result<DriverControl, SessionError> {
        if self.state.publish != PublishState::Pending {
            return Err(AgentError::UnknownOutbound.into());
        }
        self.state.publish = PublishState::Idle;
        self.agent.confirm_outbound(event_id)?;
        if self.agent.reconnect_revision()?.is_some() {
            if !self.state.unsubscribe_pending() && self.agent.pending_inbound_settled() {
                return Ok(DriverControl::Reconnect);
            }
            self.state.reconnect = ReconnectState::Ready;
            if self.state.can_unsubscribe() {
                self.session.unsubscribe_command().await?;
                self.state.subscription = SubscriptionState::Unsubscribing;
            }
        } else if self.state.can_subscribe() && self.agent.command_intake_open(now()) {
            self.session.subscribe().await?;
        }
        Ok(DriverControl::Continue)
    }

    async fn on_unsubscribed(&mut self) -> Result<DriverControl, SessionError> {
        self.state.subscription = SubscriptionState::Inactive;
        if let Some((delivery, settlement_token)) = self.state.pending_command_ack.take() {
            self.session
                .acknowledge_command(delivery, settlement_token)
                .await?;
            return Ok(DriverControl::Continue);
        }
        if self.recovery_command.is_some()
            && self.state.recovery_observation == RecoveryObservation::NotObserved
            && !self.agent.pending_inbound_settled()
        {
            self.agent.mark_pending_inbound_absent()?;
        }
        match unsubscribe_completion(
            self.state.reconnect == ReconnectState::Ready,
            self.agent.pending_inbound_settled(),
            self.agent.rotation_in_flight(),
        ) {
            UnsubscribeCompletion::Exit => Ok(DriverControl::Reconnect),
            UnsubscribeCompletion::Subscribe
                if self.state.can_subscribe() && self.agent.command_intake_open(now()) =>
            {
                self.session.subscribe().await?;
                Ok(DriverControl::Continue)
            }
            UnsubscribeCompletion::Subscribe | UnsubscribeCompletion::Wait => {
                Ok(DriverControl::Continue)
            }
        }
    }

    fn on_inbound_acknowledged(
        &mut self,
        settlement_token: Option<&str>,
    ) -> Result<DriverControl, SessionError> {
        if let Some(settlement_token) = settlement_token {
            self.agent.mark_pending_inbound_settled(settlement_token)?;
            if self.state.reconnect == ReconnectState::Ready && !self.state.unsubscribe_pending() {
                return Ok(DriverControl::Reconnect);
            }
        }
        Ok(DriverControl::Continue)
    }
}

#[derive(Default)]
struct SessionState {
    publish: PublishState,
    subscription: SubscriptionState,
    connection: ConnectionState,
    pending_command_ack: Option<(Box<CommandDelivery>, Option<String>)>,
    recovery_observation: RecoveryObservation,
    reconnect: ReconnectState,
    shutdown_deadline: Option<tokio::time::Instant>,
}

impl SessionState {
    fn can_publish(&self) -> bool {
        matches!(self.connection, ConnectionState::Connected { .. })
            && self.publish == PublishState::Idle
            && self.reconnect == ReconnectState::Dormant
            && !self.unsubscribe_pending()
    }

    fn can_unsubscribe(&self) -> bool {
        matches!(self.connection, ConnectionState::Connected { .. })
            && self.subscription == SubscriptionState::Active
    }

    fn can_subscribe(&self) -> bool {
        self.subscription == SubscriptionState::Inactive && self.shutdown_deadline.is_none()
    }

    fn connection_is_stable(&self) -> bool {
        matches!(self.connection, ConnectionState::Connected { at }
            if at.elapsed() >= Duration::from_mins(1))
    }

    fn shutdown_is_quiescent(&self, agent: &ReferenceDeviceAgent) -> bool {
        self.transport_is_quiescent() && agent.next_outbound().is_none()
    }

    fn transport_is_quiescent(&self) -> bool {
        self.shutdown_deadline.is_some()
            && matches!(self.connection, ConnectionState::Connected { .. })
            && self.publish == PublishState::Idle
            && self.pending_command_ack.is_none()
            && !self.unsubscribe_pending()
    }

    fn unsubscribe_pending(&self) -> bool {
        self.subscription == SubscriptionState::Unsubscribing
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum PublishState {
    #[default]
    Idle,
    Pending,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum SubscriptionState {
    #[default]
    Inactive,
    Active,
    Unsubscribing,
}

#[derive(Clone, Copy, Default)]
enum ConnectionState {
    #[default]
    Connecting,
    Connected {
        at: tokio::time::Instant,
    },
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum RecoveryObservation {
    #[default]
    NotObserved,
    Observed,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum ReconnectState {
    #[default]
    Dormant,
    Ready,
}

enum DriverPoll {
    Event(MqttEvent),
    ShutdownStarted,
    ShutdownDeadline,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DriverControl {
    Continue,
    Reconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionCompletion {
    Reconnect,
    Shutdown,
}

const fn should_hold_command_ack(accepted: bool, intake_open: bool, shutting_down: bool) -> bool {
    accepted || !intake_open || shutting_down
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

async fn wait_for_shutdown(shutdown: CancellationToken) {
    #[cfg(unix)]
    {
        let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel();
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    shutdown.cancel();
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

    #[test]
    fn command_ack_is_held_behind_admission_and_shutdown_barriers() {
        assert!(!should_hold_command_ack(false, true, false));
        assert!(should_hold_command_ack(true, true, false));
        assert!(should_hold_command_ack(false, false, false));
        assert!(should_hold_command_ack(false, true, true));
    }

    #[test]
    fn shutdown_waits_for_every_transport_fact() {
        assert!(quiescent_state().transport_is_quiescent());
        for state in [
            SessionState {
                shutdown_deadline: None,
                ..quiescent_state()
            },
            SessionState {
                connection: ConnectionState::Connecting,
                ..quiescent_state()
            },
            SessionState {
                publish: PublishState::Pending,
                ..quiescent_state()
            },
            SessionState {
                subscription: SubscriptionState::Unsubscribing,
                ..quiescent_state()
            },
        ] {
            assert!(!state.transport_is_quiescent());
        }
    }

    fn quiescent_state() -> SessionState {
        SessionState {
            shutdown_deadline: Some(tokio::time::Instant::now()),
            connection: ConnectionState::Connected {
                at: tokio::time::Instant::now(),
            },
            ..SessionState::default()
        }
    }
}
