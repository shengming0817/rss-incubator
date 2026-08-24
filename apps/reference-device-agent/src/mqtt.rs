use std::collections::{HashMap, VecDeque};
use std::fs;
use std::time::Duration;

use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{
    ConnectReturnCode, Packet, Publish, PublishProperties, SubAck, SubscribeReasonCode, UnsubAck,
    UnsubAckReason,
};
use rumqttc::v5::{AsyncClient, ClientError, ConnectionError, Event, EventLoop, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};

use crate::wire::{EncodedOutbound, EncodedOutboundKind};
use reference_device_agent_core::{
    BrokerAssertionVerifier, CommandId, CredentialFiles, DeviceIdentity, MqttConnectionConfig,
    RecoveryCommandScope, TopicSet,
};

#[derive(thiserror::Error)]
pub(super) enum MqttError {
    #[error("MQTT credential files are unavailable")]
    CredentialUnavailable,
    #[error("MQTT request queue failed")]
    Request(#[source] Box<ClientError>),
    #[error("MQTT connection failed")]
    Connection(#[source] Box<ConnectionError>),
    #[error("MQTT command frame is invalid")]
    InvalidCommandFrame,
    #[error("MQTT outbound acknowledgement was not correlated")]
    UnknownPubAck,
    #[error("MQTT subscription was rejected")]
    SubscriptionRejected,
    #[error("MQTT broker assertion was rejected")]
    AssertionRejected,
}

impl std::fmt::Debug for MqttError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MqttError")
            .field("kind", &self.kind())
            .finish()
    }
}

impl MqttError {
    #[must_use]
    pub(super) fn is_retryable(&self) -> bool {
        matches!(self, Self::Request(_))
            || matches!(
                self,
                Self::Connection(error)
                    if matches!(error.as_ref(), ConnectionError::Timeout(_) | ConnectionError::Io(_))
            )
            || matches!(
                self,
                Self::Connection(error)
                    if matches!(
                        error.as_ref(),
                        ConnectionError::ConnectionRefused(
                            ConnectReturnCode::ServiceUnavailable
                                | ConnectReturnCode::ServerUnavailable
                                | ConnectReturnCode::ServerBusy
                                | ConnectReturnCode::QuotaExceeded
                                | ConnectReturnCode::ConnectionRateExceeded
                        )
                    )
            )
    }

    #[must_use]
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "credential_unavailable",
            Self::Request(_) => "request_queue",
            Self::Connection(error) => match error.as_ref() {
                ConnectionError::Timeout(_) => "timeout",
                ConnectionError::Io(_) => "io",
                _ => "connection_rejected",
            },
            Self::InvalidCommandFrame => "invalid_command_frame",
            Self::UnknownPubAck => "unknown_puback",
            Self::SubscriptionRejected => "subscription_rejected",
            Self::AssertionRejected => "assertion_rejected",
        }
    }
}

/// Broker-asserted command delivery retaining the one-shot manual PUBACK capability.
pub(super) struct CommandDelivery {
    publish: Publish,
    topic: String,
    command_id: String,
    identity: DeviceIdentity,
}

impl std::fmt::Debug for CommandDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommandDelivery(<authenticated>)")
    }
}

impl CommandDelivery {
    #[must_use]
    pub(super) fn topic(&self) -> &str {
        &self.topic
    }

    #[must_use]
    pub(super) fn payload(&self) -> &[u8] {
        &self.publish.payload
    }

    #[must_use]
    pub(super) fn command_id(&self) -> &str {
        &self.command_id
    }

    #[must_use]
    pub(super) const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }
}

/// Observable MQTT v5 transport events. Broker acknowledgements never become application facts.
#[derive(Debug)]
pub(super) enum MqttEvent {
    Connected,
    Subscribed,
    Unsubscribed,
    Command(Box<CommandDelivery>),
    OutboundAcknowledged { event_id: String },
    InboundAcknowledged { settlement_token: Option<String> },
    TransportProgress,
}

/// Concrete MQTT v5 client with mandatory mTLS, persistent session, `QoS` 1, and manual ACKs.
pub(super) struct MqttSession {
    client: AsyncClient,
    event_loop: EventLoop,
    topics: TopicSet,
    awaiting_packet_id: VecDeque<String>,
    packet_events: HashMap<u16, String>,
    inbound_acknowledgements: HashMap<u16, Option<String>>,
    recovery_command: Option<RecoveryCommandScope>,
    assertion_verifier: BrokerAssertionVerifier,
}

impl std::fmt::Debug for MqttSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MqttSession(<mTLS-persistent>)")
    }
}

impl MqttSession {
    /// Constructs a closed mTLS MQTT v5 session.
    ///
    /// # Errors
    ///
    /// Returns an error when any mandatory credential file is unavailable.
    pub(super) fn new(
        config: &MqttConnectionConfig,
        credentials: &CredentialFiles,
        topics: TopicSet,
        recovery_command: Option<RecoveryCommandScope>,
    ) -> Result<Self, MqttError> {
        let ca =
            fs::read(credentials.ca_certificate()).map_err(|_| MqttError::CredentialUnavailable)?;
        let certificate = fs::read(credentials.certificate_chain())
            .map_err(|_| MqttError::CredentialUnavailable)?;
        let private_key =
            fs::read(credentials.private_key()).map_err(|_| MqttError::CredentialUnavailable)?;
        let mut options = MqttOptions::new(config.client_id(), config.host(), config.port());
        options
            .set_clean_start(false)
            .set_session_expiry_interval(Some(config.session_expiry_seconds().get()))
            .set_receive_maximum(Some(1))
            .set_manual_acks(true)
            .set_keep_alive(Duration::from_secs(15))
            .set_transport(Transport::Tls(TlsConfiguration::Simple {
                ca,
                alpn: None,
                client_auth: Some((certificate, private_key)),
            }));
        let (client, event_loop) = AsyncClient::new(options, config.request_capacity().get());
        Ok(Self {
            client,
            event_loop,
            topics,
            awaiting_packet_id: VecDeque::new(),
            packet_events: HashMap::new(),
            inbound_acknowledgements: HashMap::new(),
            recovery_command,
            assertion_verifier: config.assertion_verifier().clone(),
        })
    }

    /// Subscribes to the sole canonical command topic at `QoS` 1.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be queued to the transport.
    pub(super) async fn subscribe(&self) -> Result<(), MqttError> {
        self.client
            .subscribe(self.topics.command(), QoS::AtLeastOnce)
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Unsubscribes from the canonical command topic before credential reconnect.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be queued to the transport.
    pub(super) async fn unsubscribe_command(&self) -> Result<(), MqttError> {
        self.client
            .unsubscribe(self.topics.command())
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Removes one exact durable recovery subscription.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be queued to the transport.
    pub(super) async fn unsubscribe_recovery(&self) -> Result<(), MqttError> {
        let recovery = self
            .recovery_command
            .as_ref()
            .ok_or(MqttError::InvalidCommandFrame)?;
        self.client
            .unsubscribe(recovery.topic())
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Publishes one durable fact at `QoS` 1 with its event ID as correlation data.
    ///
    /// # Errors
    ///
    /// Returns an error when the publish cannot be queued to the transport.
    pub(super) async fn publish(&mut self, outbound: EncodedOutbound) -> Result<(), MqttError> {
        let (kind, event_id, payload) = outbound.into_parts();
        let topic = match kind {
            EncodedOutboundKind::CommandAcknowledged => self.topics.command_acknowledged(),
            EncodedOutboundKind::CertificateReported => self.topics.certificate_reported(),
        };
        let properties = PublishProperties {
            correlation_data: Some(event_id.as_bytes().to_vec().into()),
            payload_format_indicator: Some(1),
            content_type: Some("application/json".to_owned()),
            ..PublishProperties::default()
        };
        self.client
            .publish_with_properties(topic, QoS::AtLeastOnce, false, payload, properties)
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))?;
        self.awaiting_packet_id.push_back(event_id);
        Ok(())
    }

    /// Explicitly queues the inbound command `PUBACK` after durable application.
    ///
    /// # Errors
    ///
    /// Returns an error when the acknowledgement cannot be queued to the transport.
    pub(super) async fn acknowledge_command(
        &mut self,
        delivery: Box<CommandDelivery>,
        settlement_token: Option<String>,
    ) -> Result<(), MqttError> {
        self.client
            .ack(&delivery.publish)
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))?;
        self.inbound_acknowledgements
            .insert(delivery.publish.pkid, settlement_token);
        Ok(())
    }

    /// Requests a graceful MQTT disconnect after application state is quiescent.
    ///
    /// # Errors
    ///
    /// Returns an error when the disconnect cannot be queued.
    pub(super) async fn disconnect(&self) -> Result<(), MqttError> {
        self.client
            .disconnect()
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Polls one correlated transport event.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, invalid command frames, or uncorrelated `PUBACK`s.
    pub(super) async fn poll(&mut self) -> Result<MqttEvent, MqttError> {
        let event = self
            .event_loop
            .poll()
            .await
            .map_err(|error| MqttError::Connection(Box::new(error)))?;
        match event {
            Event::Incoming(Packet::ConnAck(_)) => Ok(MqttEvent::Connected),
            Event::Incoming(Packet::SubAck(ack)) => {
                validate_suback(&ack)?;
                Ok(MqttEvent::Subscribed)
            }
            Event::Incoming(Packet::UnsubAck(ack)) => {
                validate_unsuback(&ack)?;
                Ok(MqttEvent::Unsubscribed)
            }
            Event::Incoming(Packet::Publish(publish)) => self.command_delivery(publish),
            Event::Incoming(Packet::PubAck(ack)) => {
                let event_id = self
                    .packet_events
                    .remove(&ack.pkid)
                    .ok_or(MqttError::UnknownPubAck)?;
                Ok(MqttEvent::OutboundAcknowledged { event_id })
            }
            Event::Outgoing(Outgoing::Publish(packet_id)) => {
                let event_id = self
                    .awaiting_packet_id
                    .pop_front()
                    .ok_or(MqttError::UnknownPubAck)?;
                if self.packet_events.insert(packet_id, event_id).is_some() {
                    return Err(MqttError::UnknownPubAck);
                }
                Ok(MqttEvent::TransportProgress)
            }
            Event::Outgoing(Outgoing::PubAck(packet_id)) => {
                let settlement_token = self
                    .inbound_acknowledgements
                    .remove(&packet_id)
                    .ok_or(MqttError::UnknownPubAck)?;
                Ok(MqttEvent::InboundAcknowledged { settlement_token })
            }
            _ => Ok(MqttEvent::TransportProgress),
        }
    }

    fn command_delivery(&self, publish: Publish) -> Result<MqttEvent, MqttError> {
        let topic = std::str::from_utf8(&publish.topic)
            .map_err(|_| MqttError::InvalidCommandFrame)?
            .to_owned();
        if publish.qos != QoS::AtLeastOnce {
            return Err(MqttError::InvalidCommandFrame);
        }
        let correlation = publish
            .properties
            .as_ref()
            .and_then(|properties| properties.correlation_data.as_deref())
            .ok_or(MqttError::InvalidCommandFrame)?;
        let command_id = std::str::from_utf8(correlation)
            .map_err(|_| MqttError::InvalidCommandFrame)?
            .to_owned();
        CommandId::try_from(command_id.as_str()).map_err(|_| MqttError::InvalidCommandFrame)?;
        let identity = if self.topics.accepts_command(&topic) {
            self.topics.identity()
        } else if self
            .recovery_command
            .as_ref()
            .is_some_and(|scope| scope.topic() == topic && scope.command_id() == command_id)
        {
            self.recovery_command
                .as_ref()
                .map(RecoveryCommandScope::identity)
                .ok_or(MqttError::InvalidCommandFrame)?
        } else {
            return Err(MqttError::InvalidCommandFrame);
        };
        let properties = publish.properties.as_ref();
        let user_properties = properties
            .map(|properties| properties.user_properties.as_slice())
            .unwrap_or_default();
        self.assertion_verifier
            .verify_command(
                identity,
                &topic,
                &publish.payload,
                correlation,
                1,
                publish.retain,
                user_properties,
            )
            .map_err(|_| MqttError::AssertionRejected)?;
        Ok(MqttEvent::Command(Box::new(CommandDelivery {
            publish,
            topic,
            command_id,
            identity: identity.clone(),
        })))
    }
}

fn validate_suback(acknowledgement: &SubAck) -> Result<(), MqttError> {
    matches!(
        acknowledgement.return_codes.as_slice(),
        [SubscribeReasonCode::Success(QoS::AtLeastOnce)]
    )
    .then_some(())
    .ok_or(MqttError::SubscriptionRejected)
}

fn validate_unsuback(acknowledgement: &UnsubAck) -> Result<(), MqttError> {
    matches!(
        acknowledgement.reasons.as_slice(),
        [UnsubAckReason::Success | UnsubAckReason::NoSubscriptionExisted]
    )
    .then_some(())
    .ok_or(MqttError::SubscriptionRejected)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::num::{NonZeroU32, NonZeroUsize};

    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use rumqttc::v5::mqttbytes::v5::{
        PublishProperties, SubAck, SubscribeReasonCode, UnsubAck, UnsubAckReason,
    };
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;
    use uuid::Uuid;

    use reference_device_agent_core::{AckFact, CredentialGeneration, OutboundFact, ReportFact};

    #[test]
    fn broker_refusal_retry_policy_separates_capacity_from_authentication() {
        for code in [
            ConnectReturnCode::ServiceUnavailable,
            ConnectReturnCode::ServerUnavailable,
            ConnectReturnCode::ServerBusy,
            ConnectReturnCode::QuotaExceeded,
            ConnectReturnCode::ConnectionRateExceeded,
        ] {
            let error = MqttError::Connection(Box::new(ConnectionError::ConnectionRefused(code)));
            assert!(error.is_retryable(), "{code:?} must retry");
        }
        for code in [
            ConnectReturnCode::BadClientId,
            ConnectReturnCode::BadUserNamePassword,
            ConnectReturnCode::NotAuthorized,
            ConnectReturnCode::Banned,
            ConnectReturnCode::BadAuthenticationMethod,
            ConnectReturnCode::TopicNameInvalid,
        ] {
            let error = MqttError::Connection(Box::new(ConnectionError::ConnectionRefused(code)));
            assert!(!error.is_retryable(), "{code:?} must fail closed");
        }
    }

    #[test]
    fn subscription_completion_requires_one_success_reason() {
        let accepted = SubAck {
            pkid: 1,
            return_codes: vec![SubscribeReasonCode::Success(QoS::AtLeastOnce)],
            properties: None,
        };
        assert!(validate_suback(&accepted).is_ok());

        for return_codes in [
            Vec::new(),
            vec![SubscribeReasonCode::NotAuthorized],
            vec![
                SubscribeReasonCode::Success(QoS::AtLeastOnce),
                SubscribeReasonCode::Success(QoS::AtLeastOnce),
            ],
            vec![SubscribeReasonCode::Success(QoS::AtMostOnce)],
        ] {
            let rejected = SubAck {
                pkid: 1,
                return_codes,
                properties: None,
            };
            assert!(validate_suback(&rejected).is_err());
        }

        for (reasons, accepted) in [
            (vec![UnsubAckReason::Success], true),
            (vec![UnsubAckReason::NoSubscriptionExisted], true),
            (vec![UnsubAckReason::NotAuthorized], false),
            (Vec::new(), false),
            (
                vec![UnsubAckReason::Success, UnsubAckReason::Success],
                false,
            ),
        ] {
            let acknowledgement = UnsubAck {
                pkid: 1,
                reasons,
                properties: None,
            };
            assert_eq!(validate_unsuback(&acknowledgement).is_ok(), accepted);
        }
    }

    #[tokio::test]
    async fn private_transport_queues_only_wire_minted_operations() {
        let mut fixture = SessionFixture::new(None);
        fixture.session.subscribe().await.expect("subscribe");
        fixture
            .session
            .unsubscribe_command()
            .await
            .expect("unsubscribe command");
        assert!(matches!(
            fixture.session.unsubscribe_recovery().await,
            Err(MqttError::InvalidCommandFrame)
        ));

        for outbound in [
            OutboundFact::CommandAcknowledged {
                event_id: "ack-event".to_owned(),
                payload: AckFact {
                    command_id: "command-1".to_owned(),
                    desired_generation: 3,
                    fence_epoch: 2,
                    device_sequence: 1,
                    observed_at: 1_800_000_000,
                    rejection: None,
                },
            },
            OutboundFact::CertificateReported {
                event_id: "report-event".to_owned(),
                payload: ReportFact {
                    observed_generation: 3,
                    fence_epoch: 2,
                    device_sequence: 2,
                    observed_at: 1_800_000_001,
                    state_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    artifact_digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned(),
                    expires_at: None,
                },
            },
        ] {
            let encoded = crate::wire::encode_outbound(&fixture.identity, outbound)
                .expect("canonical outbound");
            fixture.session.publish(encoded).await.expect("publish");
        }

        let delivery = fixture.signed_delivery(
            fixture.topics.command().to_owned(),
            &fixture.identity,
            "command-1",
            b"payload",
        );
        assert_eq!(delivery.topic(), fixture.topics.command());
        assert_eq!(delivery.command_id(), "command-1");
        assert_eq!(delivery.payload(), b"payload");
        assert_eq!(delivery.identity(), &fixture.identity);
        assert_eq!(format!("{delivery:?}"), "CommandDelivery(<authenticated>)");
        fixture
            .session
            .acknowledge_command(delivery, Some("settlement-1".to_owned()))
            .await
            .expect("manual PUBACK");
        fixture.session.disconnect().await.expect("disconnect");
    }

    #[tokio::test]
    async fn recovery_unsubscribe_is_bound_to_the_exact_old_scope() {
        let identity = identity(1);
        let topic = TopicSet::new(&identity).command().to_owned();
        let recovery =
            RecoveryCommandScope::new(identity.clone(), topic.clone(), "old-command".to_owned());
        let fixture = SessionFixture::new(Some(recovery));
        fixture
            .session
            .unsubscribe_recovery()
            .await
            .expect("unsubscribe recovery");
        let delivery = fixture.signed_delivery(topic, &identity, "old-command", b"old");
        assert_eq!(delivery.identity(), &identity);
    }

    #[test]
    fn command_frame_validation_rejects_every_unasserted_coordinate() {
        let fixture = SessionFixture::new(None);
        let command_topic = fixture.topics.command().to_owned();
        let valid_properties = PublishProperties {
            correlation_data: Some(b"command-1".to_vec().into()),
            ..PublishProperties::default()
        };

        let mut invalid_utf8_topic = Publish::new(
            command_topic.clone(),
            QoS::AtLeastOnce,
            b"payload".as_slice(),
            Some(valid_properties.clone()),
        );
        invalid_utf8_topic.topic = vec![0xff].into();
        let cases = [
            invalid_utf8_topic,
            Publish::new(
                command_topic.clone(),
                QoS::AtMostOnce,
                b"payload".as_slice(),
                Some(valid_properties.clone()),
            ),
            Publish::new(
                command_topic.clone(),
                QoS::AtLeastOnce,
                b"payload".as_slice(),
                None,
            ),
            Publish::new(
                command_topic.clone(),
                QoS::AtLeastOnce,
                b"payload".as_slice(),
                Some(PublishProperties {
                    correlation_data: Some(vec![0xff].into()),
                    ..PublishProperties::default()
                }),
            ),
            Publish::new(
                command_topic.clone(),
                QoS::AtLeastOnce,
                b"payload".as_slice(),
                Some(PublishProperties {
                    correlation_data: Some(Vec::new().into()),
                    ..PublishProperties::default()
                }),
            ),
            Publish::new(
                "rss/v1/wrong/topic",
                QoS::AtLeastOnce,
                b"payload".as_slice(),
                Some(valid_properties.clone()),
            ),
            Publish::new(
                command_topic,
                QoS::AtLeastOnce,
                b"payload".as_slice(),
                Some(valid_properties),
            ),
        ];

        for publish in cases {
            assert!(fixture.session.command_delivery(publish).is_err());
        }
    }

    #[test]
    fn broker_asserted_command_id_must_still_be_canonical() {
        let fixture = SessionFixture::new(None);
        for command_id in ["contains\ncontrol".to_owned(), "x".repeat(257)] {
            let publish = fixture.signed_publish(
                fixture.topics.command().to_owned(),
                &fixture.identity,
                &command_id,
                b"payload",
            );
            assert!(matches!(
                fixture.session.command_delivery(publish),
                Err(MqttError::InvalidCommandFrame)
            ));
        }
    }

    #[test]
    fn mqtt_errors_are_closed_redacted_and_classified() {
        for (error, kind) in [
            (MqttError::CredentialUnavailable, "credential_unavailable"),
            (MqttError::InvalidCommandFrame, "invalid_command_frame"),
            (MqttError::UnknownPubAck, "unknown_puback"),
            (MqttError::SubscriptionRejected, "subscription_rejected"),
            (MqttError::AssertionRejected, "assertion_rejected"),
        ] {
            assert_eq!(error.kind(), kind);
            assert!(!error.is_retryable());
            assert!(!format!("{error}").is_empty());
            assert_eq!(
                format!("{error:?}"),
                format!("MqttError {{ kind: \"{kind}\" }}")
            );
        }
    }

    struct SessionFixture {
        _directory: TempDir,
        key: Ed25519KeyPair,
        identity: DeviceIdentity,
        topics: TopicSet,
        session: MqttSession,
    }

    impl SessionFixture {
        fn new(recovery: Option<RecoveryCommandScope>) -> Self {
            let directory = tempfile::tempdir().expect("temporary credentials");
            let ca = directory.path().join("ca.pem");
            let certificate = directory.path().join("device.pem");
            let private_key = directory.path().join("device.key");
            for path in [&ca, &certificate, &private_key] {
                fs::write(path, b"test-material").expect("credential fixture");
            }
            let key = Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .expect("generate assertion key")
                    .as_ref(),
            )
            .expect("assertion key");
            let verifier = BrokerAssertionVerifier::from_base64(
                &URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            )
            .expect("assertion verifier");
            let config = MqttConnectionConfig::new(
                "127.0.0.1",
                65_000,
                "reference-agent-unit",
                NonZeroU32::new(300).expect("expiry"),
                NonZeroUsize::new(32).expect("capacity"),
                verifier,
            )
            .expect("MQTT config");
            let identity = identity(2);
            let topics = TopicSet::new(&identity);
            let credentials = CredentialFiles::new(ca, certificate, private_key);
            let session = MqttSession::new(&config, &credentials, topics.clone(), recovery)
                .expect("MQTT session");
            Self {
                _directory: directory,
                key,
                identity,
                topics,
                session,
            }
        }

        fn signed_delivery(
            &self,
            topic: String,
            identity: &DeviceIdentity,
            command_id: &str,
            payload: &[u8],
        ) -> Box<CommandDelivery> {
            let publish = self.signed_publish(topic, identity, command_id, payload);
            match self
                .session
                .command_delivery(publish)
                .expect("signed command")
            {
                MqttEvent::Command(delivery) => delivery,
                _ => panic!("command delivery event"),
            }
        }

        fn signed_publish(
            &self,
            topic: String,
            identity: &DeviceIdentity,
            command_id: &str,
            payload: &[u8],
        ) -> Publish {
            let principal = identity.principal_urn();
            let signature = self.key.sign(&signed_bytes(
                &principal,
                &topic,
                command_id.as_bytes(),
                payload,
            ));
            let properties = PublishProperties {
                correlation_data: Some(command_id.as_bytes().to_vec().into()),
                user_properties: vec![
                    ("rss.authn.v1.version".to_owned(), "1".to_owned()),
                    ("rss.authn.v1.principal".to_owned(), principal),
                    (
                        "rss.authn.v1.signature".to_owned(),
                        URL_SAFE_NO_PAD.encode(signature.as_ref()),
                    ),
                ],
                ..PublishProperties::default()
            };
            let mut publish =
                Publish::new(topic, QoS::AtLeastOnce, payload.to_vec(), Some(properties));
            publish.pkid = 7;
            publish
        }
    }

    fn identity(generation: u64) -> DeviceIdentity {
        DeviceIdentity::try_new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("tenant"),
            Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("device"),
            CredentialGeneration::try_from(generation).expect("generation"),
        )
        .expect("identity")
    }

    fn signed_bytes(principal: &str, topic: &str, correlation: &[u8], payload: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(payload);
        let mut bytes = b"rss.mqtt.authn.v1\0".to_vec();
        for field in [
            b"1".as_slice(),
            principal.as_bytes(),
            topic.as_bytes(),
            correlation,
            digest.as_slice(),
            &[1],
            &[0],
        ] {
            let length = u32::try_from(field.len()).expect("field length");
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes
    }
}
