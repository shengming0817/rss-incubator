use std::collections::{HashMap, VecDeque};
use std::fs;
use std::time::Duration;

use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, Publish, PublishProperties};
use rumqttc::v5::{AsyncClient, ClientError, ConnectionError, Event, EventLoop, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};

use crate::{CredentialFiles, MqttConnectionConfig, TopicSet};

#[derive(Debug, thiserror::Error)]
pub enum MqttError {
    #[error("MQTT credential files are unavailable")]
    CredentialUnavailable,
    #[error("MQTT request queue failed: {0}")]
    Request(#[source] Box<ClientError>),
    #[error("MQTT connection failed: {0}")]
    Connection(#[source] Box<ConnectionError>),
    #[error("MQTT command frame is invalid")]
    InvalidCommandFrame,
    #[error("MQTT outbound acknowledgement was not correlated")]
    UnknownPubAck,
}

impl MqttError {
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Request(_))
            || matches!(
                self,
                Self::Connection(error)
                    if matches!(error.as_ref(), ConnectionError::Timeout(_) | ConnectionError::Io(_))
            )
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
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
        }
    }
}

/// Peer-authenticated command delivery retaining the one-shot manual PUBACK capability.
pub struct CommandDelivery {
    publish: Publish,
    topic: String,
    command_id: String,
}

impl std::fmt::Debug for CommandDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommandDelivery(<authenticated>)")
    }
}

impl CommandDelivery {
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.publish.payload
    }

    #[must_use]
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
}

/// Observable MQTT v5 transport events. Broker acknowledgements never become application facts.
#[derive(Debug)]
pub enum MqttEvent {
    Connected { session_present: bool },
    Subscribed,
    Unsubscribed,
    Command(Box<CommandDelivery>),
    OutboundAcknowledged { event_id: String },
    TransportProgress,
}

/// Concrete MQTT v5 client with mandatory mTLS, persistent session, `QoS` 1, and manual ACKs.
pub struct MqttSession {
    client: AsyncClient,
    event_loop: EventLoop,
    topics: TopicSet,
    awaiting_packet_id: VecDeque<String>,
    packet_events: HashMap<u16, String>,
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
    pub fn new(
        config: &MqttConnectionConfig,
        credentials: &CredentialFiles,
        topics: TopicSet,
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
        })
    }

    /// Subscribes to the sole canonical command topic at `QoS` 1.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be queued to the transport.
    pub async fn subscribe(&self) -> Result<(), MqttError> {
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
    pub async fn unsubscribe_command(&self) -> Result<(), MqttError> {
        self.client
            .unsubscribe(self.topics.command())
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Publishes one durable fact at `QoS` 1 with its event ID as correlation data.
    ///
    /// # Errors
    ///
    /// Returns an error when the publish cannot be queued to the transport.
    pub async fn publish(
        &mut self,
        event_id: &str,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<(), MqttError> {
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
        self.awaiting_packet_id.push_back(event_id.to_owned());
        Ok(())
    }

    /// Explicitly queues the inbound command `PUBACK` after durable application.
    ///
    /// # Errors
    ///
    /// Returns an error when the acknowledgement cannot be queued to the transport.
    pub async fn acknowledge_command(&self, delivery: &CommandDelivery) -> Result<(), MqttError> {
        self.client
            .ack(&delivery.publish)
            .await
            .map_err(|error| MqttError::Request(Box::new(error)))
    }

    /// Polls one correlated transport event.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, invalid command frames, or uncorrelated `PUBACK`s.
    pub async fn poll(&mut self) -> Result<MqttEvent, MqttError> {
        let event = self
            .event_loop
            .poll()
            .await
            .map_err(|error| MqttError::Connection(Box::new(error)))?;
        match event {
            Event::Incoming(Packet::ConnAck(ack)) => Ok(MqttEvent::Connected {
                session_present: ack.session_present,
            }),
            Event::Incoming(Packet::SubAck(_)) => Ok(MqttEvent::Subscribed),
            Event::Incoming(Packet::UnsubAck(_)) => Ok(MqttEvent::Unsubscribed),
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
            _ => Ok(MqttEvent::TransportProgress),
        }
    }

    fn command_delivery(&self, publish: Publish) -> Result<MqttEvent, MqttError> {
        let topic = std::str::from_utf8(&publish.topic)
            .map_err(|_| MqttError::InvalidCommandFrame)?
            .to_owned();
        if publish.qos != QoS::AtLeastOnce || !self.topics.accepts_command(&topic) {
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
        if command_id.is_empty() {
            return Err(MqttError::InvalidCommandFrame);
        }
        Ok(MqttEvent::Command(Box::new(CommandDelivery {
            publish,
            topic,
            command_id,
        })))
    }
}
