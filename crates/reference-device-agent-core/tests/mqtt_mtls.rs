use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs};

use reference_device_agent_core::{
    BrokerAssertionVerifier, CommandDelivery, CredentialFiles, CredentialGeneration,
    DeviceIdentity, MqttConnectionConfig, MqttEvent, MqttSession, TopicSet,
};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, PublishProperties};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{TlsConfiguration, Transport};
use tokio::time::timeout;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the disposable Mosquitto mTLS reference environment"]
async fn persistent_session_queues_offline_command_and_manual_ack_is_explicit() {
    let host = required("RSS_AGENT_MQTT_HOST");
    let port = required("RSS_AGENT_MQTT_PORT").parse().expect("MQTT port");
    let identity = DeviceIdentity::try_new(
        required("RSS_AGENT_TENANT_ID")
            .parse::<Uuid>()
            .expect("tenant"),
        required("RSS_AGENT_DEVICE_ID")
            .parse::<Uuid>()
            .expect("device"),
        CredentialGeneration::try_from(
            required("RSS_AGENT_CREDENTIAL_GENERATION")
                .parse::<u64>()
                .expect("credential generation"),
        )
        .expect("credential generation"),
    )
    .expect("identity");
    let topics = TopicSet::new(&identity);
    let device_credentials = credentials("DEVICE");
    let service_credentials = credentials("SERVICE");
    let run_id = required("RSS_AGENT_RUN_ID");
    let device_config = connection(&host, port, &format!("reference-agent-t2-device-{run_id}"));

    let mut online = MqttSession::new(&device_config, &device_credentials, topics.clone(), None)
        .expect("device session");
    wait_connected(&mut online, false).await;
    online.subscribe().await.expect("subscribe");
    wait_subscribed(&mut online).await;
    drop(online);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (service, mut service_events) = raw_service(
        &host,
        port,
        &format!("reference-agent-t2-service-{run_id}"),
        &service_credentials,
    );
    wait_raw_connected(&mut service_events).await;
    let properties = PublishProperties {
        correlation_data: Some(b"offline-command-1".to_vec().into()),
        payload_format_indicator: Some(1),
        content_type: Some("application/json".to_owned()),
        ..PublishProperties::default()
    };
    service
        .publish_with_properties(
            topics.command(),
            QoS::AtLeastOnce,
            false,
            br#"{"probe":"persistent-session"}"#.to_vec(),
            properties,
        )
        .await
        .expect("publish command");
    wait_raw_puback(&mut service_events).await;
    drop(service);

    let mut reconnected =
        MqttSession::new(&device_config, &device_credentials, topics.clone(), None)
            .expect("reconnected device session");
    wait_connected(&mut reconnected, true).await;
    let delivery = wait_command(&mut reconnected).await;
    assert_eq!(delivery.command_id(), "offline-command-1");
    assert_eq!(delivery.payload(), br#"{"probe":"persistent-session"}"#);
    drop(reconnected);

    let mut after_crash =
        MqttSession::new(&device_config, &device_credentials, topics.clone(), None)
            .expect("post-crash device session");
    wait_connected(&mut after_crash, true).await;
    let redelivery = wait_command(&mut after_crash).await;
    assert_eq!(redelivery.command_id(), "offline-command-1");
    assert_eq!(redelivery.payload(), br#"{"probe":"persistent-session"}"#);
    after_crash
        .acknowledge_command(redelivery, None)
        .await
        .expect("manual PUBACK enqueue");
    wait_inbound_ack(&mut after_crash).await;
    drop(after_crash);

    let mut settled = MqttSession::new(&device_config, &device_credentials, topics, None)
        .expect("settled device session");
    wait_connected(&mut settled, true).await;
    assert_no_command(&mut settled).await;
}

fn connection(host: &str, port: u16, client_id: &str) -> MqttConnectionConfig {
    MqttConnectionConfig::new(
        host,
        port,
        client_id,
        NonZeroU32::new(300).expect("expiry"),
        NonZeroUsize::new(10).expect("capacity"),
        BrokerAssertionVerifier::from_base64(&required("RSS_AGENT_BROKER_ASSERTION_PUBLIC_KEY"))
            .expect("broker assertion key"),
    )
    .expect("MQTT config")
}

fn raw_service(
    host: &str,
    port: u16,
    client_id: &str,
    credentials: &CredentialFiles,
) -> (AsyncClient, EventLoop) {
    let mut options = MqttOptions::new(client_id, host, port);
    options
        .set_clean_start(true)
        .set_keep_alive(Duration::from_secs(15))
        .set_transport(Transport::Tls(TlsConfiguration::Simple {
            ca: fs::read(credentials.ca_certificate()).expect("service CA"),
            alpn: None,
            client_auth: Some((
                fs::read(credentials.certificate_chain()).expect("service certificate"),
                fs::read(credentials.private_key()).expect("service key"),
            )),
        }));
    AsyncClient::new(options, 10)
}

async fn wait_raw_connected(events: &mut EventLoop) {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("service connect timeout")
            .expect("service connect transport");
        if matches!(event, Event::Incoming(Packet::ConnAck(_))) {
            return;
        }
    }
}

async fn wait_raw_puback(events: &mut EventLoop) {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("service PUBACK timeout")
            .expect("service PUBACK transport");
        if matches!(event, Event::Incoming(Packet::PubAck(_))) {
            return;
        }
    }
}

fn credentials(kind: &str) -> CredentialFiles {
    CredentialFiles::new(
        PathBuf::from(required("RSS_AGENT_CA_PATH")),
        PathBuf::from(required(&format!("RSS_AGENT_{kind}_CERT_PATH"))),
        PathBuf::from(required(&format!("RSS_AGENT_{kind}_KEY_PATH"))),
    )
}

async fn wait_connected(session: &mut MqttSession, expected_session_present: bool) {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("connect timeout")
            .expect("connect transport");
        if let MqttEvent::Connected { session_present } = event {
            assert_eq!(session_present, expected_session_present);
            return;
        }
    }
}

async fn wait_subscribed(session: &mut MqttSession) {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("subscribe timeout")
            .expect("subscribe transport");
        if matches!(event, MqttEvent::Subscribed) {
            return;
        }
    }
}

async fn wait_inbound_ack(session: &mut MqttSession) {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("outgoing PUBACK timeout")
            .expect("outgoing PUBACK transport");
        if matches!(event, MqttEvent::InboundAcknowledged { .. }) {
            return;
        }
    }
}

async fn assert_no_command(session: &mut MqttSession) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            session.poll(),
        )
        .await
        {
            Err(_) => return,
            Ok(Ok(MqttEvent::Command(_))) => panic!("settled command was redelivered"),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!("settled session failed: {error}"),
        }
    }
}

async fn wait_command(session: &mut MqttSession) -> Box<CommandDelivery> {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("command timeout")
            .expect("command transport");
        if let MqttEvent::Command(delivery) = event {
            return delivery;
        }
    }
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}
