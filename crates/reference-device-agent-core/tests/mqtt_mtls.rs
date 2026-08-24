use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs};

use reference_device_agent_core::{
    CredentialFiles, CredentialGeneration, DeviceIdentity, TopicSet,
};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::{Packet, PublishProperties};
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::{Outgoing, TlsConfiguration, Transport};
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
    let device_client_id = format!("reference-agent-t2-device-{run_id}");

    let (online, mut online_events) =
        raw_device(&host, port, &device_client_id, &device_credentials);
    wait_connected(&mut online_events, false).await;
    online
        .subscribe(topics.command(), QoS::AtLeastOnce)
        .await
        .expect("subscribe");
    wait_subscribed(&mut online_events).await;
    drop(online);
    drop(online_events);
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

    let (reconnected, mut reconnected_events) =
        raw_device(&host, port, &device_client_id, &device_credentials);
    wait_connected(&mut reconnected_events, true).await;
    let delivery = wait_command(&mut reconnected_events).await;
    assert_eq!(correlation(&delivery), b"offline-command-1");
    assert_eq!(
        delivery.payload.as_ref(),
        br#"{"probe":"persistent-session"}"#
    );
    drop(reconnected);
    drop(reconnected_events);

    let (after_crash, mut after_crash_events) =
        raw_device(&host, port, &device_client_id, &device_credentials);
    wait_connected(&mut after_crash_events, true).await;
    let redelivery = wait_command(&mut after_crash_events).await;
    assert_eq!(correlation(&redelivery), b"offline-command-1");
    assert_eq!(
        redelivery.payload.as_ref(),
        br#"{"probe":"persistent-session"}"#
    );
    after_crash
        .ack(&redelivery)
        .await
        .expect("manual PUBACK enqueue");
    wait_inbound_ack(&mut after_crash_events).await;
    drop(after_crash);
    drop(after_crash_events);

    let (_settled, mut settled_events) =
        raw_device(&host, port, &device_client_id, &device_credentials);
    wait_connected(&mut settled_events, true).await;
    assert_no_command(&mut settled_events).await;
}

fn raw_device(
    host: &str,
    port: u16,
    client_id: &str,
    credentials: &CredentialFiles,
) -> (AsyncClient, EventLoop) {
    let mut options = MqttOptions::new(client_id, host, port);
    options
        .set_clean_start(false)
        .set_session_expiry_interval(Some(300))
        .set_receive_maximum(Some(1))
        .set_manual_acks(true)
        .set_keep_alive(Duration::from_secs(15))
        .set_transport(tls(credentials));
    AsyncClient::new(options, 10)
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
        .set_transport(tls(credentials));
    AsyncClient::new(options, 10)
}

fn tls(credentials: &CredentialFiles) -> Transport {
    Transport::Tls(TlsConfiguration::Simple {
        ca: fs::read(credentials.ca_certificate()).expect("CA"),
        alpn: None,
        client_auth: Some((
            fs::read(credentials.certificate_chain()).expect("certificate"),
            fs::read(credentials.private_key()).expect("private key"),
        )),
    })
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

async fn wait_connected(events: &mut EventLoop, expected_session_present: bool) {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("connect timeout")
            .expect("connect transport");
        if let Event::Incoming(Packet::ConnAck(ack)) = event {
            assert_eq!(ack.session_present, expected_session_present);
            return;
        }
    }
}

async fn wait_subscribed(events: &mut EventLoop) {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("subscribe timeout")
            .expect("subscribe transport");
        if matches!(event, Event::Incoming(Packet::SubAck(_))) {
            return;
        }
    }
}

async fn wait_inbound_ack(events: &mut EventLoop) {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("outgoing PUBACK timeout")
            .expect("outgoing PUBACK transport");
        if matches!(event, Event::Outgoing(Outgoing::PubAck(_))) {
            return;
        }
    }
}

async fn assert_no_command(events: &mut EventLoop) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            events.poll(),
        )
        .await
        {
            Err(_) => return,
            Ok(Ok(Event::Incoming(Packet::Publish(_)))) => {
                panic!("settled command was redelivered");
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!("settled session failed: {error}"),
        }
    }
}

async fn wait_command(events: &mut EventLoop) -> rumqttc::v5::mqttbytes::v5::Publish {
    loop {
        let event = timeout(Duration::from_secs(10), events.poll())
            .await
            .expect("command timeout")
            .expect("command transport");
        if let Event::Incoming(Packet::Publish(delivery)) = event {
            return delivery;
        }
    }
}

fn correlation(delivery: &rumqttc::v5::mqttbytes::v5::Publish) -> &[u8] {
    delivery
        .properties
        .as_ref()
        .and_then(|properties| properties.correlation_data.as_deref())
        .expect("correlation data")
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}
