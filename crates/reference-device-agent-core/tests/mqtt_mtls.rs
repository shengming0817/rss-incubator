use std::env;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use reference_device_agent_core::{
    CredentialFiles, CredentialGeneration, DeviceIdentity, MqttConnectionConfig, MqttEvent,
    MqttSession, TopicSet,
};
use tokio::time::timeout;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the disposable Mosquitto mTLS reference environment"]
async fn persistent_session_queues_offline_command_and_manual_ack_is_explicit() {
    let host = required("RSS_AGENT_MQTT_HOST");
    let port = required("RSS_AGENT_MQTT_PORT").parse().expect("MQTT port");
    let identity = DeviceIdentity::new(
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
    );
    let topics = TopicSet::new(&identity);
    let device_credentials = credentials("DEVICE");
    let service_credentials = credentials("SERVICE");
    let run_id = required("RSS_AGENT_RUN_ID");
    let device_config = connection(&host, port, &format!("reference-agent-t2-device-{run_id}"));
    let service_config = connection(&host, port, &format!("reference-agent-t2-service-{run_id}"));

    let mut online = MqttSession::new(&device_config, &device_credentials, topics.clone(), None)
        .expect("device session");
    wait_connected(&mut online, false).await;
    online.subscribe().await.expect("subscribe");
    wait_subscribed(&mut online).await;
    drop(online);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut service = MqttSession::new(&service_config, &service_credentials, topics.clone(), None)
        .expect("service session");
    wait_connected(&mut service, false).await;
    service
        .publish(
            "offline-command-1",
            topics.command(),
            br#"{"probe":"persistent-session"}"#.to_vec(),
        )
        .await
        .expect("publish command");
    wait_outbound_ack(&mut service, "offline-command-1").await;
    drop(service);

    let mut reconnected = MqttSession::new(&device_config, &device_credentials, topics, None)
        .expect("reconnected device session");
    wait_connected(&mut reconnected, true).await;
    let delivery = wait_command(&mut reconnected).await;
    assert_eq!(delivery.command_id(), "offline-command-1");
    assert_eq!(delivery.payload(), br#"{"probe":"persistent-session"}"#);
    reconnected
        .acknowledge_command(&delivery)
        .await
        .expect("manual PUBACK enqueue");
    let _ = timeout(Duration::from_secs(5), reconnected.poll())
        .await
        .expect("manual PUBACK progress")
        .expect("manual PUBACK transport");
}

fn connection(host: &str, port: u16, client_id: &str) -> MqttConnectionConfig {
    MqttConnectionConfig::new(
        host,
        port,
        client_id,
        NonZeroU32::new(300).expect("expiry"),
        NonZeroUsize::new(10).expect("capacity"),
    )
    .expect("MQTT config")
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

async fn wait_outbound_ack(session: &mut MqttSession, expected: &str) {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("PUBACK timeout")
            .expect("PUBACK transport");
        if let MqttEvent::OutboundAcknowledged { event_id } = event {
            assert_eq!(event_id, expected);
            return;
        }
    }
}

async fn wait_command(session: &mut MqttSession) -> reference_device_agent_core::CommandDelivery {
    loop {
        let event = timeout(Duration::from_secs(10), session.poll())
            .await
            .expect("command timeout")
            .expect("command transport");
        if let MqttEvent::Command(delivery) = event {
            return *delivery;
        }
    }
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}
