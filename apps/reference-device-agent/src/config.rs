use std::fs;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

use reference_device_agent_core::{
    AgentConfig, ArtifactCatalog, BrokerAssertionVerifier, CredentialFiles, CredentialGeneration,
    DeviceIdentity, MqttConnectionConfig,
};
use rotation_model::{CredentialRevision, FenceEpoch, Generation, InstalledCredentialPosition};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("reference agent configuration is unavailable")]
    Unavailable,
    #[error("reference agent configuration JSON is invalid")]
    InvalidJson,
    #[error("reference agent configuration schema is unsupported")]
    UnsupportedSchema,
    #[error("reference agent configuration path has no parent")]
    MissingBaseDirectory,
    #[error("reference agent identity is invalid")]
    InvalidIdentity,
    #[error("MQTT client identity does not match the configured device")]
    ClientIdentityMismatch,
    #[error("initial desired generation is invalid")]
    InvalidDesiredGeneration,
    #[error("initial fence epoch is invalid")]
    InvalidFenceEpoch,
    #[error("initial credential revision is invalid")]
    InvalidCredentialRevision,
    #[error("MQTT session expiry is invalid")]
    InvalidSessionExpiry,
    #[error("MQTT request capacity is invalid")]
    InvalidRequestCapacity,
    #[error("MQTT broker assertion public key is invalid")]
    InvalidBrokerAssertionKey,
    #[error("MQTT connection configuration is invalid")]
    InvalidMqtt,
}

pub(crate) struct RuntimeConfig {
    pub agent: AgentConfig,
    pub mqtt: MqttConnectionConfig,
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(|_| ConfigError::Unavailable)?;
        let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidJson)?;
        if raw.schema_version != 1 {
            return Err(ConfigError::UnsupportedSchema);
        }
        let base = path.parent().ok_or(ConfigError::MissingBaseDirectory)?;
        let identity = DeviceIdentity::try_new(
            raw.tenant_id,
            raw.device_id,
            CredentialGeneration::try_from(raw.credential_generation)
                .map_err(|_| ConfigError::InvalidIdentity)?,
        )
        .map_err(|_| ConfigError::InvalidIdentity)?;
        if raw.mqtt.client_id != identity.mqtt_client_id() {
            return Err(ConfigError::ClientIdentityMismatch);
        }
        let session_expiry = NonZeroU32::new(raw.mqtt.session_expiry_seconds)
            .ok_or(ConfigError::InvalidSessionExpiry)?;
        let initial_position = InstalledCredentialPosition::new(
            Generation::try_from(raw.initial.desired_generation)
                .map_err(|_| ConfigError::InvalidDesiredGeneration)?,
            FenceEpoch::try_from(raw.initial.fence_epoch)
                .map_err(|_| ConfigError::InvalidFenceEpoch)?,
            CredentialRevision::try_from(raw.initial.credential_revision)
                .map_err(|_| ConfigError::InvalidCredentialRevision)?,
        );
        let agent = AgentConfig::new(
            identity,
            resolve(base, &raw.state_directory),
            ArtifactCatalog::new(resolve(base, &raw.artifact_catalog)),
            initial_position,
            CredentialFiles::new(
                resolve(base, &raw.initial.ca_path),
                resolve(base, &raw.initial.certificate_path),
                resolve(base, &raw.initial.private_key_path),
            ),
            session_expiry,
        );
        let assertion_verifier =
            BrokerAssertionVerifier::from_base64(&raw.mqtt.broker_assertion_public_key)
                .map_err(|_| ConfigError::InvalidBrokerAssertionKey)?;
        let mqtt = MqttConnectionConfig::new(
            raw.mqtt.host,
            raw.mqtt.port,
            raw.mqtt.client_id,
            session_expiry,
            NonZeroUsize::new(raw.mqtt.request_capacity)
                .ok_or(ConfigError::InvalidRequestCapacity)?,
            assertion_verifier,
        )
        .map_err(|_| ConfigError::InvalidMqtt)?;
        Ok(Self { agent, mqtt })
    }
}

fn resolve(base: &Path, raw: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw.to_owned()
    } else {
        base.join(raw)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigV1 {
    schema_version: u8,
    tenant_id: Uuid,
    device_id: Uuid,
    credential_generation: u64,
    state_directory: PathBuf,
    artifact_catalog: PathBuf,
    mqtt: MqttConfig,
    initial: InitialConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MqttConfig {
    host: String,
    port: u16,
    client_id: String,
    session_expiry_seconds: u32,
    request_capacity: usize,
    broker_assertion_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitialConfig {
    desired_generation: u64,
    fence_epoch: u64,
    credential_revision: u64,
    ca_path: PathBuf,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "tenantId": "00000000-0000-0000-0000-000000000001",
            "deviceId": "00000000-0000-0000-0000-000000000101",
            "credentialGeneration": 1,
            "stateDirectory": "state",
            "artifactCatalog": "catalog.json",
            "mqtt": {
                "host": "localhost",
                "port": 8883,
                "clientId": "rss-reference-device-00000000-0000-0000-0000-000000000001-00000000-0000-0000-0000-000000000101",
                "sessionExpirySeconds": 300,
                "requestCapacity": 16,
                "brokerAssertionPublicKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
            },
            "initial": {
                "desiredGeneration": 1,
                "fenceEpoch": 1,
                "credentialRevision": 1,
                "caPath": "ca.pem",
                "certificatePath": "device.pem",
                "privateKeyPath": "device-key.pem"
            }
        })
    }

    fn load(value: &serde_json::Value) -> Result<RuntimeConfig, ConfigError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("config.json");
        fs::write(&path, serde_json::to_vec(value).expect("JSON")).expect("configuration");
        RuntimeConfig::load(&path)
    }

    #[test]
    fn valid_coordinates_produce_closed_runtime_configuration() {
        assert!(load(&valid_config()).is_ok());
    }

    #[test]
    fn configuration_failures_remain_distinguishable() {
        let mut schema = valid_config();
        schema["schemaVersion"] = 2.into();
        assert!(matches!(load(&schema), Err(ConfigError::UnsupportedSchema)));

        let mut identity = valid_config();
        identity["tenantId"] = "00000000-0000-0000-0000-000000000000".into();
        assert!(matches!(load(&identity), Err(ConfigError::InvalidIdentity)));

        let mut client = valid_config();
        client["mqtt"]["clientId"] = "another-client".into();
        assert!(matches!(
            load(&client),
            Err(ConfigError::ClientIdentityMismatch)
        ));

        let mut expiry = valid_config();
        expiry["mqtt"]["sessionExpirySeconds"] = 0.into();
        assert!(matches!(
            load(&expiry),
            Err(ConfigError::InvalidSessionExpiry)
        ));

        let mut assertion = valid_config();
        assertion["mqtt"]["brokerAssertionPublicKey"] = "invalid".into();
        assert!(matches!(
            load(&assertion),
            Err(ConfigError::InvalidBrokerAssertionKey)
        ));

        let mut host = valid_config();
        host["mqtt"]["host"] = "".into();
        assert!(matches!(load(&host), Err(ConfigError::InvalidMqtt)));
    }
}
