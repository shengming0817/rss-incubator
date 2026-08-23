use std::fs;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

use reference_device_agent_core::{
    AgentConfig, ArtifactCatalog, CredentialFiles, CredentialGeneration, DeviceIdentity,
    MqttConnectionConfig,
};
use rotation_model::{CredentialRevision, FenceEpoch, Generation, InstalledCredentialPosition};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("reference agent configuration is invalid or unavailable")]
pub(crate) struct ConfigError;

pub(crate) struct RuntimeConfig {
    pub agent: AgentConfig,
    pub mqtt: MqttConnectionConfig,
}

impl RuntimeConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(|_| ConfigError)?;
        let raw: ConfigV1 = serde_json::from_slice(&bytes).map_err(|_| ConfigError)?;
        if raw.schema_version != 1 {
            return Err(ConfigError);
        }
        let base = path.parent().ok_or(ConfigError)?;
        let identity = DeviceIdentity::new(
            raw.tenant_id,
            raw.device_id,
            CredentialGeneration::try_from(raw.credential_generation).map_err(|_| ConfigError)?,
        );
        if raw.mqtt.client_id != identity.mqtt_client_id() {
            return Err(ConfigError);
        }
        let initial_position = InstalledCredentialPosition::new(
            Generation::try_from(raw.initial.desired_generation).map_err(|_| ConfigError)?,
            FenceEpoch::try_from(raw.initial.fence_epoch).map_err(|_| ConfigError)?,
            CredentialRevision::try_from(raw.initial.credential_revision)
                .map_err(|_| ConfigError)?,
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
        );
        let mqtt = MqttConnectionConfig::new(
            raw.mqtt.host,
            raw.mqtt.port,
            raw.mqtt.client_id,
            NonZeroU32::new(raw.mqtt.session_expiry_seconds).ok_or(ConfigError)?,
            NonZeroUsize::new(raw.mqtt.request_capacity).ok_or(ConfigError)?,
        )
        .map_err(|_| ConfigError)?;
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
