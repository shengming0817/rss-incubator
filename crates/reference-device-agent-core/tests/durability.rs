use std::fs;
use std::num::NonZeroU64;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    SanType,
};
use reference_device_agent_core::{
    AgentConfig, AgentError, ApplyOutcome, ArtifactCatalog, ArtifactId, CommandId,
    CommandRejection, CredentialFiles, CredentialGeneration, DeviceCommand, DeviceIdentity,
    OutboundFact, ReferenceDeviceAgent, Sha256Digest, StoreError, TopicSet,
    compute_artifact_digest,
};
use rotation_model::{CredentialRevision, FenceEpoch, Generation, InstalledCredentialPosition};
use tempfile::TempDir;
use uuid::Uuid;

const NOW: u64 = 1_800_000_000;
const INTENT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const POLICY: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn accepted_command_is_durable_and_report_waits_for_ack_and_new_session() {
    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    let command_topic = TopicSet::new(&fixture.initial_identity)
        .command()
        .to_owned();

    assert_eq!(
        agent
            .apply_command(&command_topic, &command, NOW)
            .expect("apply"),
        ApplyOutcome::Accepted
    );
    let ack = agent.next_outbound().expect("durable ACK");
    assert!(matches!(ack, OutboundFact::CommandAcknowledged { .. }));
    agent.confirm_outbound(ack.event_id()).expect("confirm ACK");
    assert!(agent.next_outbound().is_none());
    assert_eq!(
        agent
            .reconnect_revision()
            .expect("revision")
            .map(CredentialRevision::get),
        Some(2)
    );
    assert_eq!(
        agent
            .current_identity()
            .expect("identity")
            .credential_generation()
            .get(),
        2
    );

    drop(agent);
    let mut reopened = fixture.open_agent();
    assert!(reopened.next_outbound().is_none());
    reopened
        .mark_current_credential_connected(CredentialRevision::try_from(2).expect("revision"))
        .expect("new credential connected");
    let report = reopened.next_outbound().expect("report after reconnect");
    assert!(matches!(report, OutboundFact::CertificateReported { .. }));
    reopened
        .confirm_outbound(report.event_id())
        .expect("confirm report");
    assert!(reopened.next_outbound().is_none());

    let current_topic = TopicSet::new(&reopened.current_identity().expect("identity"))
        .command()
        .to_owned();
    assert_eq!(
        reopened
            .apply_command(&current_topic, &command, NOW)
            .expect("duplicate"),
        ApplyOutcome::Duplicate
    );
    assert_eq!(reopened.next_outbound().expect("replayed ACK"), ack);
}

#[test]
fn unknown_state_fields_fail_closed_without_resetting_state() {
    let fixture = Fixture::new();
    drop(fixture.open_agent());
    let state_path = fixture.root.path().join("state/state.v1.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("JSON");
    state["legacyFallback"] = serde_json::json!(true);
    fs::write(&state_path, serde_json::to_vec(&state).expect("serialize")).expect("corrupt");

    let error = ReferenceDeviceAgent::open(fixture.config(), NOW).expect_err("must fail closed");
    assert!(error.to_string().contains("malformed"));
    assert!(state_path.exists());
}

#[test]
fn semantically_corrupt_known_state_fields_fail_closed() {
    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    agent
        .apply_command(&fixture.command_topic(), &command, NOW)
        .expect("accept");
    drop(agent);
    let state_path = fixture.root.path().join("state/state.v1.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("JSON");
    state["outbox"][1]["payload"]["stateHash"] = serde_json::json!(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    fs::write(&state_path, serde_json::to_vec(&state).expect("serialize")).expect("corrupt");

    assert!(matches!(
        ReferenceDeviceAgent::open(fixture.config(), NOW),
        Err(AgentError::Store(StoreError::InvalidState))
    ));
}

#[test]
fn stale_temporary_files_are_recovered_without_becoming_current() {
    let fixture = Fixture::new_unopened();
    let state_root = fixture.root.path().join("state");
    fs::create_dir_all(state_root.join("credentials/.revision-1.staging")).expect("stale staging");
    fs::write(state_root.join("state.v1.json.tmp"), b"partial").expect("stale state temporary");

    let agent = fixture.open_agent();

    assert_eq!(agent.reconnect_revision().expect("revision"), None);
    assert!(state_root.join("credentials/revision-1").is_dir());
    assert!(!state_root.join("credentials/.revision-1.staging").exists());
    assert!(!state_root.join("state.v1.json.tmp").exists());
}

#[test]
fn rejection_order_and_conflicting_replay_do_not_change_current_credential() {
    let fixture = Fixture::new();
    let (mut agent, accepted) = fixture.agent_and_command();
    let topic = fixture.command_topic();

    let malformed = fixture.command(
        "wrong-topic-command",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 600,
        2,
        2,
    );
    let wrong_topic = agent
        .apply_command("rss/v1/wrong", &malformed, NOW)
        .expect("wrong topic rejection");
    assert_eq!(
        wrong_topic,
        ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
    );
    agent
        .confirm_outbound(agent.next_outbound().expect("ACK").event_id())
        .expect("confirm rejection");

    let expired = fixture.command(
        "expired-command",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW,
        2,
        2,
    );
    assert_eq!(
        agent.apply_command(&topic, &expired, NOW).expect("expired"),
        ApplyOutcome::Rejected(CommandRejection::PolicyRejected)
    );
    agent
        .confirm_outbound(agent.next_outbound().expect("ACK").event_id())
        .expect("confirm rejection");

    let wrong_digest = fixture.command(
        "digest-command",
        &fixture.artifact_id,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        NOW + 600,
        2,
        2,
    );
    assert_eq!(
        agent
            .apply_command(&topic, &wrong_digest, NOW)
            .expect("digest"),
        ApplyOutcome::Rejected(CommandRejection::ArtifactDigestMismatch)
    );
    agent
        .confirm_outbound(agent.next_outbound().expect("ACK").event_id())
        .expect("confirm rejection");

    assert_eq!(
        agent.apply_command(&topic, &accepted, NOW).expect("accept"),
        ApplyOutcome::Accepted
    );
    let conflicting = fixture.command(
        "command-0001",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 601,
        2,
        2,
    );
    let new_topic = TopicSet::new(&agent.current_identity().expect("identity"))
        .command()
        .to_owned();
    assert_eq!(
        agent
            .apply_command(&new_topic, &conflicting, NOW)
            .expect("conflicting replay"),
        ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
    );
    assert_eq!(
        agent
            .current_identity()
            .expect("identity")
            .credential_generation()
            .get(),
        2
    );
}

#[test]
fn durable_outbox_applies_backpressure_at_the_fixed_limit() {
    let fixture = Fixture::new();
    let mut agent = fixture.open_agent();
    let topic = fixture.command_topic();
    for index in 0..128 {
        let command = fixture.command(
            &format!("missing-command-{index:03}"),
            &format!("missing-artifact-{index:03}"),
            &fixture.artifact_digest,
            NOW + 600,
            2,
            2,
        );
        assert_eq!(
            agent
                .apply_command(&topic, &command, NOW)
                .expect("rejection"),
            ApplyOutcome::Rejected(CommandRejection::ArtifactUnavailable)
        );
    }
    let overflow = fixture.command(
        "missing-command-overflow",
        "missing-artifact-overflow",
        &fixture.artifact_digest,
        NOW + 600,
        2,
        2,
    );
    assert!(matches!(
        agent.apply_command(&topic, &overflow, NOW),
        Err(AgentError::Store(StoreError::OutboxFull))
    ));
    assert_eq!(
        agent
            .current_identity()
            .expect("identity")
            .credential_generation()
            .get(),
        1
    );
}

#[test]
fn stale_fence_is_checked_before_stale_generation() {
    let fixture = Fixture::new();
    let (mut agent, accepted) = fixture.agent_and_command();
    let initial_topic = fixture.command_topic();
    assert_eq!(
        agent
            .apply_command(&initial_topic, &accepted, NOW)
            .expect("accept"),
        ApplyOutcome::Accepted
    );
    let current_topic = TopicSet::new(&agent.current_identity().expect("identity"))
        .command()
        .to_owned();

    fixture.set_catalog_position(3, 1);
    let stale_fence = fixture.command(
        "stale-fence-command",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 600,
        3,
        1,
    );
    assert_eq!(
        agent
            .apply_command(&current_topic, &stale_fence, NOW)
            .expect("stale fence"),
        ApplyOutcome::Rejected(CommandRejection::FenceEpochStale)
    );

    fixture.set_catalog_position(1, 3);
    let stale_generation = fixture.command(
        "stale-generation-command",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 600,
        1,
        3,
    );
    assert_eq!(
        agent
            .apply_command(&current_topic, &stale_generation, NOW)
            .expect("stale generation"),
        ApplyOutcome::Rejected(CommandRejection::GenerationStale)
    );
    assert_eq!(
        agent
            .current_identity()
            .expect("identity")
            .credential_generation()
            .get(),
        2
    );
}

#[test]
fn only_the_accepted_command_ack_can_unlock_credential_reconnect() {
    let fixture = Fixture::new();
    let (mut agent, accepted) = fixture.agent_and_command();
    let rejected = fixture.command(
        "rejected-before-rotation",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 600,
        2,
        2,
    );
    assert_eq!(
        agent
            .apply_command("rss/v1/wrong", &rejected, NOW)
            .expect("reject"),
        ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
    );
    assert_eq!(
        agent
            .apply_command(&fixture.command_topic(), &accepted, NOW)
            .expect("accept"),
        ApplyOutcome::Accepted
    );

    let rejection_ack = agent.next_outbound().expect("rejection ACK");
    agent
        .confirm_outbound(rejection_ack.event_id())
        .expect("confirm rejection ACK");
    assert_eq!(agent.reconnect_revision().expect("revision"), None);

    let accepted_ack = agent.next_outbound().expect("accepted ACK");
    agent
        .confirm_outbound(accepted_ack.event_id())
        .expect("confirm accepted ACK");
    assert_eq!(
        agent
            .reconnect_revision()
            .expect("revision")
            .map(CredentialRevision::get),
        Some(2)
    );
}

#[test]
fn missing_manifest_with_a_committed_revision_fails_closed() {
    let fixture = Fixture::new();
    let state_path = fixture.root.path().join("state/state.v1.json");
    fs::remove_file(&state_path).expect("remove state manifest");

    let error = ReferenceDeviceAgent::open(fixture.config(), NOW).expect_err("must not reset");

    assert!(matches!(error, AgentError::Store(StoreError::InvalidState)));
    assert!(!state_path.exists());
    assert!(
        fixture
            .root
            .path()
            .join("state/credentials/revision-1")
            .is_dir()
    );
}

#[test]
fn revoked_catalog_artifact_is_rejected_without_installing_it() {
    let fixture = Fixture::new();
    fixture.set_catalog_revoked(true);
    let (mut agent, command) = fixture.agent_and_command();

    assert_eq!(
        agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("revoked rejection"),
        ApplyOutcome::Rejected(CommandRejection::PolicyRejected)
    );
    assert_eq!(
        agent
            .current_identity()
            .expect("identity")
            .credential_generation()
            .get(),
        1
    );
    assert!(
        !fixture
            .root
            .path()
            .join("state/credentials/revision-2")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn catalog_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let catalog_certificate = fixture.root.path().join("catalog/material/certificate.pem");
    let outside = fixture.root.path().join("outside-certificate.pem");
    fs::copy(&catalog_certificate, &outside).expect("outside certificate");
    fs::remove_file(&catalog_certificate).expect("remove catalog certificate");
    symlink(&outside, &catalog_certificate).expect("symlink");
    let (mut agent, command) = fixture.agent_and_command();

    assert_eq!(
        agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("symlink rejection"),
        ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
    );
    assert!(
        !fixture
            .root
            .path()
            .join("state/credentials/revision-2")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn insecure_catalog_private_key_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let private_key = fixture.root.path().join("catalog/material/private-key.pem");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644))
        .expect("widen key permissions");
    let (mut agent, command) = fixture.agent_and_command();

    assert_eq!(
        agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("permission rejection"),
        ApplyOutcome::Rejected(CommandRejection::DeviceFailure)
    );
    assert!(
        !fixture
            .root
            .path()
            .join("state/credentials/revision-2")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn failed_persistence_does_not_advance_in_memory_protocol_state() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    agent
        .apply_command(&fixture.command_topic(), &command, NOW)
        .expect("accept");
    let acknowledgement = agent.next_outbound().expect("ACK");
    let state_root = fixture.root.path().join("state");
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o500))
        .expect("make state read-only");

    let result = agent.confirm_outbound(acknowledgement.event_id());

    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .expect("restore state permissions");
    assert!(matches!(
        result,
        Err(AgentError::Store(StoreError::Unavailable))
    ));
    assert_eq!(agent.next_outbound(), Some(acknowledgement));
    assert_eq!(agent.reconnect_revision().expect("revision"), None);
}

struct Fixture {
    root: TempDir,
    device: Uuid,
    initial_identity: DeviceIdentity,
    initial_files: CredentialFiles,
    artifact_id: String,
    artifact_digest: String,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self::new_unopened();
        drop(fixture.open_agent());
        fixture
    }

    fn new_unopened() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("tenant");
        let device = Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("device");
        let initial_identity = DeviceIdentity::new(
            tenant,
            device,
            CredentialGeneration::try_from(1).expect("generation"),
        );
        let next_identity = DeviceIdentity::new(
            tenant,
            device,
            CredentialGeneration::try_from(2).expect("generation"),
        );
        let initial_files = issue_credentials(&root.path().join("initial"), &initial_identity);
        let next_files = issue_credentials(&root.path().join("catalog/material"), &next_identity);
        let artifact_digest = compute_artifact_digest(&next_files)
            .expect("digest")
            .expose()
            .to_owned();
        let artifact_id = "fixture-device-certificate-0001".to_owned();
        let catalog = serde_json::json!({
            "schemaVersion": 1,
            "artifacts": [{
                "artifactId": artifact_id,
                "artifactDigest": artifact_digest,
                "tenantId": tenant,
                "deviceId": device,
                "credentialGeneration": 2,
                "desiredGeneration": 2,
                "fenceEpoch": 2,
                "intentDigest": INTENT,
                "policyHash": POLICY,
                "caPath": "material/ca.pem",
                "certificatePath": "material/certificate.pem",
                "privateKeyPath": "material/private-key.pem",
                "revoked": false
            }]
        });
        fs::create_dir_all(root.path().join("catalog")).expect("catalog dir");
        fs::write(
            root.path().join("catalog/catalog.json"),
            serde_json::to_vec(&catalog).expect("catalog JSON"),
        )
        .expect("catalog");
        Self {
            root,
            device,
            initial_identity,
            initial_files,
            artifact_id,
            artifact_digest,
        }
    }

    fn config(&self) -> AgentConfig {
        AgentConfig::new(
            self.initial_identity.clone(),
            self.root.path().join("state"),
            ArtifactCatalog::new(self.root.path().join("catalog/catalog.json")),
            InstalledCredentialPosition::new(
                Generation::try_from(1).expect("generation"),
                FenceEpoch::try_from(1).expect("fence"),
                CredentialRevision::try_from(1).expect("revision"),
            ),
            self.initial_files.clone(),
        )
    }

    fn open_agent(&self) -> ReferenceDeviceAgent {
        ReferenceDeviceAgent::open(self.config(), NOW).expect("open agent")
    }

    fn agent_and_command(&self) -> (ReferenceDeviceAgent, DeviceCommand) {
        let command = self.command(
            "command-0001",
            &self.artifact_id,
            &self.artifact_digest,
            NOW + 600,
            2,
            2,
        );
        (self.open_agent(), command)
    }

    fn command_topic(&self) -> String {
        TopicSet::new(&self.initial_identity).command().to_owned()
    }

    fn set_catalog_position(&self, generation: u64, fence: u64) {
        let path = self.root.path().join("catalog/catalog.json");
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("catalog")).expect("catalog JSON");
        catalog["artifacts"][0]["desiredGeneration"] = serde_json::json!(generation);
        catalog["artifacts"][0]["fenceEpoch"] = serde_json::json!(fence);
        fs::write(path, serde_json::to_vec(&catalog).expect("catalog JSON"))
            .expect("rewrite catalog");
    }

    fn set_catalog_revoked(&self, revoked: bool) {
        let path = self.root.path().join("catalog/catalog.json");
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("catalog")).expect("catalog JSON");
        catalog["artifacts"][0]["revoked"] = serde_json::json!(revoked);
        fs::write(path, serde_json::to_vec(&catalog).expect("catalog JSON"))
            .expect("rewrite catalog");
    }

    fn command(
        &self,
        command_id: &str,
        artifact_id: &str,
        artifact_digest: &str,
        deadline: u64,
        generation: u64,
        fence: u64,
    ) -> DeviceCommand {
        DeviceCommand::new(
            CommandId::try_from(command_id).expect("command id"),
            self.device,
            ArtifactId::try_from(artifact_id.to_owned()).expect("artifact id"),
            Sha256Digest::try_from(artifact_digest.to_owned()).expect("digest"),
            Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-0123456789ab").expect("receipt"),
            NonZeroU64::new(deadline).expect("deadline"),
            Generation::try_from(generation).expect("generation"),
            FenceEpoch::try_from(fence).expect("fence"),
            Sha256Digest::try_from(INTENT).expect("intent"),
            Sha256Digest::try_from(POLICY).expect("policy"),
        )
    }
}

fn issue_credentials(directory: &Path, identity: &DeviceIdentity) -> CredentialFiles {
    fs::create_dir_all(directory).expect("credential directory");
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA");

    let key = KeyPair::generate().expect("device key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("device params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::URI(
        identity.principal_urn().try_into().expect("URI SAN"),
    )];
    let certificate = params.signed_by(&key, &ca).expect("device certificate");

    let ca_path = directory.join("ca.pem");
    let certificate_path = directory.join("certificate.pem");
    let private_key_path = directory.join("private-key.pem");
    fs::write(&ca_path, ca.pem()).expect("CA PEM");
    fs::write(&certificate_path, certificate.pem()).expect("certificate PEM");
    fs::write(&private_key_path, key.serialize_pem()).expect("key PEM");
    owner_only(&private_key_path);
    CredentialFiles::new(ca_path, certificate_path, private_key_path)
}

#[cfg(unix)]
fn owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("key permissions");
}

#[cfg(not(unix))]
fn owner_only(_path: &Path) {}
