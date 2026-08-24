use std::fs;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    SanType, date_time_ymd,
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
    let ack = accept_and_confirm_ack(&fixture, &mut agent, &command);
    drop(agent);
    reconnect_confirm_report_and_replay(&fixture, &command, &ack);
}

fn accept_and_confirm_ack(
    fixture: &Fixture,
    agent: &mut ReferenceDeviceAgent,
    command: &DeviceCommand,
) -> OutboundFact {
    let command_topic = TopicSet::new(&fixture.initial_identity)
        .command()
        .to_owned();

    assert_eq!(
        agent
            .apply_command(&command_topic, command, NOW)
            .expect("apply"),
        ApplyOutcome::Accepted
    );
    assert!(agent.rotation_in_flight());
    let settlement_token = agent
        .pending_settlement_token(command)
        .expect("settlement token")
        .to_owned();
    agent
        .mark_pending_inbound_settled(&settlement_token)
        .expect("inbound PUBACK outgoing");
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

    ack
}

fn reconnect_confirm_report_and_replay(
    fixture: &Fixture,
    command: &DeviceCommand,
    expected_ack: &OutboundFact,
) {
    let mut reopened = fixture.open_agent();
    assert!(reopened.next_outbound().is_none());
    reopened
        .mark_current_credential_connected(CredentialRevision::try_from(2).expect("revision"))
        .expect("new credential connected");
    assert!(reopened.rotation_in_flight());
    let report = reopened.next_outbound().expect("report after reconnect");
    assert!(matches!(report, OutboundFact::CertificateReported { .. }));
    reopened
        .confirm_outbound(report.event_id())
        .expect("confirm report");
    assert!(reopened.next_outbound().is_none());
    assert!(!reopened.rotation_in_flight());

    let current_topic = TopicSet::new(&reopened.current_identity().expect("identity"))
        .command()
        .to_owned();
    assert_eq!(
        reopened
            .apply_command(&current_topic, command, NOW)
            .expect("duplicate"),
        ApplyOutcome::Duplicate
    );
    let replayed = reopened.next_outbound().expect("replayed ACK");
    assert_eq!(&replayed, expected_ack);
}

#[test]
fn committed_rotation_recognizes_only_its_old_delivery_after_restart() {
    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    let old_topic = fixture.command_topic();
    agent
        .apply_command(&old_topic, &command, NOW)
        .expect("accept rotation");
    drop(agent);

    let mut reopened = fixture.open_agent();
    assert_eq!(reopened.pending_command_topic(), Some(old_topic.as_str()));
    assert_eq!(reopened.pending_command_id(), Some("command-0001"));
    assert_eq!(
        reopened
            .delivery_identity(&old_topic, "command-0001")
            .expect("durable recovery identity")
            .credential_generation()
            .get(),
        1
    );
    assert!(matches!(
        reopened.delivery_identity(&old_topic, "another-command"),
        Err(AgentError::UnexpectedDelivery)
    ));
    assert_eq!(
        reopened
            .apply_command(&old_topic, &command, NOW)
            .expect("redelivery replay"),
        ApplyOutcome::Duplicate
    );
    reopened
        .mark_pending_inbound_absent()
        .expect("unsubscribe barrier without another redelivery");
    let unrelated = fixture.command(
        "another-command",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW + 600,
        3,
        3,
    );
    assert!(matches!(
        reopened.apply_command(&old_topic, &unrelated, NOW),
        Err(AgentError::RotationInFlight)
    ));

    let ack = reopened.next_outbound().expect("ACK");
    reopened
        .confirm_outbound(ack.event_id())
        .expect("ACK PUBACK");
    reopened
        .mark_current_credential_connected(CredentialRevision::try_from(2).expect("revision"))
        .expect("reconnect");
    let report = reopened.next_outbound().expect("report");
    reopened
        .confirm_outbound(report.event_id())
        .expect("report PUBACK");
    assert!(reopened.pending_command_topic().is_none());
    assert!(matches!(
        reopened.delivery_identity(&old_topic, "command-0001"),
        Err(AgentError::UnexpectedDelivery)
    ));
}

#[test]
fn report_is_durably_blocked_until_exact_inbound_settlement() {
    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    agent
        .apply_command(&fixture.command_topic(), &command, NOW)
        .expect("accept rotation");
    let ack = agent.next_outbound().expect("ACK");
    agent.confirm_outbound(ack.event_id()).expect("ACK PUBACK");
    agent
        .mark_current_credential_connected(CredentialRevision::try_from(2).expect("revision"))
        .expect("reconnect");
    assert!(agent.next_outbound().is_none());
    assert!(!agent.pending_inbound_settled());
    assert!(matches!(
        agent.mark_pending_inbound_settled("reference-settlement-wrong"),
        Err(AgentError::UnexpectedDelivery)
    ));

    drop(agent);
    let mut reopened = fixture.open_agent();
    assert!(!reopened.pending_inbound_settled());
    assert!(reopened.next_outbound().is_none());
    reopened
        .mark_pending_inbound_absent()
        .expect("unsubscribe barrier");
    assert!(matches!(
        reopened.next_outbound(),
        Some(OutboundFact::CertificateReported { .. })
    ));
}

#[test]
fn conflicting_replay_redelivery_reuses_one_durable_rejection() {
    let fixture = Fixture::new();
    let (mut agent, accepted) = fixture.agent_and_command();
    let topic = fixture.command_topic();
    agent
        .apply_command(&topic, &accepted, NOW)
        .expect("accept rotation");
    let conflicting = fixture.command(
        "command-0001",
        "different-artifact",
        &fixture.artifact_digest,
        NOW + 600,
        2,
        2,
    );
    for _ in 0..2 {
        assert_eq!(
            agent
                .apply_command(&topic, &conflicting, NOW)
                .expect("stable rejection"),
            ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
        );
    }
    let accepted_ack = agent.next_outbound().expect("accepted ACK");
    agent
        .confirm_outbound(accepted_ack.event_id())
        .expect("accepted ACK PUBACK");
    let rejection = agent.next_outbound().expect("one rejection");
    agent
        .confirm_outbound(rejection.event_id())
        .expect("rejection PUBACK");
    assert!(agent.next_outbound().is_none());
}

#[test]
fn terminal_command_journal_survives_newer_commands_and_restart() {
    let fixture = Fixture::new();
    let mut agent = fixture.open_agent();
    let topic = fixture.command_topic();
    let first = fixture.command(
        "expired-command-first",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW,
        2,
        2,
    );
    let second = fixture.command(
        "expired-command-second",
        &fixture.artifact_id,
        &fixture.artifact_digest,
        NOW,
        2,
        2,
    );

    for command in [&first, &second] {
        assert_eq!(
            agent.apply_command(&topic, command, NOW).expect("reject"),
            ApplyOutcome::Rejected(CommandRejection::PolicyRejected)
        );
        let acknowledgement = agent.next_outbound().expect("ACK");
        agent
            .confirm_outbound(acknowledgement.event_id())
            .expect("ACK PUBACK");
    }
    drop(agent);

    let mut reopened = fixture.open_agent();
    assert_eq!(
        reopened
            .apply_command(&topic, &first, NOW)
            .expect("historic duplicate"),
        ApplyOutcome::Duplicate
    );
}

#[test]
fn state_root_has_one_live_process_owner() {
    let fixture = Fixture::new();
    let owner = fixture.open_agent();
    assert!(matches!(
        ReferenceDeviceAgent::open(fixture.config(), NOW),
        Err(AgentError::Store(StoreError::AlreadyOpen))
    ));
    drop(owner);
    drop(fixture.open_agent());
}

#[test]
fn malformed_delivery_is_durably_terminal_before_puback() {
    let fixture = Fixture::new();
    let mut agent = fixture.open_agent();
    let topic = fixture.command_topic();

    assert_eq!(
        agent
            .reject_malformed_delivery(&topic, "poison-command", b"{", NOW)
            .expect("durable poison disposition"),
        ApplyOutcome::Rejected(CommandRejection::MalformedCommand)
    );
    let acknowledgement = agent.next_outbound().expect("malformed ACK");
    agent
        .confirm_outbound(acknowledgement.event_id())
        .expect("ACK PUBACK");
    drop(agent);

    let mut reopened = fixture.open_agent();
    assert_eq!(
        reopened
            .reject_malformed_delivery(&topic, "poison-command", b"{", NOW)
            .expect("durable duplicate"),
        ApplyOutcome::Duplicate
    );
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
fn corrupt_event_causality_and_rotation_phase_fail_closed() {
    for mutation in ["event-id", "ack-outcome", "premature-report"] {
        let fixture = Fixture::new();
        let (mut agent, command) = fixture.agent_and_command();
        agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("accept");
        drop(agent);
        let state_path = fixture.root.path().join("state/state.v1.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).expect("state")).expect("JSON");
        match mutation {
            "event-id" => {
                state["outbox"][0]["eventId"] = serde_json::json!(
                    "reference-ack-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                );
            }
            "ack-outcome" => {
                state["outbox"][0]["payload"]["activatesRevision"] = serde_json::Value::Null;
            }
            "premature-report" => {
                state["outbox"][1]["kind"] = serde_json::json!("reportReady");
            }
            _ => unreachable!(),
        }
        fs::write(&state_path, serde_json::to_vec(&state).expect("serialize")).expect("corrupt");

        let error = ReferenceDeviceAgent::open(fixture.config(), NOW)
            .expect_err("corrupt phase must fail closed");
        assert!(matches!(error, AgentError::Store(StoreError::InvalidState)));
    }
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
    for index in 0..127 {
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
    assert!(!agent.command_intake_open(NOW));
    let final_command = fixture.command(
        "missing-command-final",
        "missing-artifact-final",
        &fixture.artifact_digest,
        NOW + 600,
        2,
        2,
    );
    assert_eq!(
        agent
            .apply_command(&topic, &final_command, NOW)
            .expect("final one-slot rejection"),
        ApplyOutcome::Rejected(CommandRejection::ArtifactUnavailable)
    );
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
    let settlement_token = agent
        .pending_settlement_token(&accepted)
        .expect("settlement token")
        .to_owned();
    agent
        .mark_pending_inbound_settled(&settlement_token)
        .expect("inbound PUBACK outgoing");
    let ack = agent.next_outbound().expect("ACK");
    agent.confirm_outbound(ack.event_id()).expect("ACK PUBACK");
    agent
        .mark_current_credential_connected(CredentialRevision::try_from(2).expect("revision"))
        .expect("reconnect");
    let report = agent.next_outbound().expect("report");
    agent
        .confirm_outbound(report.event_id())
        .expect("report PUBACK");
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
fn catalog_ancestor_symlink_swap_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let catalog = fixture.root.path().join("catalog");
    let material = catalog.join("material");
    let outside = fixture.root.path().join("outside-material");
    fs::rename(&material, &outside).expect("move material outside catalog");
    symlink(&outside, &material).expect("ancestor symlink");
    let (mut agent, command) = fixture.agent_and_command();

    assert_eq!(
        agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("ancestor symlink rejection"),
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

#[test]
fn catalog_rejects_wrong_identity_expired_untrusted_and_mismatched_key_material() {
    for case in ["identity", "expired", "untrusted", "key-mismatch"] {
        let fixture = Fixture::new();
        let material = fixture.root.path().join("catalog/material");
        match case {
            "identity" => {
                let wrong = DeviceIdentity::try_new(
                    fixture.initial_identity.tenant(),
                    Uuid::parse_str("00000000-0000-0000-0000-000000000999").expect("wrong device"),
                    CredentialGeneration::try_from(2).expect("generation"),
                )
                .expect("identity");
                issue_credentials(&material, &wrong);
            }
            "expired" => {
                let next = DeviceIdentity::try_new(
                    fixture.initial_identity.tenant(),
                    fixture.device,
                    CredentialGeneration::try_from(2).expect("generation"),
                )
                .expect("identity");
                issue_expired_credentials(&material, &next);
            }
            "untrusted" => {
                let next = DeviceIdentity::try_new(
                    fixture.initial_identity.tenant(),
                    fixture.device,
                    CredentialGeneration::try_from(2).expect("generation"),
                )
                .expect("identity");
                let replacement =
                    issue_credentials(&fixture.root.path().join("untrusted-material"), &next);
                fs::copy(
                    replacement.certificate_chain(),
                    material.join("certificate.pem"),
                )
                .expect("certificate");
                fs::copy(replacement.private_key(), material.join("private-key.pem")).expect("key");
                owner_only(&material.join("private-key.pem"));
            }
            "key-mismatch" => {
                let replacement = KeyPair::generate().expect("replacement key");
                fs::write(
                    material.join("private-key.pem"),
                    replacement.serialize_pem(),
                )
                .expect("key");
                owner_only(&material.join("private-key.pem"));
            }
            _ => unreachable!(),
        }
        let files = CredentialFiles::new(
            material.join("ca.pem"),
            material.join("certificate.pem"),
            material.join("private-key.pem"),
        );
        let digest = compute_artifact_digest(&files)
            .expect("digest")
            .expose()
            .to_owned();
        fixture.set_catalog_digest(&digest);
        let command = fixture.command(
            "invalid-credential-command",
            &fixture.artifact_id,
            &digest,
            NOW + 600,
            2,
            2,
        );
        let mut agent = fixture.open_agent();
        let outcome = agent
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("credential rejection");
        assert!(matches!(
            outcome,
            ApplyOutcome::Rejected(
                CommandRejection::PolicyRejected | CommandRejection::DeviceFailure
            )
        ));
        assert!(
            !fixture
                .root
                .path()
                .join("state/credentials/revision-2")
                .exists()
        );
    }
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

#[cfg(unix)]
#[test]
fn installed_orphan_revision_never_becomes_current_after_state_commit_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let (mut agent, command) = fixture.agent_and_command();
    let state_root = fixture.root.path().join("state");
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o500))
        .expect("make manifest directory read-only");

    let result = agent.apply_command(&fixture.command_topic(), &command, NOW);

    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .expect("restore state permissions");
    assert!(matches!(
        result,
        Err(AgentError::Store(StoreError::Unavailable))
    ));
    assert!(state_root.join("credentials/revision-2").is_dir());
    assert_eq!(
        agent
            .current_identity()
            .expect("in-memory identity")
            .credential_generation()
            .get(),
        1
    );

    drop(agent);
    let mut reopened = fixture.open_agent();
    assert_eq!(
        reopened
            .current_identity()
            .expect("durable identity")
            .credential_generation()
            .get(),
        1
    );
    assert_eq!(
        reopened
            .apply_command(&fixture.command_topic(), &command, NOW)
            .expect("reuse matching orphan"),
        ApplyOutcome::Accepted
    );
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
        let initial_identity = DeviceIdentity::try_new(
            tenant,
            device,
            CredentialGeneration::try_from(1).expect("generation"),
        )
        .expect("identity");
        let next_identity = DeviceIdentity::try_new(
            tenant,
            device,
            CredentialGeneration::try_from(2).expect("generation"),
        )
        .expect("identity");
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
            NonZeroU32::new(300).expect("retention"),
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

    fn set_catalog_digest(&self, digest: &str) {
        let path = self.root.path().join("catalog/catalog.json");
        let mut catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("catalog")).expect("catalog JSON");
        catalog["artifacts"][0]["artifactDigest"] = serde_json::json!(digest);
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
    issue_credentials_with_dates(directory, identity, false)
}

fn issue_expired_credentials(directory: &Path, identity: &DeviceIdentity) -> CredentialFiles {
    issue_credentials_with_dates(directory, identity, true)
}

fn issue_credentials_with_dates(
    directory: &Path,
    identity: &DeviceIdentity,
    expired: bool,
) -> CredentialFiles {
    fs::create_dir_all(directory).expect("credential directory");
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA");

    let key = KeyPair::generate().expect("device key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("device params");
    if expired {
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2021, 1, 1);
    }
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
