use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn binary() -> Command {
    Command::cargo_bin("rotation-control").expect("binary")
}

#[test]
fn help_and_version_are_json_successes() {
    binary()
        .env_clear()
        .arg("--help")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"operation\":\"help\"")
                .and(predicate::str::contains("rotate")),
        );
    binary()
        .env_clear()
        .arg("--version")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"operation\":\"version\"")
                .and(predicate::str::contains("rotation-control")),
        );
}

#[test]
fn policy_check_reports_counts_without_sans_or_environment_bait() {
    let directory = tempdir().expect("tempdir");
    let input = directory.path().join("policy.json");
    fs::write(&input, r#"{"keyUsages":["clientAuth"],"renewBeforeSeconds":600,"sans":["private.device.example"],"validitySeconds":3600}"#).expect("policy");
    let output = binary()
        .env_clear()
        .env("ACCESS_TOKEN", "token-bait")
        .env("PRIVATE_KEY", "private-key-bait")
        .args(["policy", "check", "--input", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    let value: Value = serde_json::from_str(&stdout).expect("JSON-only stdout");
    assert_eq!(value["sanCount"], 1);
    for bait in ["private.device.example", "token-bait", "private-key-bait"] {
        assert!(!stdout.contains(bait));
        assert!(!stderr.contains(bait));
    }
}

#[test]
fn invalid_cli_and_input_use_stable_exit_two_and_json_only_diagnostics() {
    binary()
        .env_clear()
        .arg("password-grant")
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"code\":\"invalid_cli\""));
    let directory = tempdir().expect("tempdir");
    let input = directory.path().join("bad.json");
    fs::write(&input, "certificate-bait not json").expect("input");
    binary()
        .env_clear()
        .args(["policy", "check", "--input", input.to_str().expect("path")])
        .assert()
        .code(2)
        .stdout(
            predicate::str::contains("invalid_policy_json")
                .and(predicate::str::contains("certificate-bait").not()),
        );
}

#[test]
fn audit_validates_only_one_rotate_record_and_declares_no_durable_query() {
    let directory = tempdir().expect("tempdir");
    let input = directory.path().join("rotate.json");
    fs::write(&input, r#"{"schemaVersion":"1","operation":"rotate","outcome":"accepted","requestId":"0198d5f2-70de-7a2d-b3f4-012345678901","correlationId":"0198d5f2-70de-7a2d-b3f4-012345678902","authorizationReceiptId":"0198d5f2-70de-7a2d-b3f4-012345678903","acceptedGeneration":2,"condition":"Reconciling"}"#).expect("record");
    binary()
        .env_clear()
        .args(["audit", "--input", input.to_str().expect("path")])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"durableAuditQueried\":false"));
}
