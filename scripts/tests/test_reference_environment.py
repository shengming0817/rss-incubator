import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/reference-environment.py"
COMPOSE = ROOT / "deploy/compose.yaml"
FIXTURE = ROOT / "policies/reference-fixture.json"


def load_reference_environment():
    spec = importlib.util.spec_from_file_location("reference_environment", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReferenceEnvironmentPolicyTests(unittest.TestCase):
    def test_canonical_layout_exists(self):
        expected = {
            SCRIPT,
            COMPOSE,
            FIXTURE,
            ROOT / "deploy/keycloak/realm.json",
            ROOT / "deploy/keycloak/tenant-attribute.json",
            ROOT / "deploy/vault/deviceidentity-sign.hcl",
            ROOT / "deploy/vault/roles.json",
            ROOT / "deploy/mosquitto/mosquitto.conf",
            ROOT / "deploy/postgres/bootstrap.sql",
        }
        self.assertEqual([], sorted(str(path.relative_to(ROOT)) for path in expected if not path.is_file()))

    def test_compose_model_is_closed_and_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            environment = os.environ.copy()
            environment.update(
                {
                    "REFERENCE_STATE": str(state),
                    "REFERENCE_OWNER": "0" * 32,
                    "HOST_UID": str(os.getuid()),
                    "HOST_GID": str(os.getgid()),
                    "VAULT_ROOT_TOKEN": "unit-vault-token",
                    "POSTGRES_SUPERUSER_PASSWORD": "unit-postgres-password",
                    "KEYCLOAK_ADMIN_PASSWORD": "unit-keycloak-password",
                    "KEYCLOAK_DB_PASSWORD": "unit-keycloak-db-password",
                    "DEVICEIDENTITY_MIGRATOR_PASSWORD": "unit-migrator-password",
                    "DEVICEIDENTITY_APP_PASSWORD": "unit-app-password",
                    "DEVICEIDENTITY_CLIENT_SECRET": "unit-client-secret",
                    "OPERATOR_PASSWORD": "unit-operator-password",
                    "KEYCLOAK_PORT": "18080",
                    "VAULT_PORT": "18200",
                    "MQTT_PORT": "18883",
                }
            )
            completed = subprocess.run(
                ["docker", "compose", "-f", str(COMPOSE), "config", "--format", "json"],
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
        model = json.loads(completed.stdout)
        self.assertEqual({"keycloak", "mosquitto", "postgres", "vault"}, set(model["services"]))
        expected_images = {
            "keycloak": "quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13",
            "vault": "hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54",
            "mosquitto": "eclipse-mosquitto:2.0.22-openssl@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c",
            "postgres": "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382",
        }
        self.assertEqual(expected_images, {name: service["image"] for name, service in model["services"].items()})
        for service in model["services"].values():
            self.assertNotIn("build", service)
            self.assertNotIn("rss", service["image"].lower())
            self.assertIn("healthcheck", service)
            self.assertEqual("0" * 32, service["labels"]["rss.reference.owner"])
            for port in service.get("ports", []):
                self.assertEqual("127.0.0.1", port.get("host_ip"))
                self.assertNotEqual(1883, port["target"])
        self.assertEqual(
            f"{os.getuid()}:{os.getgid()}", model["services"]["vault"]["user"]
        )
        self.assertEqual(
            f"{os.getuid()}:{os.getgid()}", model["services"]["mosquitto"]["user"]
        )
        self.assertEqual(f"{os.getuid()}:0", model["services"]["keycloak"]["user"])
        self.assertEqual(
            "false", model["services"]["keycloak"]["environment"]["KC_HTTP_ENABLED"]
        )
        self.assertEqual(8443, model["services"]["keycloak"]["ports"][0]["target"])
        self.assertIn(
            "<redacted-root-token>", " ".join(model["services"]["vault"]["command"])
        )
        state_root = str(state)
        self.assertNotIn(
            state_root,
            {volume["source"] for volume in model["services"]["keycloak"].get("volumes", [])},
        )
        self.assertEqual(
            {
                f"{state_root}/pki/ca.pem",
                f"{state_root}/pki/server.crt",
                f"{state_root}/pki/server.key",
                f"{state_root}/mosquitto",
                f"{state_root}/mosquitto-data",
            },
            {
                volume["source"]
                for volume in model["services"]["mosquitto"]["volumes"]
                if volume["source"].startswith(state_root)
            },
        )
        self.assertEqual(
            {f"{state_root}/pki", f"{state_root}/vault-tls"},
            {
                volume["source"]
                for volume in model["services"]["vault"]["volumes"]
                if volume["source"].startswith(state_root)
            },
        )
        self.assertEqual(
            {
                f"{state_root}/pki/ca.pem",
                f"{state_root}/pki/keycloak.crt",
                f"{state_root}/pki/keycloak.key",
            },
            {
                volume["source"]
                for volume in model["services"]["keycloak"]["volumes"]
                if volume["source"].startswith(state_root)
            },
        )
        lifecycle = SCRIPT.read_text(encoding="utf-8")
        for image in expected_images.values():
            self.assertNotIn(image, lifecycle)

    def test_fixture_is_a_stable_disposable_exact_set(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "schemaVersion",
                "tenantId",
                "deviceId",
                "generation",
                "resourceFact",
                "rotationPolicy",
                "mqtt",
            },
            set(fixture),
        )
        self.assertEqual(1, fixture["schemaVersion"])
        self.assertEqual(1, fixture["generation"])
        self.assertEqual(
            {
                "identity.device-command-acked",
                "identity.device-certificate-reported",
            },
            set(fixture["mqtt"]["uplinkContracts"]),
        )
        self.assertEqual(
            {
                "identity.apply-device-certificate",
                "identity.device-ingress-receipted",
            },
            set(fixture["mqtt"]["downlinkContracts"]),
        )
        self.assertNotIn("#", json.dumps(fixture))
        self.assertNotIn("+", json.dumps(fixture))

    def test_provider_configs_fail_closed(self):
        mosquitto = (ROOT / "deploy/mosquitto/mosquitto.conf").read_text(encoding="utf-8")
        self.assertIn("listener 8883", mosquitto)
        self.assertIn("allow_anonymous false", mosquitto)
        self.assertIn("require_certificate true", mosquitto)
        self.assertIn("use_identity_as_username true", mosquitto)
        self.assertNotIn("listener 1883", mosquitto)

        policy = (ROOT / "deploy/vault/deviceidentity-sign.hcl").read_text(encoding="utf-8")
        self.assertIn('path "device-pki/sign/mqtt-device"', policy)
        self.assertIn('"ttl" = []', policy)
        self.assertNotIn('path "device-pki/sign/mqtt-service"', policy)
        self.assertNotIn('path "device-pki/sign/mosquitto-server"', policy)
        self.assertNotIn('path "device-pki/root', policy)
        self.assertNotIn('capabilities = ["sudo"]', policy)

        vault_roles = json.loads(
            (ROOT / "deploy/vault/roles.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {"mosquitto-server", "keycloak-server", "mqtt-device", "mqtt-service"},
            set(vault_roles["roles"]),
        )
        self.assertTrue(
            all(not role["allow_ip_sans"] for role in vault_roles["roles"].values())
        )

        realm = json.loads(
            (ROOT / "deploy/keycloak/realm.json").read_text(encoding="utf-8")
        )
        self.assertEqual("rss-device-security", realm["realm"])
        self.assertEqual(
            {"rotation-control", "deviceidentity"},
            {client["clientId"] for client in realm["clients"]},
        )
        self.assertEqual(
            {"rotation-operator", "deviceidentity-service"},
            {role["name"] for role in realm["roles"]["realm"]},
        )

        postgres = (ROOT / "deploy/postgres/bootstrap.sql").read_text(encoding="utf-8")
        for forbidden in (
            "SUPERUSER",
            "CREATEDB",
            "CREATEROLE",
            "REPLICATION",
            "BYPASSRLS",
        ):
            self.assertIn(f"NO{forbidden}", postgres)
        self.assertIn("REVOKE CREATE ON SCHEMA public FROM PUBLIC", postgres)

    def test_secret_material_is_runtime_only(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("/deploy/.state/", gitignore)
        module = load_reference_environment()
        self.assertEqual([], module.tracked_secret_violations(module.git_tracked_entries()))

    def test_secret_detector_has_synthetic_red_cases(self):
        module = load_reference_environment()
        private_key = b"-----BEGIN " + b"PRIVATE KEY-----\nsynthetic\n"
        vault_token = b"token=" + b"hvs." + b"syntheticcredentialvalue"
        password = b"password=" + (b"a" * 40)
        violations = module.tracked_secret_violations(
            {
                "deploy/.state/forced/runtime.env": b"synthetic",
                "README-secret.md": private_key,
                "scripts/token.txt": vault_token,
                "policies/password.txt": password,
            }
        )
        self.assertEqual(4, len(violations), violations)

    def test_project_and_state_validation_rejects_unsafe_targets(self):
        module = load_reference_environment()
        for invalid in ("", "UPPER", "../escape", "/absolute", "two words", "a" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(module.ReferenceEnvironmentError):
                module.validate_project_name(invalid)

        with tempfile.TemporaryDirectory() as directory:
            deploy_root = Path(directory)
            state = module.state_directory("valid-project", deploy_root=deploy_root)
            state.mkdir(parents=True)
            with self.assertRaises(module.ReferenceEnvironmentError):
                module.remove_state(state, "valid-project", deploy_root=deploy_root)

            module.write_sentinel(state, "valid-project", deploy_root=deploy_root)
            outside = deploy_root.parent / "outside-reference-state"
            outside.mkdir(exist_ok=True)
            self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
            with self.assertRaises(module.ReferenceEnvironmentError):
                module.remove_state(outside, "valid-project", deploy_root=deploy_root)
            module.remove_state(state, "valid-project", deploy_root=deploy_root)
            self.assertFalse(state.exists())

    def test_empty_state_never_adopts_an_existing_project_namespace(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "empty-state"
            state.mkdir()
            environment = object.__new__(module.ReferenceEnvironment)
            environment.project = "valid-project"
            environment.state = state
            environment.env_file = state / "runtime.env"
            with mock.patch.object(
                environment,
                "project_resources",
                return_value={"containers": ["foreign"], "networks": [], "volumes": []},
            ), self.assertRaises(module.ReferenceEnvironmentError):
                environment.initialize_state()

    def test_existing_state_checks_resource_ownership_at_the_shared_funnel(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            environment = object.__new__(module.ReferenceEnvironment)
            environment.project = "valid-project"
            environment.state = state
            environment.env_file = state / "runtime.env"
            environment.env_file.touch()
            calls = []
            environment.load_runtime_values = lambda: calls.append("runtime")
            environment.verify_resource_ownership = lambda: calls.append("ownership")
            with mock.patch.object(module, "validate_sentinel"):
                environment.require_state()
        self.assertEqual(["runtime", "ownership"], calls)

    def test_mqtt_v5_denial_is_not_confused_with_cli_success(self):
        module = load_reference_environment()
        denied = subprocess.CompletedProcess(
            ["mosquitto_pub"], 0, stdout="", stderr="Warning: Publish failed: Not authorized."
        )
        accepted = subprocess.CompletedProcess(
            ["mosquitto_pub"], 0, stdout="", stderr=""
        )
        self.assertTrue(module.ReferenceEnvironment.mqtt_was_denied(denied))
        self.assertFalse(module.ReferenceEnvironment.mqtt_was_denied(accepted))

    def test_log_redaction_includes_persisted_runtime_token(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            environment = object.__new__(module.ReferenceEnvironment)
            environment.state = state
            environment.values = {"VAULT_ROOT_TOKEN": "a" * 48}
            (state / "vault-runtime-token").write_text("runtime-token-value\n", encoding="utf-8")
            redacted = environment.redact(
                f"root={'a' * 48}; runtime=runtime-token-value"
            )
        self.assertNotIn("a" * 48, redacted)
        self.assertNotIn("runtime-token-value", redacted)


if __name__ == "__main__":
    unittest.main()
