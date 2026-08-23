import ast
from contextlib import redirect_stderr
import importlib.util
import io
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
            ROOT / "deploy/postgres/pg_hba.conf",
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
            {
                f"{state_root}/pki/ca.pem",
                f"{state_root}/pki/postgres.crt",
                f"{state_root}/pki/postgres.key",
            },
            {
                volume["source"]
                for volume in model["services"]["postgres"].get("volumes", [])
                if volume["source"].startswith(state_root)
            },
        )
        self.assertEqual(
            {f"{state_root}/csr", f"{state_root}/vault-tls"},
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
        self.assertEqual(
            {"identity-database", "keycloak-control"},
            set(model["services"]["keycloak"]["networks"]),
        )
        self.assertEqual(
            {"identity-database"}, set(model["services"]["postgres"]["networks"])
        )
        self.assertEqual(
            {"pki", "vault-control"}, set(model["services"]["vault"]["networks"])
        )
        self.assertEqual(
            {"broker", "broker-control"},
            set(model["services"]["mosquitto"]["networks"]),
        )
        self.assertEqual(
            "verify-server",
            model["services"]["keycloak"]["environment"]["KC_DB_TLS_MODE"],
        )
        self.assertEqual(
            "/reference-state/pki/ca.pem",
            model["services"]["keycloak"]["environment"]["KC_DB_TLS_TRUST_STORE_FILE"],
        )
        postgres_command = " ".join(model["services"]["postgres"]["command"])
        self.assertIn("ssl=on", postgres_command)
        self.assertIn("ssl_min_protocol_version=TLSv1.3", postgres_command)
        keycloak_health = " ".join(model["services"]["keycloak"]["healthcheck"]["test"])
        self.assertIn("/health/ready", keycloak_health)
        self.assertIn('"status"[[:space:]]*:[[:space:]]*"UP"', keycloak_health)
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
        self.assertIn('path "{{mount}}/sign/mqtt-device"', policy)
        self.assertIn('"ttl" = []', policy)
        self.assertNotIn('path "{{mount}}/sign/mqtt-service"', policy)
        self.assertNotIn('path "{{mount}}/sign/mosquitto-server"', policy)
        self.assertNotIn('/root', policy)
        self.assertNotIn('capabilities = ["sudo"]', policy)

        vault_roles = json.loads(
            (ROOT / "deploy/vault/roles.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {
                "mosquitto-server",
                "keycloak-server",
                "postgres-server",
                "mqtt-device",
                "mqtt-service",
            },
            set(vault_roles["roles"]),
        )
        self.assertTrue(
            all(not role["allow_ip_sans"] for role in vault_roles["roles"].values())
        )

        realm = json.loads(
            (ROOT / "deploy/keycloak/realm.json").read_text(encoding="utf-8")
        )
        rotation = next(
            client for client in realm["clients"] if client["clientId"] == "rotation-control"
        )
        self.assertFalse(rotation["directAccessGrantsEnabled"])
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
        postgres_hba = (ROOT / "deploy/postgres/pg_hba.conf").read_text(encoding="utf-8")
        for forbidden in (
            "SUPERUSER",
            "CREATEDB",
            "CREATEROLE",
            "REPLICATION",
            "BYPASSRLS",
        ):
            self.assertIn(f"NO{forbidden}", postgres)
        self.assertIn("REVOKE CREATE ON SCHEMA public FROM PUBLIC", postgres)
        self.assertIn("hostnossl all all all reject", postgres_hba)
        self.assertIn("hostssl all all all scram-sha-256", postgres_hba)

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
        infrastructure_failure = subprocess.CompletedProcess(
            ["mosquitto_pub"], 1, stdout="", stderr="Error: Connection refused"
        )
        self.assertTrue(module.ReferenceEnvironment.mqtt_was_denied(denied))
        self.assertFalse(module.ReferenceEnvironment.mqtt_was_denied(accepted))
        self.assertFalse(module.ReferenceEnvironment.mqtt_was_denied(infrastructure_failure))

    def test_missing_state_reports_the_reachable_up_instruction(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            environment = object.__new__(module.ReferenceEnvironment)
            environment.project = "valid-project"
            environment.state = Path(directory) / "missing"
            environment.env_file = environment.state / "runtime.env"
            with self.assertRaisesRegex(module.ReferenceEnvironmentError, "run `up` first"):
                environment.require_state()

    def test_logs_command_fails_when_compose_logs_fails(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            environment = object.__new__(module.ReferenceEnvironment)
            environment.state = Path(directory)
            environment.values = {}
            environment.require_state = lambda: None
            environment.compose = lambda *args, **kwargs: subprocess.CompletedProcess(
                ["docker", "compose", "logs"], 1, stdout="", stderr="daemon unavailable"
            )
            with redirect_stderr(io.StringIO()), self.assertRaises(
                module.ReferenceEnvironmentError
            ):
                environment.logs()

    def test_mqtt_cli_mounts_only_the_requested_identity_files(self):
        module = load_reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            environment = object.__new__(module.ReferenceEnvironment)
            environment.state = Path(directory)
            pki = environment.state / "pki"
            pki.mkdir()
            for name in ("ca.pem", "device.crt", "device.key"):
                (pki / name).touch()
            environment.compose = lambda *args, **kwargs: subprocess.CompletedProcess(
                ["docker", "compose", "ps"], 0, stdout="a" * 64, stderr=""
            )
            environment.service_image = lambda service: "canonical-mosquitto-image"
            command = environment.mqtt_command_line(
                [
                    "mosquitto_pub",
                    "--cafile",
                    "/reference-state/pki/ca.pem",
                    "--cert",
                    "/reference-state/pki/device.crt",
                    "--key",
                    "/reference-state/pki/device.key",
                ]
            )
        mounts = {
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--mount"
        }
        self.assertEqual(3, len(mounts))
        self.assertFalse(any("source=" + directory + "/pki,target=" in item for item in mounts))

    def test_docker_discovery_is_bounded(self):
        module = load_reference_environment()
        environment = object.__new__(module.ReferenceEnvironment)
        environment.project = "valid-project"
        completed = subprocess.CompletedProcess(["docker"], 0, stdout="", stderr="")
        with mock.patch.object(module, "run", return_value=completed) as execute:
            self.assertEqual(
                {"containers": [], "networks": [], "volumes": []},
                environment.project_resources(),
            )
        self.assertTrue(execute.call_args_list)
        self.assertTrue(all(call.kwargs.get("timeout") == 15 for call in execute.call_args_list))

    def test_provider_identities_have_one_loaded_owner(self):
        lifecycle = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('"/realms/rss-device-security', lifecycle)
        self.assertNotIn('"device-pki/', lifecycle)

    def test_json_parser_maps_malformed_provider_output_to_domain_error(self):
        module = load_reference_environment()
        with self.assertRaisesRegex(module.ReferenceEnvironmentError, "Vault role inventory"):
            module.parse_json("not-json", source="Vault role inventory")
        with self.assertRaisesRegex(module.ReferenceEnvironmentError, "Keycloak clients"):
            module.parse_json('{"wrong":"shape"}', source="Keycloak clients", expected_type=list)

    def test_managed_lifecycle_functions_stay_below_complexity_budget(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        managed = {
            "bootstrap_vault",
            "bootstrap_keycloak",
            "verify_keycloak",
            "load_runtime_values",
            "certificate_matches",
        }
        branching = (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.BoolOp)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in managed:
                complexity = 1 + sum(isinstance(child, branching) for child in ast.walk(node))
                self.assertLessEqual(complexity, 15, f"{node.name} complexity={complexity}")

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
