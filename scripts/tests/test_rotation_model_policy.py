from pathlib import Path
import tomllib
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY / "crates/rotation-model/Cargo.toml"
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
FORBIDDEN_TRANSPORT_OR_PROVIDER_PACKAGES = {
    "http",
    "hyper",
    "keycloak",
    "paho-mqtt",
    "reqwest",
    "rumqttc",
    "serde",
    "serde-json",
    "vault",
}


def dependency_declarations(manifest):
    for table_name in DEPENDENCY_TABLES:
        yield from manifest.get(table_name, {}).items()
    for target in manifest.get("target", {}).values():
        for table_name in DEPENDENCY_TABLES:
            yield from target.get(table_name, {}).items()


def dependency_policy_violations(manifest):
    violations = []
    for alias, specification in dependency_declarations(manifest):
        package = (
            specification.get("package", alias)
            if isinstance(specification, dict)
            else alias
        ).replace("_", "-")
        if package.startswith("rss-"):
            violations.append(f"{package}: RSS coupling")
        if package in FORBIDDEN_TRANSPORT_OR_PROVIDER_PACKAGES:
            violations.append(f"{package}: transport/provider coupling")
        if isinstance(specification, dict):
            forbidden_sources = {"path", "git", "workspace"}.intersection(specification)
            if forbidden_sources:
                violations.append(
                    f"{package}: source/workspace coupling via {sorted(forbidden_sources)}"
                )
    return violations


class RotationModelPolicyTests(unittest.TestCase):
    def test_rotation_model_is_non_publishable_and_transport_neutral(self):
        manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))

        self.assertFalse(manifest["package"]["publish"])
        self.assertEqual(dependency_policy_violations(manifest), [])

    def test_rotation_model_policy_rejects_each_forbidden_edge_semantically(self):
        manifest = {
            "dependencies": {
                "contracts": {"package": "rss-device-security-contracts", "version": "=0.1.0"},
                "wire": {"package": "serde_json", "version": "1"},
                "transport": {"package": "reqwest", "version": "0.13"},
                "source": {"package": "helper", "path": "../helper"},
            },
            "target": {
                "cfg(unix)": {
                    "dev-dependencies": {
                        "provider": {"package": "vault", "git": "https://example.invalid/vault"}
                    }
                }
            },
        }

        violations = dependency_policy_violations(manifest)
        self.assertEqual(len(violations), 6)
        self.assertTrue(any("RSS coupling" in violation for violation in violations))
        self.assertTrue(any("transport/provider coupling" in violation for violation in violations))
        self.assertTrue(any("source/workspace coupling" in violation for violation in violations))


if __name__ == "__main__":
    unittest.main()
