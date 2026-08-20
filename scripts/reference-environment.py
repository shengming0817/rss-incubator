#!/usr/bin/env python3
"""Manage the disposable Secure Device Rotation provider environment."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_ROOT = ROOT / "deploy"
COMPOSE_FILE = DEPLOY_ROOT / "compose.yaml"
FIXTURE_FILE = ROOT / "policies/reference-fixture.json"
SENTINEL = ".rss-reference-environment.json"
PROJECT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
STATE_SCHEMA = 1
RUNTIME_KEYS = {
    "REFERENCE_STATE",
    "REFERENCE_OWNER",
    "HOST_UID",
    "HOST_GID",
    "VAULT_ROOT_TOKEN",
    "POSTGRES_SUPERUSER_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "KEYCLOAK_DB_PASSWORD",
    "DEVICEIDENTITY_MIGRATOR_PASSWORD",
    "DEVICEIDENTITY_APP_PASSWORD",
    "DEVICEIDENTITY_CLIENT_SECRET",
    "OPERATOR_PASSWORD",
    "VAULT_PORT",
    "KEYCLOAK_PORT",
    "MQTT_PORT",
}
SECRET_MARKERS = ("PASSWORD", "SECRET", "TOKEN")
KEYCLOAK_BUILTIN_CLIENTS = {
    "account",
    "account-console",
    "admin-cli",
    "broker",
    "realm-management",
    "security-admin-console",
}


class ReferenceEnvironmentError(RuntimeError):
    """A fail-closed reference environment error."""


def validate_project_name(project: str) -> str:
    if PROJECT_NAME.fullmatch(project) is None:
        raise ReferenceEnvironmentError(
            "project must be 1..63 lowercase ASCII letters, digits, underscores, or hyphens"
        )
    return project


def state_directory(project: str, *, deploy_root: Path = DEPLOY_ROOT) -> Path:
    validate_project_name(project)
    return deploy_root.resolve() / ".state" / project


def sentinel_payload(project: str, deploy_root: Path) -> dict[str, object]:
    return {
        "schemaVersion": STATE_SCHEMA,
        "project": project,
        "deployRoot": str(deploy_root.resolve()),
    }


def write_sentinel(state: Path, project: str, *, deploy_root: Path = DEPLOY_ROOT) -> None:
    expected = state_directory(project, deploy_root=deploy_root)
    if state.resolve() != expected:
        raise ReferenceEnvironmentError(f"state path escapes the canonical root: {state}")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    path = state / SENTINEL
    write_private_text(
        path,
        json.dumps(sentinel_payload(project, deploy_root), sort_keys=True) + "\n",
    )


def validate_sentinel(
    state: Path, project: str, *, deploy_root: Path = DEPLOY_ROOT
) -> None:
    expected = state_directory(project, deploy_root=deploy_root)
    if state.resolve() != expected:
        raise ReferenceEnvironmentError(f"refusing non-canonical state path: {state}")
    path = state / SENTINEL
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReferenceEnvironmentError(f"state sentinel is missing or invalid: {path}") from error
    if payload != sentinel_payload(project, deploy_root):
        raise ReferenceEnvironmentError(f"state sentinel identity differs: {path}")


def remove_state(
    state: Path, project: str, *, deploy_root: Path = DEPLOY_ROOT
) -> None:
    validate_sentinel(state, project, deploy_root=deploy_root)
    shutil.rmtree(state)


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = True,
    timeout: int | None = None,
    redact: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        display_command = " ".join(command)
        for value in redact:
            if value:
                display_command = display_command.replace(value, "<redacted>")
        raise ReferenceEnvironmentError(
            f"command timed out: {display_command}"
        ) from error
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        display_command = " ".join(command)
        for value in redact:
            if value:
                display_command = display_command.replace(value, "<redacted>")
                detail = detail.replace(value, "<redacted>")
        raise ReferenceEnvironmentError(
            f"command failed ({completed.returncode}): {display_command}\n{detail}"
        )
    return completed


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or "\n" in value or "\r" in value:
            raise ReferenceEnvironmentError(f"invalid runtime environment line in {path}")
        if key in values:
            raise ReferenceEnvironmentError(f"duplicate runtime environment key in {path}: {key}")
        values[key] = value
    return values


def write_private_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    path.chmod(0o600)


@contextmanager
def project_lock(project: str):
    validate_project_name(project)
    lock_root = DEPLOY_ROOT / ".state/.locks"
    lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_root.chmod(0o700)
    lock_path = lock_root / f"{project}.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReferenceEnvironmentError(
                f"another lifecycle command owns project `{project}`"
            ) from error
        yield


def render_fixture_placeholders(value: object, fixture: dict[str, object]) -> object:
    replacements = {
        "{{tenantId}}": str(fixture["tenantId"]),
        "{{deviceId}}": str(fixture["deviceId"]),
        "{{generation}}": str(fixture["generation"]),
        "{{validitySeconds}}": str(fixture["rotationPolicy"]["validitySeconds"]),
        "{{renewBeforeSeconds}}": str(fixture["rotationPolicy"]["renewBeforeSeconds"]),
    }
    if isinstance(value, str):
        for placeholder, replacement in replacements.items():
            value = value.replace(placeholder, replacement)
        if "{{" in value or "}}" in value:
            raise ReferenceEnvironmentError(f"unknown fixture placeholder: {value}")
        return value
    if isinstance(value, list):
        return [render_fixture_placeholders(item, fixture) for item in value]
    if isinstance(value, dict):
        return {
            key: render_fixture_placeholders(item, fixture)
            for key, item in value.items()
        }
    return value


def duration_seconds(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", value)
    if match is None:
        raise ReferenceEnvironmentError(f"unsupported duration: {value}")
    multiplier = {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    return int(match.group(1)) * multiplier


def tracked_secret_violations(entries: dict[str, bytes]) -> list[str]:
    private_markers = (
        b"-----BEGIN " + b"PRIVATE KEY-----",
        b"-----BEGIN " + b"RSA PRIVATE KEY-----",
        b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    )
    credential = re.compile(
        rb"(?i)(password|secret|token)\s*[:=]\s*['\"]?(?:[0-9a-f]{32,}|hvs\.[A-Za-z0-9_-]{16,})"
    )
    violations = []
    for name, contents in entries.items():
        normalized = Path(name).as_posix()
        if normalized == "deploy/.state" or normalized.startswith("deploy/.state/"):
            violations.append(f"tracked runtime state: {normalized}")
        if b"\0" in contents:
            continue
        if any(marker in contents for marker in private_markers):
            violations.append(f"tracked private key: {normalized}")
        if credential.search(contents):
            violations.append(f"tracked credential-shaped value: {normalized}")
    return violations


def git_tracked_entries() -> dict[str, bytes]:
    names = run(["/usr/bin/git", "ls-files", "-z"]).stdout.split("\0")
    return {
        name: (ROOT / name).read_bytes()
        for name in names
        if name and (ROOT / name).is_file()
    }


class ReferenceEnvironment:
    def __init__(self, project: str):
        self.project = validate_project_name(project)
        self.state = state_directory(project)
        self.env_file = self.state / "runtime.env"
        self.fixture = json.loads(FIXTURE_FILE.read_text(encoding="utf-8"))
        self.vault_config = render_fixture_placeholders(
            json.loads((DEPLOY_ROOT / "vault/roles.json").read_text(encoding="utf-8")),
            self.fixture,
        )
        self.values: dict[str, str] = {}
        self._keycloak_port: int | None = None
        self._compose_model: dict[str, object] | None = None

    def private_values(self) -> tuple[str, ...]:
        values = [
            value
            for key, value in self.values.items()
            if any(marker in key for marker in SECRET_MARKERS)
        ]
        token_path = self.state / "vault-runtime-token"
        if token_path.is_file():
            values.append(token_path.read_text(encoding="utf-8").strip())
        return tuple(values)

    def redact(self, text: str) -> str:
        for value in self.private_values():
            text = text.replace(value, "<redacted>")
        return text

    def check_dependencies(self) -> None:
        for executable in ("docker", "openssl"):
            if shutil.which(executable) is None:
                raise ReferenceEnvironmentError(f"required executable is missing: {executable}")
        run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15)
        run(["docker", "compose", "version"], timeout=15)

    def initialize_state(self) -> None:
        if not (self.state / SENTINEL).is_file() and any(
            self.project_resources().values()
        ):
            raise ReferenceEnvironmentError(
                f"refusing to adopt existing Docker resources for project `{self.project}`"
            )
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.chmod(0o700)
        if (self.state / SENTINEL).exists():
            validate_sentinel(self.state, self.project)
        else:
            if any(self.state.iterdir()):
                raise ReferenceEnvironmentError(
                    f"refusing non-empty state without canonical sentinel: {self.state}"
                )
            write_sentinel(self.state, self.project)

        if not self.env_file.exists():
            values = {
                "REFERENCE_STATE": str(self.state),
                "REFERENCE_OWNER": secrets.token_hex(16),
                "HOST_UID": str(os.getuid()),
                "HOST_GID": str(os.getgid()),
                "VAULT_ROOT_TOKEN": secrets.token_hex(24),
                "POSTGRES_SUPERUSER_PASSWORD": secrets.token_hex(24),
                "KEYCLOAK_ADMIN_PASSWORD": secrets.token_hex(24),
                "KEYCLOAK_DB_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_MIGRATOR_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_APP_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_CLIENT_SECRET": secrets.token_hex(24),
                "OPERATOR_PASSWORD": secrets.token_hex(18),
                "VAULT_PORT": "0",
                "KEYCLOAK_PORT": "0",
                "MQTT_PORT": "0",
            }
            write_private_text(
                self.env_file,
                "".join(f"{key}={value}\n" for key, value in sorted(values.items())),
            )
        self.load_runtime_values()
        for directory in ("vault-tls", "pki", "mosquitto", "mosquitto-data"):
            path = self.state / directory
            path.mkdir(exist_ok=True, mode=0o700)
            path.chmod(0o700)

    def require_state(self) -> None:
        validate_sentinel(self.state, self.project)
        if not self.env_file.is_file():
            raise ReferenceEnvironmentError("runtime environment is missing; run `up` first")
        self.load_runtime_values()

    def load_runtime_values(self) -> None:
        values = read_env_file(self.env_file)
        if set(values) != RUNTIME_KEYS:
            missing = sorted(RUNTIME_KEYS - set(values))
            extra = sorted(set(values) - RUNTIME_KEYS)
            raise ReferenceEnvironmentError(
                f"runtime environment key closure differs; missing={missing}, extra={extra}"
            )
        if Path(values["REFERENCE_STATE"]).resolve() != self.state.resolve():
            raise ReferenceEnvironmentError("runtime REFERENCE_STATE differs from canonical state")
        if not re.fullmatch(r"[0-9a-f]{32}", values["REFERENCE_OWNER"]):
            raise ReferenceEnvironmentError("runtime owner identity is invalid")
        if values["HOST_UID"] != str(os.getuid()) or values["HOST_GID"] != str(os.getgid()):
            raise ReferenceEnvironmentError("runtime host ownership differs from this process")
        ports = []
        for key in ("VAULT_PORT", "KEYCLOAK_PORT", "MQTT_PORT"):
            try:
                port = int(values[key])
            except ValueError as error:
                raise ReferenceEnvironmentError(f"runtime port is invalid: {key}") from error
            if port != 0 and not 1024 <= port <= 65535:
                raise ReferenceEnvironmentError(f"runtime port is out of range: {key}")
            ports.append(port)
        explicit_ports = [port for port in ports if port != 0]
        if len(set(explicit_ports)) != len(explicit_ports):
            raise ReferenceEnvironmentError("runtime ports must be distinct")
        for key in RUNTIME_KEYS:
            if any(marker in key for marker in SECRET_MARKERS) and len(values[key]) < 24:
                raise ReferenceEnvironmentError(f"runtime secret is missing or too short: {key}")
        self.values = values

    def compose_command(self, *arguments: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--env-file",
            str(self.env_file),
            "--project-name",
            self.project,
            "--file",
            str(COMPOSE_FILE),
            *arguments,
        ]

    def compose(
        self,
        *arguments: str,
        check: bool = True,
        capture: bool = True,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            self.compose_command(*arguments),
            check=check,
            capture=capture,
            timeout=timeout,
            redact=self.private_values(),
        )

    def compose_exec(
        self,
        service: str,
        arguments: list[str],
        *,
        environment: dict[str, str] | None = None,
        check: bool = True,
        timeout: int | None = 60,
    ) -> subprocess.CompletedProcess[str]:
        command = ["exec", "--no-TTY"]
        for key, value in sorted((environment or {}).items()):
            command.extend(["--env", f"{key}={value}"])
        command.append(service)
        command.extend(arguments)
        return self.compose(*command, check=check, timeout=timeout)

    def compose_model(self) -> dict[str, object]:
        if self._compose_model is None:
            self._compose_model = json.loads(
                self.compose("config", "--format", "json", timeout=30).stdout
            )
        return self._compose_model

    def service_image(self, service: str) -> str:
        services = self.compose_model().get("services", {})
        try:
            return str(services[service]["image"])
        except (KeyError, TypeError) as error:
            raise ReferenceEnvironmentError(
                f"canonical Compose image is missing: {service}"
            ) from error

    def vault(
        self, arguments: list[str], *, token: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "VAULT_ADDR": "https://127.0.0.1:8200",
            "VAULT_CACERT": "/reference-state/vault-tls/vault-ca.pem",
            "VAULT_TOKEN": token or self.values["VAULT_ROOT_TOKEN"],
        }
        return self.compose_exec("vault", ["vault", *arguments], environment=environment, check=check)

    def up(self) -> None:
        self.check_dependencies()
        self.initialize_state()
        self._keycloak_port = None
        self._compose_model = None
        self.compose("config", "--quiet", timeout=30)
        self.compose("up", "--detach", "--wait", "--wait-timeout", "120", "vault", "postgres", timeout=150)
        self.verify_resource_ownership()

    def bootstrap_vault(self) -> None:
        mounts = json.loads(self.vault(["secrets", "list", "-format=json"]).stdout)
        mount = str(self.vault_config["mount"])
        if f"{mount}/" not in mounts:
            self.vault(["secrets", "enable", f"-path={mount}", "pki"])

        ca = self.vault(["read", "-field=certificate", f"{mount}/cert/ca"], check=False)
        if ca.returncode != 0 or "BEGIN CERTIFICATE" not in ca.stdout:
            ca_config = self.vault_config["ca"]
            self.vault(
                [
                    "write",
                    f"{mount}/root/generate/internal",
                    f"common_name={ca_config['commonName']}",
                    f"ttl={ca_config['ttl']}",
                ]
            )
            ca = self.vault(["read", "-field=certificate", f"{mount}/cert/ca"])

        ca_path = self.state / "pki/ca.pem"
        previous_ca = ca_path.read_text(encoding="utf-8") if ca_path.exists() else None
        ca_pem = ca.stdout.strip() + "\n"
        if previous_ca is not None and previous_ca != ca_pem:
            for path in (self.state / "pki").glob("*"):
                if path.name != "ca.pem" and path.is_file():
                    path.unlink()
        ca_path.write_text(ca_pem, encoding="utf-8")
        ca_path.chmod(0o644)
        ca_subject = run(
            [
                "openssl",
                "x509",
                "-in",
                str(ca_path),
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ]
        ).stdout.strip()
        if ca_subject != f"subject=CN={self.vault_config['ca']['commonName']}":
            raise ReferenceEnvironmentError("Vault CA identity differs from canonical configuration")

        roles = self.vault_config["roles"]
        if not isinstance(roles, dict):
            raise ReferenceEnvironmentError("Vault role configuration is invalid")
        inventory = self.vault(
            ["list", "-format=json", f"{mount}/roles"], check=False
        )
        existing_roles = set(json.loads(inventory.stdout)) if inventory.returncode == 0 else set()
        for extra in sorted(existing_roles - set(roles)):
            self.vault(["delete", f"{mount}/roles/{extra}"])
        for name, desired in roles.items():
            if not isinstance(desired, dict):
                raise ReferenceEnvironmentError(f"Vault role configuration is invalid: {name}")
            fields = []
            for key, value in desired.items():
                if isinstance(value, bool):
                    rendered = str(value).lower()
                elif isinstance(value, list):
                    rendered = ",".join(str(item) for item in value)
                else:
                    rendered = str(value)
                fields.append(f"{key}={rendered}")
            self.vault(["write", f"{mount}/roles/{name}", *fields])
        self.vault(
            ["policy", "write", "deviceidentity-sign", "/reference-config/vault/deviceidentity-sign.hcl"]
        )

        token_path = self.state / "vault-runtime-token"
        runtime_token = token_path.read_text(encoding="utf-8").strip() if token_path.exists() else ""
        if runtime_token:
            lookup = self.vault(["token", "lookup"], token=runtime_token, check=False)
            if lookup.returncode != 0:
                runtime_token = ""
        if not runtime_token:
            token = json.loads(
                self.vault(
                    ["token", "create", "-orphan", "-policy=deviceidentity-sign", "-format=json"]
                ).stdout
            )
            runtime_token = token["auth"]["client_token"]
            write_private_text(token_path, runtime_token + "\n")

        self.ensure_certificate(
            name="server",
            common_name="mosquitto",
            role="mosquitto-server",
            san_kind="DNS",
            san_value="mosquitto,DNS:localhost",
            token=self.values["VAULT_ROOT_TOKEN"],
        )
        self.ensure_certificate(
            name="keycloak",
            common_name="localhost",
            role="keycloak-server",
            san_kind="DNS",
            san_value="localhost",
            token=self.values["VAULT_ROOT_TOKEN"],
        )
        device_uri = self.vault_config["roles"]["mqtt-device"]["allowed_uri_sans"][0]
        self.ensure_certificate(
            name="device",
            common_name="reference-device",
            role="mqtt-device",
            san_kind="URI",
            san_value=device_uri,
            token=runtime_token,
        )
        self.ensure_certificate(
            name="service",
            common_name="deviceidentity-service",
            role="mqtt-service",
            san_kind="DNS",
            san_value="deviceidentity-service",
            token=self.values["VAULT_ROOT_TOKEN"],
        )

    def ensure_certificate(
        self,
        *,
        name: str,
        common_name: str,
        role: str,
        san_kind: str,
        san_value: str,
        token: str,
    ) -> None:
        directory = self.state / "pki"
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        certificate = directory / f"{name}.crt"
        if key.exists() and csr.exists() and certificate.exists():
            if self.certificate_matches(
                key=key,
                certificate=certificate,
                common_name=common_name,
                role=role,
                san_kind=san_kind,
                san_value=san_value,
            ):
                return
            key.unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
            certificate.unlink(missing_ok=True)

        subject_alt_name = f"{san_kind}:{san_value}"
        run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={common_name}",
                "-addext",
                f"subjectAltName={subject_alt_name}",
            ],
            timeout=30,
        )
        key.chmod(0o600)
        relative_csr = f"/reference-state/pki/{name}.csr"
        fields = [f"csr=@{relative_csr}", f"common_name={common_name}"]
        if san_kind == "URI":
            fields.append(f"uri_sans={san_value}")
        elif san_kind == "DNS":
            dns_names = ",".join(
                item.removeprefix("DNS:")
                for item in san_value.split(",")
                if not item.startswith("IP:")
            )
            fields.append(f"alt_names={dns_names}")
            if "IP:" in san_value:
                fields.append("ip_sans=127.0.0.1")
        response = json.loads(
            self.vault(
                ["write", "-format=json", f"device-pki/sign/{role}", *fields], token=token
            ).stdout
        )
        pem = response["data"]["certificate"].strip() + "\n"
        write_private_text(certificate, pem)
        certificate.chmod(0o644)

    def certificate_matches(
        self,
        *,
        key: Path,
        certificate: Path,
        common_name: str,
        role: str,
        san_kind: str,
        san_value: str,
    ) -> bool:
        directory = self.state / "pki"
        verify = run(
            ["openssl", "verify", "-CAfile", str(directory / "ca.pem"), str(certificate)],
            check=False,
        )
        if verify.returncode != 0:
            return False
        certificate_key = run(
            ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"]
        ).stdout
        private_key = run(
            ["openssl", "pkey", "-in", str(key), "-pubout"]
        ).stdout
        if certificate_key != private_key:
            return False
        subject = run(
            [
                "openssl",
                "x509",
                "-in",
                str(certificate),
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ]
        ).stdout.strip()
        if subject != f"subject=CN={common_name}":
            return False
        san_output = run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"]
        ).stdout
        actual_sans = {
            item.strip().replace(" ", "")
            for line in san_output.splitlines()[1:]
            for item in line.split(",")
            if item.strip()
        }
        if san_kind == "URI":
            expected_sans = {f"DNS:{common_name}", f"URI:{san_value}"}
        else:
            expected_sans = {
                item if ":" in item else f"DNS:{item}"
                for item in san_value.split(",")
            }
        if actual_sans != expected_sans:
            return False
        eku = run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "extendedKeyUsage"]
        ).stdout
        desired_role = self.vault_config["roles"][role]
        expected_eku = set()
        if desired_role["server_flag"]:
            expected_eku.add("TLS Web Server Authentication")
        if desired_role["client_flag"]:
            expected_eku.add("TLS Web Client Authentication")
        actual_eku = {
            item.strip()
            for line in eku.splitlines()[1:]
            for item in line.split(",")
            if item.strip()
        }
        if actual_eku != expected_eku:
            return False
        dates = run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-dates"]
        ).stdout.splitlines()
        not_after = datetime.strptime(dates[1].split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        remaining = (not_after - datetime.now(timezone.utc)).total_seconds()
        validity = int(self.fixture["rotationPolicy"]["validitySeconds"])
        renew_before = int(self.fixture["rotationPolicy"]["renewBeforeSeconds"])
        return renew_before < remaining <= validity + 100

    def bootstrap_postgres(self) -> None:
        self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--set=ON_ERROR_STOP=1",
                f"--set=keycloak_password={self.values['KEYCLOAK_DB_PASSWORD']}",
                f"--set=migrator_password={self.values['DEVICEIDENTITY_MIGRATOR_PASSWORD']}",
                f"--set=app_password={self.values['DEVICEIDENTITY_APP_PASSWORD']}",
                "--file=/reference-config/postgres/bootstrap.sql",
            ],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )

    def keycloak_url(self, path: str) -> str:
        if self._keycloak_port is None:
            configured = int(self.values["KEYCLOAK_PORT"])
            if configured:
                self._keycloak_port = configured
            else:
                mapping = self.compose("port", "keycloak", "8443", timeout=15).stdout.strip()
                try:
                    self._keycloak_port = int(mapping.rsplit(":", 1)[1])
                except (IndexError, ValueError) as error:
                    raise ReferenceEnvironmentError(
                        f"cannot resolve Keycloak loopback port: {mapping}"
                    ) from error
        return f"https://localhost:{self._keycloak_port}{path}"

    def keycloak_open(self, request: urllib.request.Request | str):
        context = ssl.create_default_context(cafile=str(self.state / "pki/ca.pem"))
        return urllib.request.urlopen(request, timeout=10, context=context)

    def keycloak_admin_token(self) -> str:
        request = urllib.request.Request(
            self.keycloak_url("/realms/master/protocol/openid-connect/token"),
            data=urllib.parse.urlencode(
                {
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "reference-admin",
                    "password": self.values["KEYCLOAK_ADMIN_PASSWORD"],
                }
            ).encode(),
            method="POST",
        )
        with self.keycloak_open(request) as response:
            return json.load(response)["access_token"]

    def keycloak_admin_request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: object | None = None,
        allowed: tuple[int, ...] = (),
    ) -> tuple[int, object | None]:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            self.keycloak_url(f"/admin{path}"),
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.keycloak_open(request) as response:
                body = response.read()
                return response.status, json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code in allowed:
                return error.code, None
            detail = error.read().decode(errors="replace")
            raise ReferenceEnvironmentError(
                f"Keycloak Admin API {method} {path} failed ({error.code}): {self.redact(detail)}"
            ) from error

    def reconcile_realm_role_mapping(
        self, *, user_id: str, desired_role: str, token: str
    ) -> None:
        path = f"/realms/rss-device-security/users/{user_id}/role-mappings/realm"
        _, current = self.keycloak_admin_request("GET", path, token=token)
        if not isinstance(current, list):
            raise ReferenceEnvironmentError("Keycloak direct realm-role mapping is invalid")
        expected = {desired_role}
        extras = [role for role in current if role.get("name") not in expected]
        if extras:
            self.keycloak_admin_request(
                "DELETE", path, token=token, payload=extras
            )
        present = {role.get("name") for role in current} - {
            role.get("name") for role in extras
        }
        if desired_role not in present:
            _, role = self.keycloak_admin_request(
                "GET",
                f"/realms/rss-device-security/roles/{urllib.parse.quote(desired_role, safe='')}",
                token=token,
            )
            self.keycloak_admin_request("POST", path, token=token, payload=[role])

    def reconcile_identity_authority_sources(
        self, *, user_id: str, desired_role: str, token: str
    ) -> None:
        self.reconcile_realm_role_mapping(
            user_id=user_id, desired_role=desired_role, token=token
        )
        _, mappings = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/users/{user_id}/role-mappings",
            token=token,
        )
        if not isinstance(mappings, dict):
            raise ReferenceEnvironmentError("Keycloak role-mapping inventory is invalid")
        client_mappings = mappings.get("clientMappings") or {}
        for mapping in client_mappings.values():
            client_id = mapping.get("id")
            roles = mapping.get("mappings") or []
            if client_id and roles:
                self.keycloak_admin_request(
                    "DELETE",
                    f"/realms/rss-device-security/users/{user_id}/role-mappings/clients/{client_id}",
                    token=token,
                    payload=roles,
                )
        _, groups = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/users/{user_id}/groups",
            token=token,
        )
        if not isinstance(groups, list):
            raise ReferenceEnvironmentError("Keycloak group-membership inventory is invalid")
        for group in groups:
            self.keycloak_admin_request(
                "DELETE",
                f"/realms/rss-device-security/users/{user_id}/groups/{group['id']}",
                token=token,
            )

    def verify_realm_role_mapping(
        self, *, user_id: str, desired_role: str, token: str
    ) -> None:
        _, current = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/users/{user_id}/role-mappings/realm",
            token=token,
        )
        actual = {role.get("name") for role in current} if isinstance(current, list) else set()
        expected = {desired_role}
        if actual != expected:
            raise ReferenceEnvironmentError(
                f"Keycloak direct realm-role closure differs for {user_id}: {actual}"
            )

    def verify_identity_authority_sources(
        self, *, user_id: str, desired_role: str, token: str
    ) -> None:
        self.verify_realm_role_mapping(
            user_id=user_id, desired_role=desired_role, token=token
        )
        _, mappings = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/users/{user_id}/role-mappings",
            token=token,
        )
        if not isinstance(mappings, dict) or mappings.get("clientMappings"):
            raise ReferenceEnvironmentError(
                f"Keycloak client-role mapping closure differs for {user_id}"
            )
        _, groups = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/users/{user_id}/groups",
            token=token,
        )
        if groups != []:
            raise ReferenceEnvironmentError(
                f"Keycloak group-membership closure differs for {user_id}"
            )

    def bootstrap_keycloak(self) -> None:
        desired = render_fixture_placeholders(
            json.loads((DEPLOY_ROOT / "keycloak/realm.json").read_text(encoding="utf-8")),
            self.fixture,
        )
        token = self.keycloak_admin_token()
        status, _ = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security", token=token, allowed=(404,)
        )
        if status == 404:
            self.keycloak_admin_request("POST", "/realms", token=token, payload=desired)
        else:
            realm_update = {
                key: desired[key]
                for key in (
                    "realm",
                    "enabled",
                    "displayName",
                    "registrationAllowed",
                    "resetPasswordAllowed",
                    "rememberMe",
                )
            }
            self.keycloak_admin_request(
                "PUT", "/realms/rss-device-security", token=token, payload=realm_update
            )

        for role in desired["roles"]["realm"]:
            name = role["name"]
            status, _ = self.keycloak_admin_request(
                "GET",
                f"/realms/rss-device-security/roles/{urllib.parse.quote(name, safe='')}",
                token=token,
                allowed=(404,),
            )
            if status == 404:
                self.keycloak_admin_request(
                    "POST",
                    "/realms/rss-device-security/roles",
                    token=token,
                    payload=role,
                )
            self.keycloak_admin_request(
                "PUT",
                f"/realms/rss-device-security/roles/{urllib.parse.quote(name, safe='')}",
                token=token,
                payload={**role, "composite": False},
            )
            _, composites = self.keycloak_admin_request(
                "GET",
                f"/realms/rss-device-security/roles/{urllib.parse.quote(name, safe='')}/composites",
                token=token,
            )
            if isinstance(composites, list) and composites:
                self.keycloak_admin_request(
                    "DELETE",
                    f"/realms/rss-device-security/roles/{urllib.parse.quote(name, safe='')}/composites",
                    token=token,
                    payload=composites,
                )

        for client in desired["clients"]:
            query = urllib.parse.urlencode({"clientId": client["clientId"]})
            _, matches = self.keycloak_admin_request(
                "GET", f"/realms/rss-device-security/clients?{query}", token=token
            )
            if not isinstance(matches, list) or len(matches) > 1:
                raise ReferenceEnvironmentError(f"duplicate Keycloak clientId={client['clientId']}")
            representation = dict(client)
            if client["clientId"] == "deviceidentity":
                representation["secret"] = self.values["DEVICEIDENTITY_CLIENT_SECRET"]
            identifier = matches[0]["id"] if matches else None
            if identifier is None:
                self.keycloak_admin_request(
                    "POST",
                    "/realms/rss-device-security/clients",
                    token=token,
                    payload=representation,
                )
            else:
                self.keycloak_admin_request(
                    "PUT",
                    f"/realms/rss-device-security/clients/{identifier}",
                    token=token,
                    payload=representation,
                )

        query = urllib.parse.urlencode({"clientId": "deviceidentity"})
        _, service_clients = self.keycloak_admin_request(
            "GET", f"/realms/rss-device-security/clients?{query}", token=token
        )
        if not isinstance(service_clients, list) or len(service_clients) != 1:
            raise ReferenceEnvironmentError("Keycloak service client did not converge")
        service_client_id = service_clients[0]["id"]
        _, service_account = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/clients/{service_client_id}/service-account-user",
            token=token,
        )
        if not isinstance(service_account, dict) or "id" not in service_account:
            raise ReferenceEnvironmentError("Keycloak service account identity is invalid")
        self.reconcile_identity_authority_sources(
            user_id=service_account["id"],
            desired_role="deviceidentity-service",
            token=token,
        )

        _, user_profile = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/users/profile", token=token
        )
        if not isinstance(user_profile, dict) or not isinstance(
            user_profile.get("attributes"), list
        ):
            raise ReferenceEnvironmentError("Keycloak user profile is invalid")
        tenant_attribute = json.loads(
            (DEPLOY_ROOT / "keycloak/tenant-attribute.json").read_text(encoding="utf-8")
        )
        user_profile["attributes"] = [
            item
            for item in user_profile["attributes"]
            if item.get("name") != tenant_attribute["name"]
        ] + [tenant_attribute]
        self.keycloak_admin_request(
            "PUT",
            "/realms/rss-device-security/users/profile",
            token=token,
            payload=user_profile,
        )

        user = desired["users"][0]
        query = urllib.parse.urlencode({"username": user["username"], "exact": "true"})
        _, users = self.keycloak_admin_request(
            "GET", f"/realms/rss-device-security/users?{query}", token=token
        )
        if not isinstance(users, list) or len(users) > 1:
            raise ReferenceEnvironmentError(f"duplicate Keycloak user={user['username']}")
        identifier = users[0]["id"] if users else None
        if identifier is None:
            self.keycloak_admin_request(
                "POST", "/realms/rss-device-security/users", token=token, payload=user
            )
            _, users = self.keycloak_admin_request(
                "GET", f"/realms/rss-device-security/users?{query}", token=token
            )
            if not isinstance(users, list) or len(users) != 1:
                raise ReferenceEnvironmentError("Keycloak operator creation did not converge")
            identifier = users[0]["id"]
        else:
            self.keycloak_admin_request(
                "PUT",
                f"/realms/rss-device-security/users/{identifier}",
                token=token,
                payload=user,
            )
        self.keycloak_admin_request(
            "PUT",
            f"/realms/rss-device-security/users/{identifier}/reset-password",
            token=token,
            payload={
                "type": "password",
                "temporary": False,
                "value": self.values["OPERATOR_PASSWORD"],
            },
        )
        self.reconcile_identity_authority_sources(
            user_id=identifier,
            desired_role="rotation-operator",
            token=token,
        )

    def generate_mosquitto_acl(self) -> None:
        tenant = self.fixture["tenantId"]
        device = self.fixture["deviceId"]
        generation = self.fixture["generation"]
        prefix = f"rss/v1/{tenant}/{device}/{generation}"
        uplinks = [f"{prefix}/uplink/{item}" for item in self.fixture["mqtt"]["uplinkContracts"]]
        downlinks = [
            f"{prefix}/downlink/{item}" for item in self.fixture["mqtt"]["downlinkContracts"]
        ]
        lines = [f"user {self.fixture['mqtt']['deviceUsername']}"]
        lines.extend(f"topic write {topic}" for topic in uplinks)
        lines.extend(f"topic read {topic}" for topic in downlinks)
        lines.append(f"user {self.fixture['mqtt']['serviceUsername']}")
        lines.extend(f"topic read {topic}" for topic in uplinks)
        lines.extend(f"topic write {topic}" for topic in downlinks)
        path = self.state / "mosquitto/acl"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def bootstrap(self) -> None:
        self.check_dependencies()
        self.require_state()
        self.compose("up", "--detach", "--wait", "--wait-timeout", "120", "vault", "postgres", timeout=150)
        self.bootstrap_vault()
        self.bootstrap_postgres()
        self.compose("up", "--detach", "--wait", "--wait-timeout", "180", "keycloak", timeout=210)
        self.bootstrap_keycloak()
        self.generate_mosquitto_acl()
        self.compose("up", "--detach", "--wait", "--wait-timeout", "120", "mosquitto", timeout=150)
        self.compose("kill", "--signal", "HUP", "mosquitto", timeout=30)
        self.compose("up", "--detach", "--wait", "--wait-timeout", "120", "mosquitto", timeout=150)

    def verify_vault(self) -> None:
        runtime_token = (self.state / "vault-runtime-token").read_text(encoding="utf-8").strip()
        mount = str(self.vault_config["mount"])
        inventory = json.loads(
            self.vault(["list", "-format=json", f"{mount}/roles"]).stdout
        )
        if set(inventory) != set(self.vault_config["roles"]):
            raise ReferenceEnvironmentError(
                f"Vault role inventory differs: {sorted(inventory)}"
            )
        for role, desired in self.vault_config["roles"].items():
            result = json.loads(
                self.vault(["read", "-format=json", f"{mount}/roles/{role}"]).stdout
            )["data"]
            expected = dict(desired)
            expected["max_ttl"] = duration_seconds(str(desired["max_ttl"]))
            expected["ttl"] = duration_seconds(str(desired["ttl"]))
            for key, value in expected.items():
                if result.get(key) != value:
                    raise ReferenceEnvironmentError(
                        f"Vault role `{role}` property differs: {key}={result.get(key)!r}"
                    )
            for dangerous in ("allow_any_name", "allow_glob_domains"):
                if result.get(dangerous) is not False:
                    raise ReferenceEnvironmentError(
                        f"Vault role `{role}` enables {dangerous}"
                    )
        forbidden = self.vault(["secrets", "list"], token=runtime_token, check=False)
        if forbidden.returncode == 0:
            raise ReferenceEnvironmentError("Vault runtime token can administer secret engines")
        verification = self.state / "pki/.vault-negative"
        verification.mkdir(mode=0o700, exist_ok=True)
        try:
            device_uri = self.vault_config["roles"]["mqtt-device"]["allowed_uri_sans"][0]
            for name, uri in (
                ("legal", device_uri),
                ("outside", "urn:rss:mqtt-device:v1:outside-boundary"),
            ):
                run(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-keyout",
                        str(verification / f"{name}.key"),
                        "-out",
                        str(verification / f"{name}.csr"),
                        "-subj",
                        "/CN=reference-device",
                        "-addext",
                        f"subjectAltName=URI:{uri}",
                    ],
                    timeout=30,
                )
            legal_csr = "/reference-state/pki/.vault-negative/legal.csr"
            outside_csr = "/reference-state/pki/.vault-negative/outside.csr"
            checks = (
                (
                    [
                        "write",
                        f"{mount}/sign/mqtt-device",
                        f"csr=@{outside_csr}",
                        "common_name=reference-device",
                    ],
                    "Vault accepted an out-of-scope device URI SAN",
                ),
                (
                    [
                        "write",
                        f"{mount}/sign/mqtt-service",
                        f"csr=@{legal_csr}",
                        "common_name=deviceidentity-service",
                    ],
                    "Vault runtime token can sign service identities",
                ),
                (
                    [
                        "write",
                        f"{mount}/sign/mosquitto-server",
                        f"csr=@{legal_csr}",
                        "common_name=mosquitto",
                    ],
                    "Vault runtime token can sign broker identities",
                ),
                (
                    ["write", f"{mount}/root/generate/internal", "common_name=forbidden"],
                    "Vault runtime token can replace the certificate authority",
                ),
            )
            for arguments, message in checks:
                if self.vault(arguments, token=runtime_token, check=False).returncode == 0:
                    raise ReferenceEnvironmentError(message)
            ttl_override = self.vault(
                [
                    "write",
                    f"{mount}/sign/mqtt-device",
                    f"csr=@{legal_csr}",
                    "common_name=reference-device",
                    "ttl=25h",
                ],
                token=runtime_token,
                check=False,
            )
            if ttl_override.returncode == 0:
                raise ReferenceEnvironmentError(
                    "Vault runtime signer accepted a caller-controlled certificate TTL"
                )
        finally:
            shutil.rmtree(verification, ignore_errors=True)

    def verify_postgres(self) -> None:
        query = """
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
FROM pg_roles
WHERE rolname IN ('keycloak_owner', 'deviceidentity_migrator', 'deviceidentity_app')
ORDER BY rolname;
"""
        result = self.compose_exec(
            "postgres",
            ["psql", "--username=postgres", "--dbname=postgres", "--tuples-only", "--no-align", "--command", query],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) != 3 or any(line.split("|")[1:] != ["f", "f", "f", "f", "f"] for line in lines):
            raise ReferenceEnvironmentError(f"PostgreSQL role closure differs: {lines}")
        closure_query = """
SELECT json_build_object(
  'owners', (
    SELECT json_object_agg(datname, pg_get_userbyid(datdba))
    FROM pg_database WHERE datname IN ('keycloak', 'deviceidentity')
  ),
  'managedMemberships', (
    SELECT count(*) FROM pg_auth_members membership
    JOIN pg_roles member ON member.oid = membership.member
    WHERE member.rolname IN ('keycloak_owner', 'deviceidentity_migrator', 'deviceidentity_app')
  ),
  'publicDatabasePrivileges', (
    SELECT count(*) FROM pg_database database,
      LATERAL aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) acl
    WHERE database.datname IN ('keycloak', 'deviceidentity') AND acl.grantee = 0
  ),
  'appConnect', has_database_privilege('deviceidentity_app', 'deviceidentity', 'CONNECT'),
  'appTemporary', has_database_privilege('deviceidentity_app', 'deviceidentity', 'TEMP')
)::text;
"""
        closure = self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--tuples-only",
                "--no-align",
                "--command",
                closure_query,
            ],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )
        postgres_state = json.loads(closure.stdout.strip())
        expected_state = {
            "owners": {
                "keycloak": "keycloak_owner",
                "deviceidentity": "deviceidentity_migrator",
            },
            "managedMemberships": 0,
            "publicDatabasePrivileges": 0,
            "appConnect": True,
            "appTemporary": False,
        }
        if postgres_state != expected_state:
            raise ReferenceEnvironmentError(
                f"PostgreSQL ownership/ACL closure differs: {postgres_state}"
            )
        schema_query = """
SELECT json_build_object(
  'owner', pg_get_userbyid(nspowner),
  'usage', has_schema_privilege('deviceidentity_app', 'public', 'USAGE'),
  'create', has_schema_privilege('deviceidentity_app', 'public', 'CREATE')
)::text FROM pg_namespace WHERE nspname = 'public';
"""
        schema = self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=postgres",
                "--dbname=deviceidentity",
                "--tuples-only",
                "--no-align",
                "--command",
                schema_query,
            ],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )
        schema_state = json.loads(schema.stdout.strip())
        if schema_state != {
            "owner": "deviceidentity_migrator",
            "usage": True,
            "create": False,
        }:
            raise ReferenceEnvironmentError(
                f"PostgreSQL schema closure differs: {schema_state}"
            )
        ddl = self.compose_exec(
            "postgres",
            ["psql", "--username=deviceidentity_app", "--dbname=deviceidentity", "--command", "CREATE TABLE forbidden(id integer)"],
            environment={"PGPASSWORD": self.values["DEVICEIDENTITY_APP_PASSWORD"]},
            check=False,
        )
        if ddl.returncode == 0:
            raise ReferenceEnvironmentError("deviceidentity serving role unexpectedly owns DDL")
        escalation = self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=deviceidentity_app",
                "--dbname=deviceidentity",
                "--command",
                "SET ROLE deviceidentity_migrator",
            ],
            environment={"PGPASSWORD": self.values["DEVICEIDENTITY_APP_PASSWORD"]},
            check=False,
        )
        if escalation.returncode == 0:
            raise ReferenceEnvironmentError("deviceidentity serving role can assume the migrator role")

    def verify_keycloak(self) -> None:
        admin_token = self.keycloak_admin_token()
        _, clients = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/clients", token=admin_token
        )
        if not isinstance(clients, list):
            raise ReferenceEnvironmentError("Keycloak client inventory is invalid")
        expected = KEYCLOAK_BUILTIN_CLIENTS | {"rotation-control", "deviceidentity"}
        actual = {item["clientId"] for item in clients}
        if actual != expected:
            raise ReferenceEnvironmentError(f"Keycloak client closure differs: {actual}")
        client_by_name = {item["clientId"]: item for item in clients}
        query = urllib.parse.urlencode({"username": "reference-operator", "exact": "true"})
        _, operators = self.keycloak_admin_request(
            "GET", f"/realms/rss-device-security/users?{query}", token=admin_token
        )
        if not isinstance(operators, list) or len(operators) != 1:
            raise ReferenceEnvironmentError("Keycloak operator identity closure differs")
        self.verify_identity_authority_sources(
            user_id=operators[0]["id"],
            desired_role="rotation-operator",
            token=admin_token,
        )
        _, service_account = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/clients/{client_by_name['deviceidentity']['id']}/service-account-user",
            token=admin_token,
        )
        if not isinstance(service_account, dict) or "id" not in service_account:
            raise ReferenceEnvironmentError("Keycloak service account identity closure differs")
        self.verify_identity_authority_sources(
            user_id=service_account["id"],
            desired_role="deviceidentity-service",
            token=admin_token,
        )
        discovery_url = self.keycloak_url(
            "/realms/rss-device-security/.well-known/openid-configuration"
        )
        with self.keycloak_open(discovery_url) as response:
            discovery = json.load(response)
        if not discovery["issuer"].endswith("/realms/rss-device-security"):
            raise ReferenceEnvironmentError("Keycloak issuer differs")
        token_request = urllib.request.Request(
            self.keycloak_url(
                "/realms/rss-device-security/protocol/openid-connect/token"
            ),
            data=urllib.parse.urlencode(
                {
                    "grant_type": "password",
                    "client_id": "rotation-control",
                    "username": "reference-operator",
                    "password": self.values["OPERATOR_PASSWORD"],
                }
            ).encode(),
            method="POST",
        )
        with self.keycloak_open(token_request) as response:
            token = json.load(response)["access_token"]
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        if claims.get("tenantId") != self.fixture["tenantId"]:
            raise ReferenceEnvironmentError("Keycloak tenant claim differs")
        service_request = urllib.request.Request(
            self.keycloak_url(
                "/realms/rss-device-security/protocol/openid-connect/token"
            ),
            data=urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": "deviceidentity",
                    "client_secret": self.values["DEVICEIDENTITY_CLIENT_SECRET"],
                }
            ).encode(),
            method="POST",
        )
        with self.keycloak_open(service_request) as response:
            service_token = json.load(response)["access_token"]
        service_payload = service_token.split(".")[1]
        service_payload += "=" * (-len(service_payload) % 4)
        service_claims = json.loads(base64.urlsafe_b64decode(service_payload))
        service_roles = service_claims.get("realm_access", {}).get("roles", [])
        if "deviceidentity-service" not in service_roles:
            raise ReferenceEnvironmentError("Keycloak service identity role differs")
        for role_name in ("rotation-operator", "deviceidentity-service"):
            _, role = self.keycloak_admin_request(
                "GET",
                f"/realms/rss-device-security/roles/{role_name}",
                token=admin_token,
            )
            _, composites = self.keycloak_admin_request(
                "GET",
                f"/realms/rss-device-security/roles/{role_name}/composites",
                token=admin_token,
            )
            if not isinstance(role, dict) or role.get("composite") or composites != []:
                raise ReferenceEnvironmentError(
                    f"Keycloak managed role `{role_name}` is composite"
                )

    def mqtt_command(self, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run(self.mqtt_command_line(arguments), check=check, timeout=20)

    def mqtt_command_line(self, arguments: list[str]) -> list[str]:
        container = self.compose("ps", "--quiet", "mosquitto", timeout=15).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise ReferenceEnvironmentError("Mosquitto container identity is unavailable")
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{container}",
            "--mount",
            f"type=bind,source={self.state / 'pki'},target=/reference-state/pki,readonly",
            "--entrypoint",
            arguments[0],
            self.service_image("mosquitto"),
            *arguments[1:],
        ]

    @staticmethod
    def mqtt_was_denied(result: subprocess.CompletedProcess[str]) -> bool:
        output = f"{result.stdout}\n{result.stderr}"
        return result.returncode != 0 or "Not authorized" in output or "RC:135" in output

    def mqtt_round_trip(
        self,
        *,
        common: list[str],
        subscriber_auth: list[str],
        publisher_auth: list[str],
        topic: str,
        message: str,
    ) -> None:
        subscriber = subprocess.Popen(
            self.mqtt_command_line(
                [
                "mosquitto_sub",
                *common,
                *subscriber_auth,
                "-q",
                "1",
                "-C",
                "1",
                "-W",
                "10",
                "-t",
                topic,
                ]
            ),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.5)
            self.mqtt_command(
                [
                    "mosquitto_pub",
                    *common,
                    *publisher_auth,
                    "-q",
                    "1",
                    "-t",
                    topic,
                    "-m",
                    message,
                ]
            )
            stdout, stderr = subscriber.communicate(timeout=12)
        except Exception:
            subscriber.terminate()
            subscriber.communicate(timeout=5)
            raise
        if subscriber.returncode != 0 or stdout.strip() != message:
            raise ReferenceEnvironmentError(
                f"MQTT authorized round trip failed: {self.redact(stderr.strip())}"
            )

    def mqtt_expect_no_delivery(
        self,
        *,
        common: list[str],
        identity: list[str],
        topic: str,
    ) -> None:
        subscriber = subprocess.Popen(
            self.mqtt_command_line(
                [
                "mosquitto_sub",
                *common,
                *identity,
                "-q",
                "1",
                "-C",
                "1",
                "-W",
                "2",
                "-t",
                topic,
                ]
            ),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.5)
            self.mqtt_command(
                [
                    "mosquitto_pub",
                    *common,
                    *identity,
                    "-q",
                    "1",
                    "-t",
                    topic,
                    "-m",
                    "must-not-be-delivered",
                ]
            )
            stdout, stderr = subscriber.communicate(timeout=5)
        except Exception:
            subscriber.terminate()
            subscriber.communicate(timeout=5)
            raise
        if stdout.strip() or "Timed out" not in stderr:
            raise ReferenceEnvironmentError(
                f"MQTT forbidden subscription received data: {self.redact(stdout.strip())}"
            )

    def ensure_untrusted_client_certificate(self) -> None:
        key = self.state / "pki/untrusted.key"
        certificate = self.state / "pki/untrusted.crt"
        if key.exists() and certificate.exists():
            return
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
                "-subj",
                "/CN=reference-device",
            ],
            timeout=30,
        )
        key.chmod(0o600)
        certificate.chmod(0o644)

    def verify_mosquitto(self) -> None:
        tenant = self.fixture["tenantId"]
        device = self.fixture["deviceId"]
        generation = self.fixture["generation"]
        prefix = f"rss/v1/{tenant}/{device}/{generation}"
        uplink = f"{prefix}/uplink/{self.fixture['mqtt']['uplinkContracts'][0]}"
        downlink = f"{prefix}/downlink/{self.fixture['mqtt']['downlinkContracts'][0]}"
        common = [
            "-V",
            "mqttv5",
            "-h",
            "localhost",
            "-p",
            "8883",
            "--cafile",
            "/reference-state/pki/ca.pem",
        ]
        device_auth = ["--cert", "/reference-state/pki/device.crt", "--key", "/reference-state/pki/device.key"]
        service_auth = ["--cert", "/reference-state/pki/service.crt", "--key", "/reference-state/pki/service.key"]
        self.mqtt_round_trip(
            common=common,
            subscriber_auth=service_auth,
            publisher_auth=device_auth,
            topic=uplink,
            message="ack",
        )
        self.mqtt_round_trip(
            common=common,
            subscriber_auth=device_auth,
            publisher_auth=service_auth,
            topic=downlink,
            message="command",
        )
        no_cert = self.mqtt_command(
            ["mosquitto_pub", *common, "-q", "1", "-t", uplink, "-m", "forbidden"], check=False
        )
        if not self.mqtt_was_denied(no_cert):
            raise ReferenceEnvironmentError("Mosquitto accepted a client without a certificate")
        self.ensure_untrusted_client_certificate()
        untrusted = self.mqtt_command(
            [
                "mosquitto_pub",
                *common,
                "--cert",
                "/reference-state/pki/untrusted.crt",
                "--key",
                "/reference-state/pki/untrusted.key",
                "-q",
                "1",
                "-t",
                uplink,
                "-m",
                "forbidden",
            ],
            check=False,
        )
        if not self.mqtt_was_denied(untrusted):
            raise ReferenceEnvironmentError("Mosquitto accepted a client signed by an untrusted CA")
        wrong_direction = self.mqtt_command(
            ["mosquitto_pub", *common, *device_auth, "-q", "1", "-t", downlink, "-m", "forbidden"],
            check=False,
        )
        if not self.mqtt_was_denied(wrong_direction):
            raise ReferenceEnvironmentError("Mosquitto accepted a device write on a downlink")
        service_wrong_direction = self.mqtt_command(
            [
                "mosquitto_pub",
                *common,
                *service_auth,
                "-q",
                "1",
                "-t",
                uplink,
                "-m",
                "forbidden",
            ],
            check=False,
        )
        if not self.mqtt_was_denied(service_wrong_direction):
            raise ReferenceEnvironmentError("Mosquitto accepted a service write on an uplink")
        forbidden_topics = {
            "tenant": uplink.replace(tenant, "00000000-0000-0000-0000-000000000999"),
            "device": uplink.replace(device, "00000000-0000-0000-0000-000000000999"),
            "generation": uplink.replace(f"/{generation}/uplink/", "/999/uplink/"),
        }
        for boundary, topic in forbidden_topics.items():
            result = self.mqtt_command(
                [
                    "mosquitto_pub",
                    *common,
                    *device_auth,
                    "-q",
                    "1",
                    "-t",
                    topic,
                    "-m",
                    "forbidden",
                ],
                check=False,
            )
            if not self.mqtt_was_denied(result):
                raise ReferenceEnvironmentError(
                    f"Mosquitto accepted a cross-{boundary} topic"
                )
        service_forbidden_topics = {
            "tenant": downlink.replace(tenant, "00000000-0000-0000-0000-000000000999"),
            "device": downlink.replace(device, "00000000-0000-0000-0000-000000000999"),
            "generation": downlink.replace(f"/{generation}/downlink/", "/999/downlink/"),
        }
        for boundary, topic in service_forbidden_topics.items():
            result = self.mqtt_command(
                [
                    "mosquitto_pub",
                    *common,
                    *service_auth,
                    "-q",
                    "1",
                    "-t",
                    topic,
                    "-m",
                    "forbidden",
                ],
                check=False,
            )
            if not self.mqtt_was_denied(result):
                raise ReferenceEnvironmentError(
                    f"Mosquitto accepted a service cross-{boundary} topic"
                )
        self.mqtt_expect_no_delivery(
            common=common, identity=device_auth, topic=uplink
        )
        self.mqtt_expect_no_delivery(
            common=common, identity=service_auth, topic=downlink
        )

    def verify(self) -> None:
        self.require_state()
        self.verify_vault()
        self.verify_postgres()
        self.verify_keycloak()
        self.verify_mosquitto()

    def logical_snapshot(self) -> dict[str, object]:
        admin_token = self.keycloak_admin_token()
        _, clients = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/clients", token=admin_token
        )
        _, users = self.keycloak_admin_request(
            "GET",
            "/realms/rss-device-security/users?username=reference-operator&exact=true",
            token=admin_token,
        )
        if not isinstance(clients, list) or not isinstance(users, list) or len(users) != 1:
            raise ReferenceEnvironmentError("Keycloak logical identity inventory is invalid")
        expected_clients = {"rotation-control", "deviceidentity"}
        client_ids = {
            item["clientId"]: item["id"]
            for item in clients
            if item.get("clientId") in expected_clients
        }
        if set(client_ids) != expected_clients:
            raise ReferenceEnvironmentError("Keycloak logical client identity closure differs")
        postgres = self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--tuples-only",
                "--no-align",
                "--command",
                "SELECT rolname || ':' || oid FROM pg_roles WHERE rolname IN "
                "('keycloak_owner','deviceidentity_migrator','deviceidentity_app') ORDER BY rolname",
            ],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )
        roles = [line.strip() for line in postgres.stdout.splitlines() if line.strip()]
        if len(roles) != 3:
            raise ReferenceEnvironmentError("PostgreSQL logical role identity closure differs")
        vault_roles = {}
        mount = str(self.vault_config["mount"])
        for role in self.vault_config["roles"]:
            result = json.loads(
                self.vault(["read", "-format=json", f"{mount}/roles/{role}"]).stdout
            )
            vault_roles[role] = result["data"]
        return {
            "keycloakClients": client_ids,
            "keycloakOperator": users[0]["id"],
            "postgresRoles": roles,
            "vaultRoles": vault_roles,
            "mqttAcl": hashlib.sha256(
                (self.state / "mosquitto/acl").read_bytes()
            ).hexdigest(),
        }

    def inject_managed_drift(self) -> None:
        self.vault(
            [
                "write",
                f"{self.vault_config['mount']}/roles/mqtt-device",
                "allowed_domains=reference-device",
                "allow_any_name=true",
                "client_flag=true",
                "server_flag=false",
                "max_ttl=24h",
            ]
        )
        self.vault(
            [
                "write",
                f"{self.vault_config['mount']}/roles/rogue",
                "allow_any_name=true",
                "client_flag=true",
                "server_flag=true",
            ]
        )
        self.compose_exec(
            "postgres",
            [
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--set=ON_ERROR_STOP=1",
                "--command=GRANT pg_read_all_data TO deviceidentity_app",
            ],
            environment={"PGPASSWORD": self.values["POSTGRES_SUPERUSER_PASSWORD"]},
        )
        token = self.keycloak_admin_token()
        query = urllib.parse.urlencode({"clientId": "deviceidentity"})
        _, clients = self.keycloak_admin_request(
            "GET", f"/realms/rss-device-security/clients?{query}", token=token
        )
        if not isinstance(clients, list) or len(clients) != 1:
            raise ReferenceEnvironmentError("cannot inject Keycloak managed drift")
        _, service_account = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/clients/{clients[0]['id']}/service-account-user",
            token=token,
        )
        _, extra_role = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/roles/rotation-operator", token=token
        )
        self.keycloak_admin_request(
            "POST",
            f"/realms/rss-device-security/users/{service_account['id']}/role-mappings/realm",
            token=token,
            payload=[extra_role],
        )
        management_query = urllib.parse.urlencode({"clientId": "realm-management"})
        _, management_clients = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/clients?{management_query}",
            token=token,
        )
        if not isinstance(management_clients, list) or len(management_clients) != 1:
            raise ReferenceEnvironmentError("cannot inject Keycloak client-role drift")
        management_id = management_clients[0]["id"]
        _, manage_users = self.keycloak_admin_request(
            "GET",
            f"/realms/rss-device-security/clients/{management_id}/roles/manage-users",
            token=token,
        )
        self.keycloak_admin_request(
            "POST",
            f"/realms/rss-device-security/users/{service_account['id']}/role-mappings/clients/{management_id}",
            token=token,
            payload=[manage_users],
        )
        self.keycloak_admin_request(
            "POST",
            "/realms/rss-device-security/roles/deviceidentity-service/composites",
            token=token,
            payload=[manage_users],
        )
        with (self.state / "mosquitto/acl").open("a", encoding="utf-8") as acl:
            acl.write("topic readwrite #\n")

    def project_resources(self) -> dict[str, list[str]]:
        label = f"label=com.docker.compose.project={self.project}"
        commands = {
            "containers": ["docker", "ps", "--all", "--quiet", "--filter", label],
            "networks": ["docker", "network", "ls", "--quiet", "--filter", label],
            "volumes": ["docker", "volume", "ls", "--quiet", "--filter", label],
        }
        return {
            kind: [line for line in run(command).stdout.splitlines() if line]
            for kind, command in commands.items()
        }

    def verify_resource_ownership(self) -> None:
        expected = self.values["REFERENCE_OWNER"]
        resources = self.project_resources()
        inspect_commands = {
            "containers": ["docker", "inspect"],
            "networks": ["docker", "network", "inspect"],
            "volumes": ["docker", "volume", "inspect"],
        }
        for kind, identifiers in resources.items():
            for identifier in identifiers:
                payload = json.loads(run([*inspect_commands[kind], identifier]).stdout)[0]
                labels = (
                    payload.get("Config", {}).get("Labels", {})
                    if kind == "containers"
                    else payload.get("Labels", {})
                ) or {}
                if labels.get("rss.reference.owner") != expected:
                    raise ReferenceEnvironmentError(
                        f"refusing foreign {kind[:-1]} in project namespace: {identifier}"
                    )

    def down(self) -> None:
        resources = self.project_resources()
        if not self.state.exists():
            if any(resources.values()):
                raise ReferenceEnvironmentError(
                    f"project resources exist without canonical state: {resources}"
                )
            return
        self.require_state()
        self.verify_resource_ownership()
        self.compose("down", "--volumes", "--remove-orphans", "--timeout", "10", timeout=90)
        remaining = self.project_resources()
        if any(remaining.values()):
            raise ReferenceEnvironmentError(f"project resources remain after teardown: {remaining}")
        remove_state(self.state, self.project)

    def fingerprints(self) -> dict[str, str]:
        runtime = {
            key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in self.values.items()
            if any(marker in key for marker in ("PASSWORD", "SECRET", "TOKEN"))
        }
        expected_material = {
            "pki/ca.pem",
            "pki/server.key",
            "pki/server.crt",
            "pki/keycloak.key",
            "pki/keycloak.crt",
            "pki/device.key",
            "pki/device.crt",
            "pki/service.key",
            "pki/service.crt",
            "pki/untrusted.key",
            "pki/untrusted.crt",
            "vault-tls/vault-ca.pem",
            "vault-tls/vault-cert.pem",
            "vault-tls/vault-key.pem",
        }
        material = {}
        for directory_name in ("pki", "vault-tls"):
            for path in sorted((self.state / directory_name).iterdir()):
                if path.suffix in {".key", ".crt", ".pem"}:
                    material[f"{directory_name}/{path.name}"] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
        if set(material) != expected_material:
            raise ReferenceEnvironmentError(
                f"runtime cryptographic material closure differs: {sorted(material)}"
            )
        return {**runtime, **material}

    def logs(self) -> None:
        if not self.state.exists():
            return
        self.require_state()
        result = self.compose("logs", "--no-color", check=False, timeout=30)
        if result.stdout:
            print(self.redact(result.stdout), file=sys.stderr)
        if result.stderr:
            print(self.redact(result.stderr), file=sys.stderr)

    def smoke(self) -> None:
        first_fingerprint: dict[str, str] | None = None
        primary_error: BaseException | None = None
        neighbor_suffix = secrets.token_hex(4)
        neighbor_project = f"{self.project}-neighbor"
        neighbor = {
            "container": f"{self.project}-neighbor-container-{neighbor_suffix}",
            "network": f"{self.project}-neighbor-network-{neighbor_suffix}",
            "volume": f"{self.project}-neighbor-volume-{neighbor_suffix}",
        }
        try:
            self.down()
            self.up()
            run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    f"com.docker.compose.project={neighbor_project}",
                    neighbor["volume"],
                ]
            )
            run(
                [
                    "docker",
                    "network",
                    "create",
                    "--label",
                    f"com.docker.compose.project={neighbor_project}",
                    neighbor["network"],
                ]
            )
            run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    neighbor["container"],
                    "--network",
                    neighbor["network"],
                    "--mount",
                    f"source={neighbor['volume']},target=/proof",
                    "--label",
                    f"com.docker.compose.project={neighbor_project}",
                    "--entrypoint",
                    "/bin/sh",
                    self.service_image("vault"),
                    "-c",
                    "while :; do sleep 60; done",
                ]
            )
            self.bootstrap()
            self.verify()
            before = self.fingerprints()
            before_identities = self.logical_snapshot()
            self.inject_managed_drift()
            self.bootstrap()
            self.verify()
            after = self.fingerprints()
            after_identities = self.logical_snapshot()
            if before != after:
                raise ReferenceEnvironmentError("idempotent bootstrap rotated runtime material")
            if before_identities != after_identities:
                raise ReferenceEnvironmentError("idempotent bootstrap changed logical identities")
            first_fingerprint = after
            self.down()
            run(["docker", "inspect", neighbor["container"]])
            run(["docker", "network", "inspect", neighbor["network"]])
            run(["docker", "volume", "inspect", neighbor["volume"]])
            self.up()
            self.bootstrap()
            self.verify()
            rebuilt = self.fingerprints()
            if first_fingerprint is None:
                raise ReferenceEnvironmentError("initial material fingerprints are missing")
            if set(rebuilt) != set(first_fingerprint):
                raise ReferenceEnvironmentError("destructive rebuild material closure differs")
            reused = sorted(
                name for name, digest in rebuilt.items() if first_fingerprint[name] == digest
            )
            if reused:
                raise ReferenceEnvironmentError(
                    f"destructive rebuild reused secret material: {reused}"
                )
        except Exception as error:
            primary_error = error
            self.logs()
            raise
        finally:
            cleanup_error: BaseException | None = None
            try:
                self.down()
            except Exception as error:
                print(f"final teardown failed: {error}", file=sys.stderr)
                cleanup_error = error
            cleanup_commands = (
                ["docker", "rm", "--force", neighbor["container"]],
                ["docker", "network", "rm", neighbor["network"]],
                ["docker", "volume", "rm", neighbor["volume"]],
            )
            for command in cleanup_commands:
                cleanup = run(command, check=False, timeout=30)
                if cleanup.returncode != 0 and "No such" not in cleanup.stderr:
                    print(
                        f"neighbor proof cleanup failed: {cleanup.stderr.strip()}",
                        file=sys.stderr,
                    )
                    cleanup_error = ReferenceEnvironmentError(
                        "failed to remove adjacent-project proof resources"
                    )
            if primary_error is None and cleanup_error is not None:
                raise cleanup_error


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project",
        default="rss-device-security-reference",
        help="isolated lowercase Docker Compose project identity",
    )
    parser.add_argument(
        "command", choices=("up", "bootstrap", "verify", "logs", "down", "smoke")
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        with project_lock(args.project):
            environment = ReferenceEnvironment(args.project)
            getattr(environment, args.command)()
    except (ReferenceEnvironmentError, OSError, subprocess.SubprocessError, urllib.error.URLError) as error:
        print(f"reference environment failed: {error}", file=sys.stderr)
        return 1
    print(f"reference environment `{args.project}`: {args.command} complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
