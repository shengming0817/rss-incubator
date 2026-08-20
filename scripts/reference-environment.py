#!/usr/bin/env python3
"""Manage the disposable Secure Device Rotation provider environment."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
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
    path.write_text(
        json.dumps(sentinel_payload(project, deploy_root), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


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
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )
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


def choose_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or "\n" in value or "\r" in value:
            raise ReferenceEnvironmentError(f"invalid runtime environment line in {path}")
        values[key] = value
    return values


def write_private_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o600)


class ReferenceEnvironment:
    def __init__(self, project: str):
        self.project = validate_project_name(project)
        self.state = state_directory(project)
        self.env_file = self.state / "runtime.env"
        self.fixture = json.loads(FIXTURE_FILE.read_text(encoding="utf-8"))
        self.values: dict[str, str] = {}

    def private_values(self) -> tuple[str, ...]:
        return tuple(
            value
            for key, value in self.values.items()
            if any(marker in key for marker in ("PASSWORD", "SECRET", "TOKEN"))
        )

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
            tenant = self.fixture["tenantId"]
            device = self.fixture["deviceId"]
            generation = self.fixture["generation"]
            downlink = self.fixture["mqtt"]["downlinkContracts"][0]
            values = {
                "REFERENCE_STATE": str(self.state),
                "VAULT_ROOT_TOKEN": secrets.token_hex(24),
                "POSTGRES_SUPERUSER_PASSWORD": secrets.token_hex(24),
                "KEYCLOAK_ADMIN_PASSWORD": secrets.token_hex(24),
                "KEYCLOAK_DB_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_MIGRATOR_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_APP_PASSWORD": secrets.token_hex(24),
                "DEVICEIDENTITY_CLIENT_SECRET": secrets.token_hex(24),
                "OPERATOR_PASSWORD": secrets.token_hex(18),
                "VAULT_PORT": str(choose_loopback_port()),
                "KEYCLOAK_PORT": str(choose_loopback_port()),
                "MQTT_PORT": str(choose_loopback_port()),
                "MQTT_HEALTH_TOPIC": f"rss/v1/{tenant}/{device}/{generation}/downlink/{downlink}",
            }
            write_private_text(
                self.env_file,
                "".join(f"{key}={value}\n" for key, value in sorted(values.items())),
            )
        self.values = read_env_file(self.env_file)
        for directory in ("vault-tls", "pki", "mosquitto"):
            path = self.state / directory
            path.mkdir(exist_ok=True, mode=0o700)
            path.chmod(0o700)

    def require_state(self) -> None:
        validate_sentinel(self.state, self.project)
        if not self.env_file.is_file():
            raise ReferenceEnvironmentError("runtime environment is missing; run `up` first")
        self.values = read_env_file(self.env_file)

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
        self.compose("config", "--quiet", timeout=30)
        self.compose("up", "--detach", "--wait", "--wait-timeout", "120", "vault", "postgres", timeout=150)

    def bootstrap_vault(self) -> None:
        mounts = json.loads(self.vault(["secrets", "list", "-format=json"]).stdout)
        if "device-pki/" not in mounts:
            self.vault(["secrets", "enable", "-path=device-pki", "pki"])

        ca = self.vault(["read", "-field=certificate", "device-pki/cert/ca"], check=False)
        if ca.returncode != 0 or "BEGIN CERTIFICATE" not in ca.stdout:
            self.vault(
                [
                    "write",
                    "device-pki/root/generate/internal",
                    "common_name=RSS Device Security Reference CA",
                    "ttl=8760h",
                ]
            )
            ca = self.vault(["read", "-field=certificate", "device-pki/cert/ca"])

        ca_path = self.state / "pki/ca.pem"
        previous_ca = ca_path.read_text(encoding="utf-8") if ca_path.exists() else None
        ca_pem = ca.stdout.strip() + "\n"
        if previous_ca is not None and previous_ca != ca_pem:
            for path in (self.state / "pki").glob("*"):
                if path.name != "ca.pem" and path.is_file():
                    path.unlink()
        ca_path.write_text(ca_pem, encoding="utf-8")
        ca_path.chmod(0o644)

        tenant = self.fixture["tenantId"]
        device = self.fixture["deviceId"]
        generation = self.fixture["generation"]
        device_uri = f"urn:rss:mqtt-device:v1:{tenant}:{device}:{generation}"
        roles = {
            "reference-server": [
                "allowed_domains=mosquitto,localhost",
                "allow_bare_domains=true",
                "allow_subdomains=false",
                "allow_ip_sans=true",
                "server_flag=true",
                "client_flag=false",
                "max_ttl=24h",
            ],
            "mqtt-device": [
                "allowed_domains=reference-device",
                "allow_bare_domains=true",
                f"allowed_uri_sans={device_uri}",
                "server_flag=false",
                "client_flag=true",
                "max_ttl=24h",
            ],
            "mqtt-service": [
                "allowed_domains=deviceidentity-service",
                "allow_bare_domains=true",
                "server_flag=false",
                "client_flag=true",
                "max_ttl=24h",
            ],
        }
        for name, fields in roles.items():
            self.vault(["write", f"device-pki/roles/{name}", *fields])
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
            role="reference-server",
            san_kind="DNS",
            san_value="mosquitto,DNS:localhost,IP:127.0.0.1",
            token=runtime_token,
        )
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
            token=runtime_token,
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
            verify = run(
                ["openssl", "verify", "-CAfile", str(directory / "ca.pem"), str(certificate)],
                check=False,
            )
            if verify.returncode == 0:
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
        fields = [f"csr=@{relative_csr}", f"common_name={common_name}", "ttl=1h"]
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
        certificate.write_text(pem, encoding="utf-8")
        certificate.chmod(0o644)

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
        return f"http://127.0.0.1:{self.values['KEYCLOAK_PORT']}{path}"

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
        with urllib.request.urlopen(request, timeout=10) as response:
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
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read()
                return response.status, json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code in allowed:
                return error.code, None
            detail = error.read().decode(errors="replace")
            raise ReferenceEnvironmentError(
                f"Keycloak Admin API {method} {path} failed ({error.code}): {self.redact(detail)}"
            ) from error

    def bootstrap_keycloak(self) -> None:
        desired = json.loads((DEPLOY_ROOT / "keycloak/realm.json").read_text(encoding="utf-8"))
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
        _, service_role = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/roles/deviceidentity-service", token=token
        )
        self.keycloak_admin_request(
            "POST",
            f"/realms/rss-device-security/users/{service_account['id']}/role-mappings/realm",
            token=token,
            payload=[service_role],
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
        _, role = self.keycloak_admin_request(
            "GET", "/realms/rss-device-security/roles/rotation-operator", token=token
        )
        self.keycloak_admin_request(
            "POST",
            f"/realms/rss-device-security/users/{identifier}/role-mappings/realm",
            token=token,
            payload=[role],
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
        path.chmod(0o644)

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
        for role in ("reference-server", "mqtt-device", "mqtt-service"):
            self.vault(["read", f"device-pki/roles/{role}"])
        forbidden = self.vault(["secrets", "list"], token=runtime_token, check=False)
        if forbidden.returncode == 0:
            raise ReferenceEnvironmentError("Vault runtime token can administer secret engines")
        for arguments, message in (
            (
                [
                    "write",
                    "device-pki/sign/mqtt-device",
                    "common_name=reference-device",
                    "uri_sans=urn:rss:mqtt-device:v1:outside-boundary",
                    "ttl=1h",
                ],
                "Vault accepted an out-of-scope device URI SAN",
            ),
            (
                [
                    "write",
                    "device-pki/sign/mqtt-device",
                    "common_name=reference-device",
                    "ttl=25h",
                ],
                "Vault accepted a certificate TTL above the role maximum",
            ),
            (
                ["write", "device-pki/root/generate/internal", "common_name=forbidden"],
                "Vault runtime token can replace the certificate authority",
            ),
        ):
            if self.vault(arguments, token=runtime_token, check=False).returncode == 0:
                raise ReferenceEnvironmentError(message)

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
        expected = {"rotation-control", "deviceidentity"}
        actual = {item["clientId"] for item in clients if item["clientId"] in expected}
        if actual != expected:
            raise ReferenceEnvironmentError(f"Keycloak client closure differs: {actual}")
        port = self.values["KEYCLOAK_PORT"]
        discovery_url = (
            f"http://127.0.0.1:{port}/realms/rss-device-security/.well-known/openid-configuration"
        )
        with urllib.request.urlopen(discovery_url, timeout=10) as response:
            discovery = json.load(response)
        if not discovery["issuer"].endswith("/realms/rss-device-security"):
            raise ReferenceEnvironmentError("Keycloak issuer differs")
        token_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/realms/rss-device-security/protocol/openid-connect/token",
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
        with urllib.request.urlopen(token_request, timeout=10) as response:
            token = json.load(response)["access_token"]
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        if claims.get("tenantId") != self.fixture["tenantId"]:
            raise ReferenceEnvironmentError("Keycloak tenant claim differs")
        service_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/realms/rss-device-security/protocol/openid-connect/token",
            data=urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": "deviceidentity",
                    "client_secret": self.values["DEVICEIDENTITY_CLIENT_SECRET"],
                }
            ).encode(),
            method="POST",
        )
        with urllib.request.urlopen(service_request, timeout=10) as response:
            service_token = json.load(response)["access_token"]
        service_payload = service_token.split(".")[1]
        service_payload += "=" * (-len(service_payload) % 4)
        service_claims = json.loads(base64.urlsafe_b64decode(service_payload))
        service_roles = service_claims.get("realm_access", {}).get("roles", [])
        if "deviceidentity-service" not in service_roles:
            raise ReferenceEnvironmentError("Keycloak service identity role differs")

    def mqtt_command(self, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.compose_exec("mosquitto", arguments, check=check, timeout=20)

    @staticmethod
    def mqtt_was_denied(result: subprocess.CompletedProcess[str]) -> bool:
        output = f"{result.stdout}\n{result.stderr}"
        return result.returncode != 0 or "Not authorized" in output or "RC:135" in output

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
            "127.0.0.1",
            "-p",
            "8883",
            "--cafile",
            "/reference-state/pki/ca.pem",
        ]
        device_auth = ["--cert", "/reference-state/pki/device.crt", "--key", "/reference-state/pki/device.key"]
        service_auth = ["--cert", "/reference-state/pki/service.crt", "--key", "/reference-state/pki/service.key"]
        self.mqtt_command(["mosquitto_pub", *common, *device_auth, "-q", "1", "-t", uplink, "-m", "ack"])
        self.mqtt_command(["mosquitto_pub", *common, *service_auth, "-q", "1", "-t", downlink, "-m", "command"])
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
        for role in ("reference-server", "mqtt-device", "mqtt-service"):
            result = json.loads(
                self.vault(["read", "-format=json", f"device-pki/roles/{role}"]).stdout
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

    def down(self) -> None:
        resources = self.project_resources()
        if not self.state.exists():
            if any(resources.values()):
                raise ReferenceEnvironmentError(
                    f"project resources exist without canonical state: {resources}"
                )
            return
        self.require_state()
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
        material = {
            f"pki/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((self.state / "pki").iterdir())
            if path.suffix in {".key", ".crt", ".pem"}
        }
        return {**runtime, **material}

    def logs(self) -> None:
        if self.env_file.exists():
            result = self.compose("logs", "--no-color", check=False, timeout=30)
            if result.stdout:
                print(result.stdout, file=sys.stderr)
            if result.stderr:
                print(result.stderr, file=sys.stderr)

    def smoke(self) -> None:
        first_fingerprint: dict[str, str] | None = None
        primary_error: BaseException | None = None
        neighbor_volume = f"{self.project}-neighbor-{secrets.token_hex(4)}"
        try:
            self.down()
            run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    f"com.docker.compose.project={self.project}-neighbor",
                    neighbor_volume,
                ]
            )
            self.up()
            self.bootstrap()
            self.verify()
            before = self.fingerprints()
            before_identities = self.logical_snapshot()
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
            run(["docker", "volume", "inspect", neighbor_volume])
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
            cleanup = run(
                ["docker", "volume", "rm", neighbor_volume], check=False, timeout=30
            )
            if cleanup.returncode != 0:
                print(
                    f"neighbor proof cleanup failed: {cleanup.stderr.strip()}",
                    file=sys.stderr,
                )
                cleanup_error = ReferenceEnvironmentError(
                    "failed to remove the adjacent-project proof volume"
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
    parser.add_argument("command", choices=("up", "bootstrap", "verify", "down", "smoke"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    environment = ReferenceEnvironment(args.project)
    try:
        getattr(environment, args.command)()
    except (ReferenceEnvironmentError, OSError, subprocess.SubprocessError, urllib.error.URLError) as error:
        print(f"reference environment failed: {error}", file=sys.stderr)
        return 1
    print(f"reference environment `{args.project}`: {args.command} complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
