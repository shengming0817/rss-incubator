# Secure Device Rotation Reference Environment

This directory owns one disposable External/T2 fixture containing digest-pinned Keycloak, Vault,
Mosquitto, and PostgreSQL providers. It is not a production deployment, freshness or authorization
authority, T3 evidence, or an RSS service/image fixture.

## Lifecycle

Run all commands from the repository root. The project name is the deletion namespace and accepts
only 1–63 lowercase letters, digits, underscores, or hyphens.

```sh
python3 scripts/reference-environment.py --project rss-device-security-reference up
python3 scripts/reference-environment.py --project rss-device-security-reference bootstrap
python3 scripts/reference-environment.py --project rss-device-security-reference verify
python3 scripts/reference-environment.py --project rss-device-security-reference down
```

`up` creates a mode-0700 `deploy/.state/<project>` directory, random runtime credentials, and the
base providers. `bootstrap` converges Vault PKI, database roles, the Keycloak realm, and the exact
Mosquitto ACL. `verify` performs provider-native positive and negative authorization checks. `down`
removes only Compose resources with the validated project identity and then removes the matching
sentinel-protected state directory. A repeated `down` succeeds.

The complete acceptance journey is:

```sh
python3 scripts/reference-environment.py --project rss-device-security-reference smoke
```

It verifies repeated bootstrap preserves provider object identities and cryptographic material,
then destroys and rebuilds the environment to prove logical identities remain fixed while secrets,
keys, and certificate fingerprints rotate. A separately labelled neighbor volume must survive the
teardown. The script always collects Compose logs after a failure and attempts scoped cleanup.

## Fixed identities and boundaries

- Keycloak realm `rss-device-security`; clients `rotation-control` and `deviceidentity`.
- Vault PKI mount `device-pki`; server, device, and service roles with bounded SANs, EKUs, and TTLs.
- PostgreSQL databases `keycloak` and empty `deviceidentity`; migrator and serving roles remain
  separate, and this fixture never imports RSS migrations.
- Mosquitto accepts MQTTS client certificates only. Device and service identities receive opposite,
  exact topic directions; wildcard topics are absent.
- `policies/reference-fixture.json` supplies disposable tenant/device/generation coordinates and
  policy inputs. It neither writes an RSS database nor becomes a production authority or contract.

All passwords, tokens, private keys, CAs, and leaf certificates remain under ignored
`deploy/.state/`. Never copy that directory into source control or reuse its values outside this
fixture. The Compose file is the sole provider image and topology source; there is no RSS candidate
image until its owning PBI supplies an immutable artifact.

## Failure diagnosis

Use the failing command's message first. While state still exists, inspect scoped provider logs with:

```sh
docker compose \
  --env-file deploy/.state/rss-device-security-reference/runtime.env \
  --project-name rss-device-security-reference \
  --file deploy/compose.yaml logs --no-color
```

Do not use Docker prune or broad volume/container deletion. If the sentinel is missing or differs,
the lifecycle tool deliberately refuses cleanup; inspect the exact project-labelled resources and
repair the sentinel/state mismatch before invoking `down` again.
