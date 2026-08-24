# Reference Device Agent

`reference-device-agent` is the non-publishable product reference for Azure PBI #2122. It runs one
device identity over MQTT v5 with mandatory mTLS, QoS 1, a persistent session, and manual inbound
PUBACK. It is deliberately not a generic SDK, fleet agent, enrollment client, CA client, artifact
downloader, inventory system, or control plane.

Build and preserve the executable only through the isolated candidate proof. The output path must
be absolute, its parent must already exist, and the destination must not exist:

```sh
python3 scripts/candidate-proof.py \
  --bundle /absolute/path/to/rss-candidate-bundle \
  --binary-output /absolute/path/to/reference-device-agent
```

The proof writes the binary only after the locked/offline candidate matrix passes. The executable
then accepts exactly one absolute configuration path:

```sh
reference-device-agent /absolute/path/to/config.json
```

Configuration and state are strict version-1 documents. Unknown fields, unknown versions, zero
generations, corrupt state, an unavailable current credential, or invalid credential material stop
the process. There is no migration, plaintext mode, clean-session mode, legacy topic, or insecure
fallback.

```json
{
  "schemaVersion": 1,
  "tenantId": "00000000-0000-0000-0000-000000000001",
  "deviceId": "00000000-0000-0000-0000-000000000101",
  "credentialGeneration": 1,
  "stateDirectory": "state",
  "artifactCatalog": "catalog/catalog.json",
  "mqtt": {
    "host": "127.0.0.1",
    "port": 8883,
    "clientId": "rss-reference-device-00000000-0000-0000-0000-000000000001-00000000-0000-0000-0000-000000000101",
    "sessionExpirySeconds": 3600,
    "requestCapacity": 16,
    "brokerAssertionPublicKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
  },
  "initial": {
    "desiredGeneration": 1,
    "fenceEpoch": 1,
    "credentialRevision": 1,
    "caPath": "credentials/ca.pem",
    "certificatePath": "credentials/device.pem",
    "privateKeyPath": "credentials/device-key.pem"
  }
}
```

Relative paths are resolved from the configuration directory. The artifact catalog maps opaque IDs
to controlled local files; IDs are never interpreted as paths. Each strict catalog entry binds the
artifact digest, tenant, device, credential generation, desired generation, fence, intent digest,
policy hash, and mandatory local `revoked` status. A revoked entry is rejected before any revision is
installed. Catalog paths and every path component must be regular, non-symlink files contained by
the catalog root. The certificate must chain to the configured CA, match its private key, be currently
valid, and contain the exact URI SAN
`urn:rss:mqtt-device:v1:<tenant>:<device>:<credential-generation>`. Private keys must be owner-only
on Unix.

`brokerAssertionPublicKey` is the canonical unpadded base64url encoding of a 32-byte Ed25519 public
key. Its private half belongs only to the broker plugin. Every command must carry a broker-minted
assertion binding the target identity, topic, correlation ID, payload digest, QoS, and retain bit;
retained commands and publisher-supplied reserved assertion properties are rejected.

The only command subscription is:

```text
rss/v1/<tenant>/<device>/<credential-generation>/downlink/identity.commands.apply-device-certificate
```

The public contract ID remains `identity.apply-device-certificate`; the transport segment above is
the sole MQTT routing name. No alias or dual subscription exists.

Accepted credentials are installed in immutable revision directories. The revision and protocol
state switch through a synced temporary file and atomic rename before the inbound command is
PUBACKed. The durable ACK must itself receive broker PUBACK before the process reconnects with the
new credential and makes the report publishable. Broker PUBACK is only a transport fact; the agent
does not create application receipts or infer `Ready`. A full 128-entry outbox stops command intake
through backpressure instead of dropping or replacing facts. After a new credential is committed,
all retries use it; the agent never rolls back to the previous revision.
