# Secure Device Rotation Reference Environment

Azure PBI #2120 owns the future disposable Keycloak, Vault, Mosquitto, and PostgreSQL reference
environment. Its bootstrap must be idempotent and destructible, commit no production secret, use
fixed provider identities, and consume an immutable RSS candidate image rather than a mutable tag.

This skeleton contains no Compose file, IdP realm, PKI mount or role, broker ACL, database migration,
policy, Resource Security Fact authority, image, readiness probe, or production deployment claim.
