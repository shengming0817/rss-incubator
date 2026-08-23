# Secure Device Credential Rotation

## Status and identity

Secure Device Credential Rotation is a non-publishable `rss-incubator` product candidate. It is the
only incubator product identity reserved for the `device-security` candidate consumer and reference
agent. It is not an RSS official profile, a production acceptance owner, an RC, or T3 evidence.

The repository maintainers named in [`MAINTAINERS.md`](../MAINTAINERS.md) own the product source,
workspace, root lockfile, build, CI, dependency upgrades, rollback, and product response. Private
security reporting and coordinated response use [`SECURITY.md`](../SECURITY.md); this document does
not duplicate either owner list or contact channel.

The existing `rss-consumer-smoke` remains a separate observability compatibility proof. It is not
part of this product and does not provide principal, tenant, authorization, or device-state evidence.

## Ownership boundary

| Fact | RSS | `rss-incubator` | External control plane |
| --- | --- | --- | --- |
| Release Surface, API, SemVer, package/image correctness, fix/yank/release approval | Owner | Exact artifact consumer | Not an owner |
| Verified principal/tenant, ABAC execution, desired/reported generation, fencing, command/receipt/reconcile, authenticated MQTT admission | Execution owner | Consumes public results; does not copy decisions or state machines | Supplies IdP/broker authority and configuration |
| Rotation product, model, client, control CLI, reference agent, workspace/lock/CI, product rollback and security response | Not an owner | Owner | Supplies dependent services |
| PKI/CA/EST/CSR/SAN authorization/signing/CRL/OCSP/certificate lifecycle | Consumes a narrow authorized artifact closure | Configures a disposable reference environment only | Production authority |
| Resource Security Fact source and authoring lifecycle | Consumes a narrow projection | May seed a disposable T2 fixture | Production authority |
| MDM, fleet, inventory, enrollment, device operations, and UI | Not an owner | Not an owner | External product scope |

The only allowed dependency direction is:

```text
rss-incubator -> immutable RSS Release Surface artifacts
```

RSS dependencies must be released registry artifacts or exact immutable candidates bound to a
version, checksum, and source revision by this repository's candidate proof. Path, Git, workspace,
submodule, vendored, internal, generated, provider-catalog, RuntimePlan, test-fixture, governance,
and T3-harness dependencies are forbidden.

## Public waist and product model

The future `rss-device-security-contracts` candidate has one six-contract public waist:

1. `identity.device-certificate-policy-put`
2. `identity.device-certificate-status-get`
3. `identity.apply-device-certificate`
4. `identity.device-command-acked`
5. `identity.device-certificate-reported`
6. `identity.device-ingress-receipted`

Resource Security Fact write is not a seventh RSS contract. There is no six/seven compatibility
path, alias, local generated copy, or lifecycle change in this product skeleton.

`rotation-model` contains product-owned opaque references, positive generation/fence values, and
distinct schema-aligned projections for acceptance, command acknowledgement, credential report,
and application receipt. It preserves the public contracts' closed outcomes, reasons, fence,
sequence, digest, and timestamp discriminants without copying wire DTOs. Construction validates
product shape only; authenticated provenance remains the future client's ingress responsibility.
These values grant no identity, authorization, readiness, or authoritative transition. The model
deliberately has no `Ready` type or predicate, allow/deny decision, L4 state machine, reconcile
behavior, transport DTO, secret material, or provider API.

## Implementation handoff

The sequence below is the single implementation path; no item is implemented by this skeleton:

1. **Azure PBI #2119** creates `crates/rss-device-security-client` and maps only the exact registry
   contract candidate into product facts.
2. **Azure PBI #2120** creates the disposable Keycloak, Vault, Mosquitto, and PostgreSQL reference
   environment without production secrets or mutable RSS image tags.
3. **Azure PBI #2121** implements `apps/rotation-control` through the public client, without local
   authentication or authorization decisions.
4. **Azure PBI #2122** implements `apps/reference-device-agent` with authenticated transport and
   device-local durability, without becoming an MDM/fleet agent.
5. **Azure PBI #2123** implements the canonical external T2 journey and focused failures. It does
   not register a T3 selector or production acceptance carrier.

## Release, rollback, and incubation exit

The skeleton is version `0.0.0`, `publish = false`, and carries no public support, SemVer, image, or
release commitment. Candidate upgrades use only the existing locked/offline artifact proof. A
failure blocks product release and returns the product pin or commit to the last known-green artifact;
it never restores source coupling or duplicates RSS internals.

Graduation requires a separate scope decision, ADR, and PBI that close product ownership, public
versioning, release and upgrade policy, data migration, operations, security support, and rollback.
It may consume only stable RSS Release Surface artifacts.

## Carrier map

| Risk | Current carrier | Strength and claim |
| --- | --- | --- |
| ACK, report, and application receipt become interchangeable | Separate Rust structs with no conversion or readiness API | Rust type-system Hard |
| Rotation model imports RSS, source/workspace, transport, or provider coupling | Package-scoped negative dependency policy over every Cargo dependency table | CI policy Hard for declared forbidden edges |
| Source coupling enters candidate consumption | Independent repository, committed root lock, existing candidate proof | Physical/Cargo Hard plus proof Medium |
| Product scope, owner, public-waist choice, and T3 prohibition drift | Accepted upstream ADR plus review of this scope document | Policy/review fact; not represented as machine enforcement |

No Markdown scanner, shape-count gate, second registry, evidence database, runner, or release control
plane is introduced to make policy text look executable.
