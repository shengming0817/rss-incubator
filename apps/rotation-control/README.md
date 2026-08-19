# Rotation Control

This directory reserves the Secure Device Credential Rotation control application identity for
Azure PBI #2121. That PBI will implement login, resource/policy bootstrap use, rotation submission,
status display, and audit display exclusively through the registry-only client from #2119.

This skeleton contains no executable, local allow/deny evaluation, token persistence, contract DTO,
database shortcut, or readiness derivation. Adding a Cargo manifest or application behavior belongs
to #2121.
