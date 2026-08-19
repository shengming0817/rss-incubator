# Secure Device Rotation T2 Journey

Azure PBI #2123 owns the future canonical external T2 journey. Its positive path will correlate an
authorized rotation acceptance through command ACK, credential report, application receipt, and an
upstream status observation. Focused negative cases will cover deny/no-write, missing or stale facts,
tenant/device mismatch, replay or stale generation, revoked credentials, and dependency failure.

This directory currently contains no executable test, fixture, receipt, selector, scheduler, or T3
claim. ACK is not treated as readiness, and no database write or internal RSS test hook may fabricate
the final status.
