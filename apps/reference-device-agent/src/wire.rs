use std::num::NonZeroU64;

use reference_device_agent_core::{
    AckFact, ArtifactId, CommandId, CommandRejection, DeviceCommand, DeviceIdentity, OutboundFact,
    ReportFact, Sha256Digest,
};
use rotation_model::{
    CommandRef, DeviceRef, FenceEpoch, Generation, RotationCoordinates, RotationId, TenantRef,
};
use rss_device_security_client::{MappingContext, correlate_command};
use rss_device_security_contracts::apply_device_certificate::IdentityApplyDeviceCertificateRequest;
use rss_device_security_contracts::device_certificate_reported::{
    IdentityDeviceCertificateReportedPayload,
    IdentityDeviceCertificateReportedPayloadArtifactDigest,
    IdentityDeviceCertificateReportedPayloadStateHash,
};
use rss_device_security_contracts::device_command_acked::{
    IdentityDeviceCommandAckedPayload, IdentityDeviceCommandAckedReceivedPayload,
    IdentityDeviceCommandAckedReceivedPayloadCommandId,
    IdentityDeviceCommandAckedReceivedPayloadReason,
    IdentityDeviceCommandAckedReceivedPayloadResult, IdentityDeviceCommandAckedRejectedPayload,
    IdentityDeviceCommandAckedRejectedPayloadCommandId,
    IdentityDeviceCommandAckedRejectedPayloadReason,
    IdentityDeviceCommandAckedRejectedPayloadResult,
};

#[derive(Debug, thiserror::Error)]
#[error("canonical device-security wire value is invalid")]
pub(crate) struct WireError;

pub(crate) fn decode_command(
    identity: &DeviceIdentity,
    command_id: &str,
    payload: &[u8],
) -> Result<DeviceCommand, WireError> {
    let request: IdentityApplyDeviceCertificateRequest =
        serde_json::from_slice(payload).map_err(|_| WireError)?;
    let coordinates = RotationCoordinates::new(
        RotationId::try_from(command_id).map_err(|_| WireError)?,
        TenantRef::try_from(identity.tenant().hyphenated().to_string()).map_err(|_| WireError)?,
        DeviceRef::try_from(identity.device().hyphenated().to_string()).map_err(|_| WireError)?,
    );
    let context = MappingContext::new(coordinates, identity.device());
    let correlated = correlate_command(
        context,
        CommandRef::try_from(command_id).map_err(|_| WireError)?,
        request,
    )
    .map_err(|_| WireError)?;
    let (_, _, request) = correlated.into_parts();
    Ok(DeviceCommand::new(
        CommandId::try_from(command_id).map_err(|_| WireError)?,
        request.device_id,
        ArtifactId::try_from(String::from(request.artifact_id)).map_err(|_| WireError)?,
        Sha256Digest::try_from(String::from(request.artifact_digest)).map_err(|_| WireError)?,
        request.authorization_receipt_id.as_uuid(),
        request.deadline_epoch_seconds,
        Generation::try_from(request.desired_generation.get()).map_err(|_| WireError)?,
        FenceEpoch::try_from(request.fence_epoch.get()).map_err(|_| WireError)?,
        Sha256Digest::try_from(String::from(request.intent_digest)).map_err(|_| WireError)?,
        Sha256Digest::try_from(String::from(request.policy_hash)).map_err(|_| WireError)?,
    ))
}

pub(crate) struct EncodedOutbound {
    pub event_id: String,
    pub kind: OutboundKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) enum OutboundKind {
    Acknowledgement,
    Report,
}

pub(crate) fn encode_outbound(
    identity: &DeviceIdentity,
    outbound: OutboundFact,
) -> Result<EncodedOutbound, WireError> {
    match outbound {
        OutboundFact::CommandAcknowledged { event_id, payload } => Ok(EncodedOutbound {
            event_id,
            kind: OutboundKind::Acknowledgement,
            payload: encode_ack(identity, payload)?,
        }),
        OutboundFact::CertificateReported { event_id, payload } => Ok(EncodedOutbound {
            event_id,
            kind: OutboundKind::Report,
            payload: encode_report(identity, payload)?,
        }),
    }
}

fn encode_ack(identity: &DeviceIdentity, payload: AckFact) -> Result<Vec<u8>, WireError> {
    let desired_generation = NonZeroU64::new(payload.desired_generation).ok_or(WireError)?;
    let fence_epoch = NonZeroU64::new(payload.fence_epoch).ok_or(WireError)?;
    let device_sequence = i64::try_from(payload.device_sequence).map_err(|_| WireError)?;
    let payload = match payload.rejection {
        None => IdentityDeviceCommandAckedPayload::ReceivedPayload(
            IdentityDeviceCommandAckedReceivedPayload {
                command_id: IdentityDeviceCommandAckedReceivedPayloadCommandId::try_from(
                    payload.command_id,
                )
                .map_err(|_| WireError)?,
                desired_generation,
                device_id: identity.device(),
                device_sequence,
                fence_epoch,
                observed_at: payload.observed_at,
                reason: IdentityDeviceCommandAckedReceivedPayloadReason::None,
                result: IdentityDeviceCommandAckedReceivedPayloadResult::Received,
            },
        ),
        Some(rejection) => IdentityDeviceCommandAckedPayload::RejectedPayload(
            IdentityDeviceCommandAckedRejectedPayload {
                command_id: IdentityDeviceCommandAckedRejectedPayloadCommandId::try_from(
                    payload.command_id,
                )
                .map_err(|_| WireError)?,
                desired_generation,
                device_id: identity.device(),
                device_sequence,
                fence_epoch,
                observed_at: payload.observed_at,
                reason: rejection_reason(rejection),
                result: IdentityDeviceCommandAckedRejectedPayloadResult::Rejected,
            },
        ),
    };
    serde_json::to_vec(&payload).map_err(|_| WireError)
}

fn encode_report(identity: &DeviceIdentity, payload: ReportFact) -> Result<Vec<u8>, WireError> {
    let report = IdentityDeviceCertificateReportedPayload {
        artifact_digest: IdentityDeviceCertificateReportedPayloadArtifactDigest::try_from(
            payload.artifact_digest,
        )
        .map_err(|_| WireError)?,
        device_id: identity.device(),
        device_sequence: i64::try_from(payload.device_sequence).map_err(|_| WireError)?,
        expires_at: payload.expires_at,
        fence_epoch: NonZeroU64::new(payload.fence_epoch).ok_or(WireError)?,
        observed_at: payload.observed_at,
        observed_generation: NonZeroU64::new(payload.observed_generation).ok_or(WireError)?,
        state_hash: IdentityDeviceCertificateReportedPayloadStateHash::try_from(payload.state_hash)
            .map_err(|_| WireError)?,
    };
    serde_json::to_vec(&report).map_err(|_| WireError)
}

const fn rejection_reason(
    rejection: CommandRejection,
) -> IdentityDeviceCommandAckedRejectedPayloadReason {
    match rejection {
        CommandRejection::ArtifactUnavailable => {
            IdentityDeviceCommandAckedRejectedPayloadReason::ArtifactUnavailable
        }
        CommandRejection::ArtifactDigestMismatch => {
            IdentityDeviceCommandAckedRejectedPayloadReason::ArtifactDigestMismatch
        }
        CommandRejection::PolicyRejected => {
            IdentityDeviceCommandAckedRejectedPayloadReason::PolicyRejected
        }
        CommandRejection::GenerationStale => {
            IdentityDeviceCommandAckedRejectedPayloadReason::GenerationStale
        }
        CommandRejection::FenceEpochStale => {
            IdentityDeviceCommandAckedRejectedPayloadReason::FenceEpochStale
        }
        CommandRejection::MalformedCommand => {
            IdentityDeviceCommandAckedRejectedPayloadReason::MalformedCommand
        }
        CommandRejection::DeviceFailure => {
            IdentityDeviceCommandAckedRejectedPayloadReason::DeviceFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reference_device_agent_core::{AckFact, CredentialGeneration};
    use uuid::Uuid;

    fn identity() -> DeviceIdentity {
        DeviceIdentity::new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("tenant"),
            Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("device"),
            CredentialGeneration::try_from(7).expect("generation"),
        )
    }

    #[test]
    fn canonical_command_is_decoded_without_a_local_wire_copy() {
        let payload = serde_json::json!({
            "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifactId": "fixture-device-certificate-0001",
            "authorizationReceiptId": "0198d5f2-70de-7a2d-b3f4-0123456789ab",
            "deadlineEpochSeconds": 1_900_000_000_u64,
            "desiredGeneration": 8,
            "deviceId": "00000000-0000-0000-0000-000000000101",
            "fenceEpoch": 3,
            "intentDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "policyHash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        });
        let command = decode_command(
            &identity(),
            "command-1",
            &serde_json::to_vec(&payload).expect("JSON"),
        )
        .expect("canonical command");

        assert_eq!(command.command_id().expose(), "command-1");
        assert_eq!(command.desired_generation().get(), 8);
        assert_eq!(command.fence_epoch().get(), 3);
    }

    #[test]
    fn canonical_decoder_rejects_unknown_fields_and_cross_device_payloads() {
        let mut payload = serde_json::json!({
            "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifactId": "fixture-device-certificate-0001",
            "authorizationReceiptId": "0198d5f2-70de-7a2d-b3f4-0123456789ab",
            "deadlineEpochSeconds": 1_900_000_000_u64,
            "desiredGeneration": 8,
            "deviceId": "00000000-0000-0000-0000-000000000999",
            "fenceEpoch": 3,
            "intentDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "policyHash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "legacyVersion": 0
        });
        assert!(
            decode_command(
                &identity(),
                "command-1",
                &serde_json::to_vec(&payload).expect("JSON")
            )
            .is_err()
        );
        payload
            .as_object_mut()
            .expect("object")
            .remove("legacyVersion");
        assert!(
            decode_command(
                &identity(),
                "command-1",
                &serde_json::to_vec(&payload).expect("JSON")
            )
            .is_err()
        );
    }

    #[test]
    fn acknowledgement_encoding_uses_the_canonical_closed_variant() {
        let encoded = encode_outbound(
            &identity(),
            OutboundFact::CommandAcknowledged {
                event_id: "ack-event".to_owned(),
                payload: AckFact {
                    command_id: "command-1".to_owned(),
                    desired_generation: 8,
                    fence_epoch: 3,
                    device_sequence: 4,
                    observed_at: 1_800_000_000,
                    rejection: Some(CommandRejection::FenceEpochStale),
                },
            },
        )
        .expect("ACK");
        let value: serde_json::Value = serde_json::from_slice(&encoded.payload).expect("JSON");
        assert_eq!(value["result"], "rejected");
        assert_eq!(value["reason"], "FenceEpochStale");
        assert_eq!(encoded.event_id, "ack-event");
    }
}
