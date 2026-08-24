use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use sha2::{Digest as _, Sha256};

use crate::DeviceIdentity;

const ASSERTION_DOMAIN: &[u8] = b"rss.mqtt.authn.v1\0";
const RESERVED_PREFIX: &str = "rss.authn.v1.";
const VERSION_KEY: &str = "rss.authn.v1.version";
const PRINCIPAL_KEY: &str = "rss.authn.v1.principal";
const SIGNATURE_KEY: &str = "rss.authn.v1.signature";
const VERSION: &str = "1";

#[derive(Clone, Copy)]
pub(crate) struct BrokerPublishFrame<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub correlation: &'a [u8],
    pub qos: u8,
    pub retain: bool,
    pub properties: &'a [(String, String)],
}

/// Ed25519 verification material for broker-minted command assertions.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerAssertionVerifier {
    public_key: [u8; 32],
}

impl std::fmt::Debug for BrokerAssertionVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerAssertionVerifier(<public-key>)")
    }
}

impl BrokerAssertionVerifier {
    /// Parses one canonical unpadded base64url Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, non-canonical, or all-zero material.
    pub fn from_base64(value: &str) -> Result<Self, BrokerAssertionError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| BrokerAssertionError)?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_| BrokerAssertionError)?;
        if URL_SAFE_NO_PAD.encode(public_key) != value || public_key.iter().all(|byte| *byte == 0) {
            return Err(BrokerAssertionError);
        }
        Ok(Self { public_key })
    }

    /// Verifies the broker-minted assertion on one exact command transport frame.
    ///
    /// # Errors
    ///
    /// Returns an error unless every signed coordinate and reserved property is canonical.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_command(
        &self,
        identity: &DeviceIdentity,
        topic: &str,
        payload: &[u8],
        correlation: &[u8],
        qos: u8,
        retain: bool,
        properties: &[(String, String)],
    ) -> Result<(), BrokerAssertionError> {
        self.verify(
            identity,
            &BrokerPublishFrame {
                topic,
                payload,
                correlation,
                qos,
                retain,
                properties,
            },
        )
    }

    pub(crate) fn verify(
        &self,
        identity: &DeviceIdentity,
        frame: &BrokerPublishFrame<'_>,
    ) -> Result<(), BrokerAssertionError> {
        if frame.qos != 1 || frame.retain {
            return Err(BrokerAssertionError);
        }
        let assertion = assertion_properties(frame.properties)?;
        let expected_principal = identity.principal_urn();
        if assertion.principal != expected_principal {
            return Err(BrokerAssertionError);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(assertion.signature)
            .map_err(|_| BrokerAssertionError)?;
        if signature.len() != 64 {
            return Err(BrokerAssertionError);
        }
        let signed = canonical_bytes(assertion.principal, frame)?;
        UnparsedPublicKey::new(&ED25519, self.public_key)
            .verify(&signed, &signature)
            .map_err(|_| BrokerAssertionError)
    }
}

struct AssertionProperties<'a> {
    principal: &'a str,
    signature: &'a str,
}

fn assertion_properties(
    properties: &[(String, String)],
) -> Result<AssertionProperties<'_>, BrokerAssertionError> {
    let mut version = None;
    let mut principal = None;
    let mut signature = None;
    for (key, value) in properties {
        if !key.starts_with(RESERVED_PREFIX) {
            continue;
        }
        let slot = match key.as_str() {
            VERSION_KEY => &mut version,
            PRINCIPAL_KEY => &mut principal,
            SIGNATURE_KEY => &mut signature,
            _ => return Err(BrokerAssertionError),
        };
        if slot.replace(value.as_str()).is_some() {
            return Err(BrokerAssertionError);
        }
    }
    if version != Some(VERSION) {
        return Err(BrokerAssertionError);
    }
    Ok(AssertionProperties {
        principal: principal.ok_or(BrokerAssertionError)?,
        signature: signature.ok_or(BrokerAssertionError)?,
    })
}

fn canonical_bytes(
    principal: &str,
    frame: &BrokerPublishFrame<'_>,
) -> Result<Vec<u8>, BrokerAssertionError> {
    let payload_digest = Sha256::digest(frame.payload);
    let mut bytes = ASSERTION_DOMAIN.to_vec();
    append_field(&mut bytes, VERSION.as_bytes())?;
    append_field(&mut bytes, principal.as_bytes())?;
    append_field(&mut bytes, frame.topic.as_bytes())?;
    append_field(&mut bytes, frame.correlation)?;
    append_field(&mut bytes, &payload_digest)?;
    append_field(&mut bytes, &[frame.qos])?;
    append_field(&mut bytes, &[u8::from(frame.retain)])?;
    Ok(bytes)
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), BrokerAssertionError> {
    let length = u32::try_from(value.len()).map_err(|_| BrokerAssertionError)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

/// Closed broker-assertion verification failure.
#[derive(Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("MQTT broker assertion rejected")]
pub struct BrokerAssertionError;

impl std::fmt::Debug for BrokerAssertionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerAssertionError(\"MQTT broker assertion rejected\")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use uuid::Uuid;

    use crate::CredentialGeneration;

    fn identity() -> DeviceIdentity {
        DeviceIdentity::try_new(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("tenant"),
            Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("device"),
            CredentialGeneration::try_from(7).expect("generation"),
        )
        .expect("identity")
    }

    fn signed_properties(
        key: &Ed25519KeyPair,
        identity: &DeviceIdentity,
        frame: &BrokerPublishFrame<'_>,
    ) -> Vec<(String, String)> {
        let principal = identity.principal_urn();
        let signature = key.sign(&canonical_bytes(&principal, frame).expect("canonical"));
        vec![
            (VERSION_KEY.to_owned(), VERSION.to_owned()),
            (PRINCIPAL_KEY.to_owned(), principal),
            (
                SIGNATURE_KEY.to_owned(),
                URL_SAFE_NO_PAD.encode(signature.as_ref()),
            ),
        ]
    }

    #[test]
    fn signed_coordinates_are_exact_and_retained_commands_are_rejected() {
        let key = Ed25519KeyPair::from_pkcs8(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .expect("key")
                .as_ref(),
        )
        .expect("keypair");
        let encoded_key = URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
        let verifier = BrokerAssertionVerifier::from_base64(&encoded_key).expect("verifier");
        let identity = identity();
        let topic = crate::TopicSet::new(&identity).command().to_owned();
        let payload = b"payload";
        let correlation = b"command-1";
        let unsigned = BrokerPublishFrame {
            topic: &topic,
            payload,
            correlation,
            qos: 1,
            retain: false,
            properties: &[],
        };
        let properties = signed_properties(&key, &identity, &unsigned);
        let valid = BrokerPublishFrame {
            properties: &properties,
            ..unsigned
        };
        assert!(verifier.verify(&identity, &valid).is_ok());

        for invalid in [
            BrokerPublishFrame {
                payload: b"tampered",
                ..valid
            },
            BrokerPublishFrame {
                retain: true,
                ..valid
            },
            BrokerPublishFrame { qos: 0, ..valid },
        ] {
            assert!(verifier.verify(&identity, &invalid).is_err());
        }
    }
}
