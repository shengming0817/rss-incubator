#![doc = "Transport-neutral product model for secure device credential rotation."]

use std::fmt;
use std::num::NonZeroU64;

/// Validation failure for a product-owned rotation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationModelError {
    /// An opaque reference was empty or contained only whitespace.
    EmptyReference { kind: &'static str },
    /// An opaque reference contained a control character.
    ControlCharacter { kind: &'static str },
    /// An accepted generation must be greater than zero.
    ZeroGeneration,
    /// A fence epoch must be greater than zero.
    ZeroFenceEpoch,
}

impl fmt::Display for RotationModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReference { kind } => write!(formatter, "{kind} must not be empty"),
            Self::ControlCharacter { kind } => {
                write!(formatter, "{kind} must not contain control characters")
            }
            Self::ZeroGeneration => formatter.write_str("generation must be greater than zero"),
            Self::ZeroFenceEpoch => formatter.write_str("fence epoch must be greater than zero"),
        }
    }
}

impl std::error::Error for RotationModelError {}

macro_rules! opaque_reference {
    ($name:ident, $kind:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Returns the reference exactly as supplied by its owning boundary.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = RotationModelError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                validate_reference(value, $kind)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = RotationModelError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_reference(&value, $kind)?;
                Ok(Self(value))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

opaque_reference!(
    RotationId,
    "rotation_id",
    "Product-owned correlation ID for one rotation request."
);
opaque_reference!(
    TenantRef,
    "tenant_ref",
    "Opaque tenant reference that does not establish a verified tenant."
);
opaque_reference!(
    DeviceRef,
    "device_ref",
    "Opaque device reference that does not establish device identity."
);
opaque_reference!(
    PrincipalRef,
    "principal_ref",
    "Opaque requester reference that does not establish authentication."
);
opaque_reference!(
    AuthorizationReceiptRef,
    "authorization_receipt_ref",
    "Opaque reference to an authorization receipt issued outside this model."
);
opaque_reference!(
    CommandRef,
    "command_ref",
    "Opaque reference to a device command issued outside this model."
);
opaque_reference!(
    ApplicationReceiptRef,
    "application_receipt_ref",
    "Opaque reference to an application ingress receipt."
);
opaque_reference!(
    CredentialRevision,
    "credential_revision",
    "Opaque non-secret reference to a credential revision."
);

fn validate_reference(value: &str, kind: &'static str) -> Result<(), RotationModelError> {
    if value.trim().is_empty() {
        return Err(RotationModelError::EmptyReference { kind });
    }
    if value.chars().any(char::is_control) {
        return Err(RotationModelError::ControlCharacter { kind });
    }
    Ok(())
}

/// Positive generation observed at the public product boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// Returns the positive generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for Generation {
    type Error = RotationModelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RotationModelError::ZeroGeneration)
    }
}

/// Positive device-local fence epoch; it does not grant server authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FenceEpoch(NonZeroU64);

impl FenceEpoch {
    /// Returns the positive fence epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for FenceEpoch {
    type Error = RotationModelError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RotationModelError::ZeroFenceEpoch)
    }
}

/// Stable product coordinates shared by every observed rotation fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationCoordinates {
    rotation_id: RotationId,
    tenant: TenantRef,
    device: DeviceRef,
}

impl RotationCoordinates {
    /// Creates product coordinates without asserting identity or authorization.
    #[must_use]
    pub const fn new(rotation_id: RotationId, tenant: TenantRef, device: DeviceRef) -> Self {
        Self {
            rotation_id,
            tenant,
            device,
        }
    }

    /// Returns the product-owned rotation correlation ID.
    #[must_use]
    pub const fn rotation_id(&self) -> &RotationId {
        &self.rotation_id
    }

    /// Returns the unverified tenant reference.
    #[must_use]
    pub const fn tenant(&self) -> &TenantRef {
        &self.tenant
    }

    /// Returns the unverified device reference.
    #[must_use]
    pub const fn device(&self) -> &DeviceRef {
        &self.device
    }
}

/// Product request intent before any authoritative acceptance is observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationIntent {
    coordinates: RotationCoordinates,
    requested_by: PrincipalRef,
}

impl RotationIntent {
    /// Creates an intent without performing authentication or authorization.
    #[must_use]
    pub const fn new(coordinates: RotationCoordinates, requested_by: PrincipalRef) -> Self {
        Self {
            coordinates,
            requested_by,
        }
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns the unverified requester reference.
    #[must_use]
    pub const fn requested_by(&self) -> &PrincipalRef {
        &self.requested_by
    }
}

macro_rules! observed_fact {
    (
        $name:ident,
        $description:literal,
        $field:ident: $field_type:ty,
        $field_description:literal
    ) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            coordinates: RotationCoordinates,
            generation: Generation,
            $field: $field_type,
        }

        impl $name {
            /// Creates a product observation without minting upstream authority.
            #[must_use]
            pub const fn new(
                coordinates: RotationCoordinates,
                generation: Generation,
                $field: $field_type,
            ) -> Self {
                Self {
                    coordinates,
                    generation,
                    $field,
                }
            }

            /// Returns the rotation coordinates.
            #[must_use]
            pub const fn coordinates(&self) -> &RotationCoordinates {
                &self.coordinates
            }

            /// Returns the upstream-observed generation.
            #[must_use]
            pub const fn generation(&self) -> Generation {
                self.generation
            }

            #[doc = $field_description]
            #[must_use]
            pub const fn $field(&self) -> &$field_type {
                &self.$field
            }
        }
    };
}

observed_fact!(
    RotationAccepted,
    "Observed upstream acceptance; it does not authorize local policy decisions.",
    authorization_receipt: AuthorizationReceiptRef,
    "Returns the opaque upstream authorization receipt reference."
);

/// An application acknowledgement is not interchangeable with a report or receipt.
///
/// ```compile_fail
/// use rotation_model::{ApplicationReceiptObservation, CommandAcknowledgement};
///
/// fn requires_receipt(_: ApplicationReceiptObservation) {}
/// fn cannot_substitute(acknowledgement: CommandAcknowledgement) {
///     requires_receipt(acknowledgement);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandAcknowledgement {
    coordinates: RotationCoordinates,
    generation: Generation,
    command: CommandRef,
}

impl CommandAcknowledgement {
    /// Creates an ACK observation without deriving readiness.
    #[must_use]
    pub const fn new(
        coordinates: RotationCoordinates,
        generation: Generation,
        command: CommandRef,
    ) -> Self {
        Self {
            coordinates,
            generation,
            command,
        }
    }

    /// Returns the rotation coordinates.
    #[must_use]
    pub const fn coordinates(&self) -> &RotationCoordinates {
        &self.coordinates
    }

    /// Returns the acknowledged generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the opaque command reference.
    #[must_use]
    pub const fn command(&self) -> &CommandRef {
        &self.command
    }
}

observed_fact!(
    CredentialReport,
    "Observed device credential report; it does not advance authoritative state.",
    credential_revision: CredentialRevision,
    "Returns the reported non-secret credential revision reference."
);

observed_fact!(
    ApplicationReceiptObservation,
    "Observed application receipt; readiness remains an upstream status concern.",
    receipt: ApplicationReceiptRef,
    "Returns the opaque application receipt reference."
);
