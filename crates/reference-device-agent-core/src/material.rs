use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{CredentialFiles, DeviceIdentity};

#[derive(Clone)]
pub(crate) struct ValidatedCredential {
    pub ca: Vec<u8>,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub expires_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential material is unavailable")]
    Unavailable,
    #[error("credential material is malformed")]
    Malformed,
    #[error("credential chain is untrusted or expired")]
    Untrusted,
    #[error("credential private key permissions are not owner-only")]
    InsecurePrivateKey,
    #[error("credential identity does not match the authenticated device scope")]
    IdentityMismatch,
}

pub(crate) fn validate_credential(
    files: &CredentialFiles,
    identity: &DeviceIdentity,
    now_epoch_seconds: u64,
) -> Result<ValidatedCredential, CredentialError> {
    require_private_key_mode(files.private_key())?;
    let ca = fs::read(files.ca_certificate()).map_err(|_| CredentialError::Unavailable)?;
    let certificate =
        fs::read(files.certificate_chain()).map_err(|_| CredentialError::Unavailable)?;
    let private_key = fs::read(files.private_key()).map_err(|_| CredentialError::Unavailable)?;

    let roots = parse_certificates(&ca)?;
    let chain = parse_certificates(&certificate)?;
    let key = parse_private_key(&private_key)?;
    let end_entity = chain.first().ok_or(CredentialError::Malformed)?;

    verify_key_matches(&chain, key)?;
    verify_chain(&roots, end_entity, &chain[1..], now_epoch_seconds)?;
    let expires_at = verify_identity(end_entity, identity)?;

    Ok(ValidatedCredential {
        ca,
        certificate,
        private_key,
        expires_at,
    })
}

fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, CredentialError> {
    let mut cursor = Cursor::new(bytes);
    let certificates = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CredentialError::Malformed)?;
    if certificates.is_empty() {
        return Err(CredentialError::Malformed);
    }
    Ok(certificates)
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, CredentialError> {
    rustls_pemfile::private_key(&mut Cursor::new(bytes))
        .map_err(|_| CredentialError::Malformed)?
        .ok_or(CredentialError::Malformed)
}

fn verify_key_matches(
    chain: &[CertificateDer<'static>],
    key: PrivateKeyDer<'static>,
) -> Result<(), CredentialError> {
    let provider = aws_lc_rs::default_provider();
    CertifiedKey::from_der(chain.to_vec(), key, &provider)
        .and_then(|certified| certified.keys_match())
        .map_err(|_| CredentialError::Malformed)
}

fn verify_chain(
    roots: &[CertificateDer<'static>],
    end_entity: &CertificateDer<'static>,
    intermediates: &[CertificateDer<'static>],
    now_epoch_seconds: u64,
) -> Result<(), CredentialError> {
    let mut root_store = RootCertStore::empty();
    let (added, _) = root_store.add_parsable_certificates(roots.iter().cloned());
    if added == 0 {
        return Err(CredentialError::Malformed);
    }
    let provider = Arc::new(aws_lc_rs::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), provider)
        .build()
        .map_err(|_| CredentialError::Malformed)?;
    verifier
        .verify_client_cert(
            end_entity,
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(now_epoch_seconds)),
        )
        .map_err(|_| CredentialError::Untrusted)?;
    Ok(())
}

fn verify_identity(
    end_entity: &CertificateDer<'_>,
    identity: &DeviceIdentity,
) -> Result<i64, CredentialError> {
    let (_, certificate) =
        X509Certificate::from_der(end_entity.as_ref()).map_err(|_| CredentialError::Malformed)?;
    let expected = identity.principal_urn();
    let matches = certificate
        .subject_alternative_name()
        .map_err(|_| CredentialError::Malformed)?
        .into_iter()
        .flat_map(|extension| extension.value.general_names.iter())
        .any(|name| matches!(name, GeneralName::URI(uri) if *uri == expected));
    if !matches {
        return Err(CredentialError::IdentityMismatch);
    }
    Ok(certificate.validity().not_after.timestamp())
}

#[cfg(unix)]
#[allow(clippy::verbose_bit_mask)]
fn require_private_key_mode(path: &Path) -> Result<(), CredentialError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = fs::metadata(path)
        .map_err(|_| CredentialError::Unavailable)?
        .permissions()
        .mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(CredentialError::InsecurePrivateKey)
    }
}

#[cfg(not(unix))]
fn require_private_key_mode(path: &Path) -> Result<(), CredentialError> {
    fs::metadata(path)
        .map(|_| ())
        .map_err(|_| CredentialError::Unavailable)
}
