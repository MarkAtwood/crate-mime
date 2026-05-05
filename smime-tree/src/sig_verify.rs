//! Shared signature-verification helpers used by both `cert` (issuer-sig chain
//! validation) and `verify` (CMS SignerInfo signature verification).
//!
//! Each function accepts an error-constructor closure so the caller can map
//! failures to the appropriate `SmimeError` variant (`CertChain` or `Other`).

use const_oid::AssociatedOid;
use der::Encode;
use p256::ecdsa::{DerSignature as P256DerSig, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{DerSignature as P384DerSig, VerifyingKey as P384VerifyingKey};
use rsa::{pkcs1v15, pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::digest::Digest;
use signature::Verifier as _;
use x509_cert::Certificate;

use crate::SmimeError;

/// Verify an RSA PKCS#1 v1.5 signature.
///
/// `D` must be a digest with an associated OID so that `VerifyingKey::new` can
/// embed the DigestInfo prefix.  `err` maps a human-readable string to the
/// appropriate `SmimeError` variant at the call site.
pub(crate) fn verify_rsa_pkcs1<D>(
    cert: &Certificate,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    err: impl Fn(String) -> SmimeError,
) -> Result<(), SmimeError>
where
    D: Digest + AssociatedOid,
{
    let spki_der = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| err(format!("SPKI DER encode: {e}")))?;
    let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| err(e.to_string()))?;
    let verifying_key = pkcs1v15::VerifyingKey::<D>::new(rsa_pub);
    let signature = pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| err(e.to_string()))?;
    rsa::signature::Verifier::verify(&verifying_key, tbs_bytes, &signature)
        .map_err(|e| err(format!("RSA sig verify: {e}")))
}

/// Verify an ECDSA-P256-SHA256 signature.
///
/// `err` maps a human-readable string to the appropriate `SmimeError` variant
/// at the call site.
pub(crate) fn verify_ecdsa_p256(
    cert: &Certificate,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    err: impl Fn(String) -> SmimeError,
) -> Result<(), SmimeError> {
    let pub_bytes = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let verifying_key =
        P256VerifyingKey::from_sec1_bytes(pub_bytes).map_err(|e| err(e.to_string()))?;
    let sig = P256DerSig::try_from(sig_bytes).map_err(|e| err(e.to_string()))?;
    verifying_key
        .verify(tbs_bytes, &sig)
        .map_err(|e| err(format!("ECDSA P-256 sig verify: {e}")))
}

/// Verify an ECDSA-P384-SHA384 signature.
///
/// `err` maps a human-readable string to the appropriate `SmimeError` variant
/// at the call site.
pub(crate) fn verify_ecdsa_p384(
    cert: &Certificate,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    err: impl Fn(String) -> SmimeError,
) -> Result<(), SmimeError> {
    let pub_bytes = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let verifying_key =
        P384VerifyingKey::from_sec1_bytes(pub_bytes).map_err(|e| err(e.to_string()))?;
    let sig = P384DerSig::try_from(sig_bytes).map_err(|e| err(e.to_string()))?;
    verifying_key
        .verify(tbs_bytes, &sig)
        .map_err(|e| err(format!("ECDSA P-384 sig verify: {e}")))
}
