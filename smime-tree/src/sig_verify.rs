//! Shared signature-verification helpers used by both `cert` (issuer-sig chain
//! validation) and `verify` (CMS SignerInfo signature verification).
//!
//! Each function accepts an error-constructor closure so the caller can map
//! failures to the appropriate `SmimeError` variant (`CertChain` or `Other`).

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_EC_PUBLIC_KEY, SECP_256_R_1,
    SECP_384_R_1,
};
use const_oid::AssociatedOid;
use der::Encode;
use rsa::{pkcs1v15, pkcs8::DecodePublicKey, PublicKey};
use sha2::digest::Digest;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier as _;
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
    let rsa_pub = PublicKey::from_public_key_der(&spki_der).map_err(|e| err(e.to_string()))?;
    let verifying_key = pkcs1v15::VerifyingKey::<D>::new(rsa_pub);
    let signature = pkcs1v15::Signature::try_from(sig_bytes).map_err(|e| err(e.to_string()))?;
    verifying_key
        .verify(tbs_bytes, &signature)
        .map_err(|e| err(format!("RSA sig verify: {e}")))
}

/// Hash function named by an `ecdsa-with-SHA*` signature algorithm OID
/// (RFC 5758 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcdsaHash {
    Sha256,
    Sha384,
    Sha512,
}

impl EcdsaHash {
    /// Map the DER content octets of a signature algorithm OID to the hash it
    /// names, or `None` if the OID is not `ecdsa-with-SHA256/384/512`.
    ///
    /// Takes raw OID bytes so callers using either the `der` 0.7 or 0.8
    /// `ObjectIdentifier` type can share this function.
    pub(crate) fn from_sig_alg_oid_bytes(oid: &[u8]) -> Option<Self> {
        if oid == ECDSA_WITH_SHA_256.as_bytes() {
            Some(Self::Sha256)
        } else if oid == ECDSA_WITH_SHA_384.as_bytes() {
            Some(Self::Sha384)
        } else if oid == ECDSA_WITH_SHA_512.as_bytes() {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }
}

/// Failure modes of [`verify_ecdsa_raw`].
#[derive(Debug)]
pub(crate) enum EcdsaError {
    /// The key is not an `id-ecPublicKey` key on P-256 or P-384.
    UnsupportedKey(String),
    /// The key, signature encoding, or signature value is invalid.
    Invalid(String),
}

/// Verify a DER-encoded ECDSA signature over `message`.
///
/// The curve is taken from the public key (`spki_alg_oid` must be
/// `id-ecPublicKey` and `curve_oid` its `namedCurve` parameter), never from the
/// signature algorithm: the `ecdsa-with-SHA*` OIDs name only the hash
/// (RFC 5758 §3.2), and any of SHA-256/384/512 may be combined with either
/// P-256 or P-384 (OpenSSL, for example, signs with SHA-256 by default
/// regardless of curve).  `hash` is applied to `message` and the result is
/// verified as a prehash, which performs the FIPS 186 truncation or
/// zero-extension of the digest to the curve order length.
///
/// All OID arguments are DER content octets; `point` is the SEC1-encoded
/// public point (the `subjectPublicKey` BIT STRING contents).
pub(crate) fn verify_ecdsa_raw(
    spki_alg_oid: &[u8],
    curve_oid: Option<&[u8]>,
    point: &[u8],
    hash: EcdsaHash,
    message: &[u8],
    sig_der: &[u8],
) -> Result<(), EcdsaError> {
    if spki_alg_oid != ID_EC_PUBLIC_KEY.as_bytes() {
        return Err(EcdsaError::UnsupportedKey(
            "ECDSA signature algorithm used with a non-EC public key".into(),
        ));
    }
    let curve = curve_oid.ok_or_else(|| {
        EcdsaError::UnsupportedKey("EC public key without a namedCurve parameter".into())
    })?;
    let prehash = hash.digest(message);
    if curve == SECP_256_R_1.as_bytes() {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| EcdsaError::Invalid(format!("P-256 public key: {e}")))?;
        let sig = p256::ecdsa::DerSignature::try_from(sig_der)
            .map_err(|e| EcdsaError::Invalid(format!("P-256 signature encoding: {e}")))?;
        vk.verify_prehash(&prehash, &sig)
            .map_err(|e| EcdsaError::Invalid(format!("ECDSA P-256 sig verify: {e}")))
    } else if curve == SECP_384_R_1.as_bytes() {
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| EcdsaError::Invalid(format!("P-384 public key: {e}")))?;
        let sig = p384::ecdsa::DerSignature::try_from(sig_der)
            .map_err(|e| EcdsaError::Invalid(format!("P-384 signature encoding: {e}")))?;
        vk.verify_prehash(&prehash, &sig)
            .map_err(|e| EcdsaError::Invalid(format!("ECDSA P-384 sig verify: {e}")))
    } else {
        Err(EcdsaError::UnsupportedKey(
            "EC public key on a curve other than P-256 or P-384".into(),
        ))
    }
}

/// Verify an ECDSA signature made by the key in `cert`.
///
/// See [`verify_ecdsa_raw`] for how the curve and hash are chosen.  An
/// unsupported key maps to `SmimeError::UnsupportedAlgorithm`; every other
/// failure is passed through `err`.
pub(crate) fn verify_ecdsa(
    cert: &Certificate,
    hash: EcdsaHash,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
    err: impl Fn(String) -> SmimeError,
) -> Result<(), SmimeError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok());
    verify_ecdsa_raw(
        spki.algorithm.oid.as_bytes(),
        curve.as_ref().map(|c| c.as_bytes()),
        spki.subject_public_key.raw_bytes(),
        hash,
        tbs_bytes,
        sig_bytes,
    )
    .map_err(|e| match e {
        EcdsaError::UnsupportedKey(m) => SmimeError::UnsupportedAlgorithm(m),
        EcdsaError::Invalid(m) => err(m),
    })
}
