//! S/MIME verify: parse a CMS SignedData blob and verify each SignerInfo.
//!
//! The caller supplies the exact raw bytes of the signed MIME part (use
//! `mime-tree` byte ranges to extract them) and the DER-encoded detached
//! signature (`application/pkcs7-signature` part).  Trust anchors are
//! also caller-supplied; no network calls are made.

use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use const_oid::db::{
    rfc5911::ID_MESSAGE_DIGEST,
    rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_SHA_256, ID_SHA_384, ID_SHA_512, RSA_ENCRYPTION,
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    },
};
use der::{asn1::OctetString, Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

use crate::{cert::validate_chain, key::RevocationChecker, sig_verify, SmimeError};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/// Overall result from verifying a `multipart/signed` S/MIME message.
///
/// `Ok(VerificationResult)` is returned only when at least one signer
/// verified successfully.  Per-signer detail (including failures for other
/// signers) is available in the `signers` vec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// One entry per `SignerInfo` found in the `SignedData`.
    pub signers: Vec<SignerResult>,
}

/// Result for a single `SignerInfo` within a `SignedData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerResult {
    /// `true` iff all of the following succeeded:
    /// message-digest check, signature verification, and cert-chain validation.
    pub verified: bool,
    /// Distinguished name of the signer's certificate subject, if found.
    pub subject: Option<String>,
    /// Human-readable error string when `verified == false`.
    pub error: Option<String>,
}

impl VerificationResult {
    /// Returns `true` if at least one signer verified successfully.
    pub fn is_verified(&self) -> bool {
        self.signers.iter().any(|s| s.verified)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify a detached CMS `SignedData` against raw signed content.
///
/// # Arguments
///
/// * `signed_content` — exact raw bytes of the signed MIME part (extracted
///   using `mime-tree` byte ranges; must match what was signed byte-for-byte).
/// * `signature_der`  — DER-encoded `ContentInfo` wrapping a `SignedData`
///   (the `application/pkcs7-signature` MIME part, after base64 decoding).
/// * `trust_anchors`  — caller-supplied trust anchors; chain validation fails
///   if this slice is empty.
/// * `now`            — current time used for certificate validity-period checks.
///   Pass `SystemTime::now()` for normal use; pass a fixed time in tests to
///   validate against certificates with known validity periods.
/// * `revocation`     — revocation checker invoked for each certificate in the
///   chain.  Pass `&NoRevocationCheck` to skip revocation checking.  Implement
///   [`RevocationChecker`] to inject OCSP or CRL validation.
///
/// # Errors
///
/// Returns `Err` when:
/// - The outer DER structure cannot be parsed (`SmimeError::Der`).
/// - The `SignedData` contains no `SignerInfo` entries.
/// - Every signer fails verification (message-digest mismatch, bad signature,
///   or cert-chain error).  At least one signer must succeed for `Ok` to be returned.
pub fn verify(
    signed_content: &[u8],
    signature_der: &[u8],
    trust_anchors: &[Certificate],
    now: std::time::SystemTime,
    revocation: &dyn RevocationChecker,
) -> Result<VerificationResult, SmimeError> {
    // Parse ContentInfo → SignedData.
    let ci = ContentInfo::from_der(signature_der)?;
    let content_der = ci.content.to_der()?;
    let sd = SignedData::from_der(content_der.as_slice())?;

    // Collect the certificate bag.
    let bag_certs: Vec<Certificate> = sd
        .certificates
        .as_ref()
        .map(|cs| {
            cs.0.iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(cert) => Some(cert.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Process each SignerInfo independently.
    let signers: Vec<SignerResult> = sd
        .signer_infos
        .0
        .iter()
        .map(|si| {
            verify_one(
                signed_content,
                si,
                &bag_certs,
                trust_anchors,
                now,
                revocation,
            )
        })
        .collect();

    if signers.is_empty() {
        return Err(SmimeError::Other(
            "no SignerInfo entries in SignedData".into(),
        ));
    }
    if signers.iter().all(|s| !s.verified) {
        return Err(SmimeError::AllSignersFailed(signers));
    }

    Ok(VerificationResult { signers })
}

// ---------------------------------------------------------------------------
// Per-signer verification
// ---------------------------------------------------------------------------

/// Build a failed `SignerResult` with a human-readable error message.
fn fail(subject: Option<String>, msg: impl Into<String>) -> SignerResult {
    SignerResult {
        verified: false,
        subject,
        error: Some(msg.into()),
    }
}

/// Run all five verification steps for a single `SignerInfo`.
///
/// Any failure is captured in `SignerResult.error` rather than propagated.
fn verify_one(
    signed_content: &[u8],
    si: &cms::signed_data::SignerInfo,
    bag_certs: &[Certificate],
    trust_anchors: &[Certificate],
    now: std::time::SystemTime,
    revocation: &dyn RevocationChecker,
) -> SignerResult {
    // Step 1: compute content digest.
    let hash = match compute_digest(signed_content, &si.digest_alg.oid) {
        Ok(h) => h,
        Err(e) => return fail(None, e.to_string()),
    };

    // Step 2: find signer cert in the bag or trust anchors.
    let signer_cert = match find_cert(bag_certs, trust_anchors, &si.sid) {
        Some(c) => c,
        None => return fail(None, "signer cert not found in certificate bag"),
    };

    let subject_str = signer_cert.tbs_certificate().subject().to_string();

    // Step 3: check that signed_attrs is present, then verify message digest.
    let signed_attrs = match si.signed_attrs.as_ref() {
        Some(a) => a,
        None => return fail(Some(subject_str), "no signed attributes present"),
    };

    if let Err(e) = check_message_digest(signed_attrs, &hash) {
        return fail(Some(subject_str), e.to_string());
    }

    // Step 4: verify signature over DER(signed_attrs).
    let tbs_bytes = match signed_attrs.to_der() {
        Ok(b) => b,
        Err(e) => return fail(Some(subject_str), format!("signed_attrs DER encode: {e}")),
    };
    let sig_bytes = si.signature.as_bytes();

    if let Err(e) = verify_sig(
        &signer_cert,
        &si.signature_algorithm.oid,
        &si.digest_alg.oid,
        &tbs_bytes,
        sig_bytes,
    ) {
        return fail(Some(subject_str), e.to_string());
    }

    // Step 5: validate certificate chain (includes revocation check per cert).
    if let Err(e) = validate_chain(&signer_cert, bag_certs, trust_anchors, now, revocation) {
        return fail(Some(subject_str), e.to_string());
    }

    SignerResult {
        verified: true,
        subject: Some(subject_str),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Step 1: content digest
// ---------------------------------------------------------------------------

fn compute_digest(data: &[u8], oid: &der::asn1::ObjectIdentifier) -> Result<Vec<u8>, SmimeError> {
    match *oid {
        x if x == ID_SHA_256 => Ok(Sha256::digest(data).to_vec()),
        x if x == ID_SHA_384 => Ok(Sha384::digest(data).to_vec()),
        x if x == ID_SHA_512 => Ok(Sha512::digest(data).to_vec()),
        _ => Err(SmimeError::UnsupportedAlgorithm(format!(
            "digest OID {oid}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Step 2: find signer cert
// ---------------------------------------------------------------------------

fn find_cert(
    bag: &[Certificate],
    trust_anchors: &[Certificate],
    sid: &SignerIdentifier,
) -> Option<Certificate> {
    // Search first in the embedded certificate bag, then in the trust anchors.
    // RFC 5652 §5.1 permits the signer to omit their cert from the bag if the
    // receiver already has it (e.g. it is itself a trust anchor).
    let mut all_certs = bag.iter().chain(trust_anchors.iter());

    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => all_certs
            .find(|cert| {
                let issuer_ok = cert
                    .tbs_certificate()
                    .issuer()
                    .to_der()
                    .ok()
                    .zip(ias.issuer.to_der().ok())
                    .map(|(a, b)| a == b)
                    .unwrap_or(false);
                let serial_ok = cert.tbs_certificate().serial_number() == &ias.serial_number;
                issuer_ok && serial_ok
            })
            .cloned(),

        SignerIdentifier::SubjectKeyIdentifier(sid_ski) => {
            // sid_ski is an x509_cert SubjectKeyIdentifier (newtype over OctetString).
            // Compare its raw bytes against the cert's SKI extension value.
            let sid_bytes = sid_ski.0.as_bytes();
            all_certs
                .find(|cert| {
                    cert.tbs_certificate()
                        .get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                        .ok()
                        .flatten()
                        .map(|(_critical, ext_ski)| ext_ski.0.as_bytes() == sid_bytes)
                        .unwrap_or(false)
                })
                .cloned()
        }
    }
}

// ---------------------------------------------------------------------------
// Step 3: message digest attribute check
// ---------------------------------------------------------------------------

fn check_message_digest(
    signed_attrs: &x509_cert::attr::Attributes,
    content_hash: &[u8],
) -> Result<(), SmimeError> {
    let md_attr = signed_attrs
        .iter()
        .find(|a| a.oid == ID_MESSAGE_DIGEST)
        .ok_or_else(|| SmimeError::Other("messageDigest attribute not found".into()))?;

    // The attribute value is encoded as an OctetString DER blob inside the Any.
    let expected_bytes: Vec<u8> = md_attr
        .values
        .iter()
        .next()
        .and_then(|v| OctetString::from_der(v.to_der().ok()?.as_slice()).ok())
        .map(|os| os.as_bytes().to_vec())
        .ok_or_else(|| SmimeError::Other("cannot decode messageDigest attribute value".into()))?;

    if expected_bytes != content_hash {
        return Err(SmimeError::Other("message digest mismatch".into()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: signature verification (dispatched by signature algorithm OID)
// ---------------------------------------------------------------------------

fn verify_sig(
    cert: &Certificate,
    sig_alg_oid: &der::asn1::ObjectIdentifier,
    digest_alg_oid: &der::asn1::ObjectIdentifier,
    tbs_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SmimeError> {
    let e = |msg: String| SmimeError::Other(msg);
    if *sig_alg_oid == SHA_256_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha256, _>(cert, tbs_bytes, sig_bytes, e)
    } else if *sig_alg_oid == SHA_384_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha384, _>(cert, tbs_bytes, sig_bytes, e)
    } else if *sig_alg_oid == SHA_512_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha512, _>(cert, tbs_bytes, sig_bytes, e)
    } else if *sig_alg_oid == RSA_ENCRYPTION {
        // RFC 5652 §5.4 + RFC 5751 §2.1: implementations MAY use rsaEncryption
        // in SignerInfo.signatureAlgorithm (rather than sha*WithRSAEncryption).
        // When they do, the digest is determined by SignerInfo.digestAlgorithm.
        if *digest_alg_oid == ID_SHA_256 {
            sig_verify::verify_rsa_pkcs1::<Sha256, _>(cert, tbs_bytes, sig_bytes, e)
        } else if *digest_alg_oid == ID_SHA_384 {
            sig_verify::verify_rsa_pkcs1::<Sha384, _>(cert, tbs_bytes, sig_bytes, e)
        } else if *digest_alg_oid == ID_SHA_512 {
            sig_verify::verify_rsa_pkcs1::<Sha512, _>(cert, tbs_bytes, sig_bytes, e)
        } else {
            Err(SmimeError::UnsupportedAlgorithm(format!(
                "rsaEncryption with digest OID {digest_alg_oid}"
            )))
        }
    } else if *sig_alg_oid == ECDSA_WITH_SHA_256 {
        sig_verify::verify_ecdsa_p256(cert, tbs_bytes, sig_bytes, e)
    } else if *sig_alg_oid == ECDSA_WITH_SHA_384 {
        sig_verify::verify_ecdsa_p384(cert, tbs_bytes, sig_bytes, e)
    } else {
        Err(SmimeError::UnsupportedAlgorithm(format!(
            "signature algorithm OID {sig_alg_oid}"
        )))
    }
}
