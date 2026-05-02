//! Certificate chain validation for S/MIME verify.
//!
//! Performs a manual chain walk using RustCrypto primitives.  No network
//! calls are made; the caller supplies a bag of intermediate certificates
//! (extracted from the CMS SignedData) and a set of trust anchors.

use const_oid::{
    db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    },
    AssociatedOid,
};
use der::Encode;
use p256::ecdsa::{DerSignature as P256DerSig, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{DerSignature as P384DerSig, VerifyingKey as P384VerifyingKey};
use rsa::{pkcs1v15, pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::digest::Digest;
use sha2::{Sha256, Sha384, Sha512};
use std::time::SystemTime;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

use crate::SmimeError;

/// Maximum certificate chain depth accepted (prevents cycles and absurdly long chains).
const MAX_CHAIN_DEPTH: usize = 10;

/// Validate the certificate chain from `signer_cert` up to a trust anchor.
///
/// # Arguments
///
/// * `signer_cert`   – end-entity certificate extracted from the CMS SignerInfo
/// * `bag`           – intermediate certificates from the CMS SignedData certificates bag
/// * `trust_anchors` – caller-supplied trust anchors (must be non-empty)
/// * `now`           – current time used for validity-period checks
///
/// # Errors
///
/// Returns `SmimeError::CertChain` if the chain cannot be built or validated,
/// or `SmimeError::UnsupportedAlgorithm` for an unrecognised signature algorithm.
pub(crate) fn validate_chain(
    signer_cert: &Certificate,
    bag: &[Certificate],
    trust_anchors: &[Certificate],
    now: SystemTime,
) -> Result<(), SmimeError> {
    if trust_anchors.is_empty() {
        return Err(SmimeError::CertChain("no trust anchors provided".into()));
    }

    let mut current: &Certificate = signer_cert;

    for _depth in 0..MAX_CHAIN_DEPTH {
        // Step 1 — validity period.
        check_validity(current, now)?;

        // Step 2 — look for the issuer among the trust anchors first.
        // Collect all anchors whose subject DN matches the current cert's issuer.
        // There may be more than one (CA renewal: same DN, different key/validity).
        let candidates: Vec<&Certificate> = trust_anchors
            .iter()
            .filter(|a| {
                names_equal(
                    current.tbs_certificate().issuer(),
                    a.tbs_certificate().subject(),
                )
            })
            .collect();
        if !candidates.is_empty() {
            // Collect all candidates whose validity period contains `now`.
            let valid_candidates: Vec<&&Certificate> = candidates
                .iter()
                .filter(|a| check_validity(a, now).is_ok())
                .collect();
            if valid_candidates.is_empty() {
                return Err(SmimeError::CertChain(
                    "all matching trust anchors are expired or not yet valid".into(),
                ));
            }
            // Try each valid anchor for signature verification — the CA renewal case
            // produces two simultaneously-valid certs with the same DN but different
            // keys, so the first valid anchor may not be the right one.
            for anchor in &valid_candidates {
                if verify_signature(current, anchor).is_ok() {
                    return Ok(());
                }
            }
            return Err(SmimeError::CertChain(
                "certificate chain: issuer signature does not match any trust anchor".into(),
            ));
        }

        // Step 3 — look for the issuer in the certificate bag.
        let parent = bag.iter().find(|candidate| {
            names_equal(
                current.tbs_certificate().issuer(),
                candidate.tbs_certificate().subject(),
            ) && verify_signature(current, candidate).is_ok()
        });

        match parent {
            Some(p) => {
                // The parent must be a CA (BasicConstraints.cA = true).
                if !is_ca_cert(p) {
                    return Err(SmimeError::CertChain(
                        "intermediate cert is not a CA".into(),
                    ));
                }
                current = p;
            }
            None => {
                return Err(SmimeError::CertChain(
                    "certificate chain: no trust anchor matches issuer \
                     (add the CA root cert to trust_anchors)"
                        .into(),
                ));
            }
        }
    }

    Err(SmimeError::CertChain(
        "certificate chain exceeds maximum depth of 10".into(),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return `Ok(())` if `cert`'s validity period contains `now`.
fn check_validity(cert: &Certificate, now: SystemTime) -> Result<(), SmimeError> {
    let not_before = SystemTime::from(&cert.tbs_certificate().validity().not_before);
    let not_after = SystemTime::from(&cert.tbs_certificate().validity().not_after);
    if now < not_before || now > not_after {
        return Err(SmimeError::CertChain(
            "certificate expired or not yet valid".into(),
        ));
    }
    Ok(())
}

/// Return `true` if `cert` has BasicConstraints with `cA = true`.
fn is_ca_cert(cert: &Certificate) -> bool {
    cert.tbs_certificate()
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .map(|(_critical, bc)| bc.ca)
        .unwrap_or(false)
}

/// Return `true` if the DER encodings of two `Name` values are identical.
fn names_equal(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(a_der), Ok(b_der)) => a_der == b_der,
        _ => false,
    }
}

/// Verify `cert`'s signature using `issuer`'s public key.
///
/// Returns `Ok(())` on success.  The caller is responsible for mapping errors
/// to the appropriate `CertChain` message.
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), SmimeError> {
    let tbs_der = cert
        .tbs_certificate()
        .to_der()
        .map_err(|e| SmimeError::CertChain(format!("TBS DER encode: {e}")))?;
    let sig_bytes = cert.signature().raw_bytes();
    let oid = &cert.signature_algorithm().oid;

    if *oid == SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa_pkcs1::<Sha256>(issuer, &tbs_der, sig_bytes)
    } else if *oid == SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa_pkcs1::<Sha384>(issuer, &tbs_der, sig_bytes)
    } else if *oid == SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa_pkcs1::<Sha512>(issuer, &tbs_der, sig_bytes)
    } else if *oid == ECDSA_WITH_SHA_256 {
        verify_ecdsa_p256(issuer, &tbs_der, sig_bytes)
    } else if *oid == ECDSA_WITH_SHA_384 {
        verify_ecdsa_p384(issuer, &tbs_der, sig_bytes)
    } else {
        Err(SmimeError::UnsupportedAlgorithm(oid.to_string()))
    }
}

/// Verify an RSA PKCS#1 v1.5 signature.
///
/// `D` must be a digest with an associated OID so that `VerifyingKey::new` can
/// embed the DigestInfo prefix.
fn verify_rsa_pkcs1<D>(
    issuer: &Certificate,
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SmimeError>
where
    D: Digest + AssociatedOid,
{
    let spki_der = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| SmimeError::CertChain(format!("SPKI DER encode: {e}")))?;
    let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| SmimeError::CertChain(e.to_string()))?;
    let verifying_key = pkcs1v15::VerifyingKey::<D>::new(rsa_pub);
    let signature = pkcs1v15::Signature::try_from(sig_bytes)
        .map_err(|e| SmimeError::CertChain(e.to_string()))?;
    rsa::signature::Verifier::verify(&verifying_key, tbs_der, &signature)
        .map_err(|e| SmimeError::CertChain(format!("RSA sig verify: {e}")))
}

/// Verify an ECDSA-P256-SHA256 signature.
fn verify_ecdsa_p256(
    issuer: &Certificate,
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SmimeError> {
    // subject_public_key is a BitString containing the uncompressed SEC1 point.
    let pub_bytes = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let verifying_key = P256VerifyingKey::from_sec1_bytes(pub_bytes)
        .map_err(|e| SmimeError::CertChain(e.to_string()))?;
    let sig = P256DerSig::try_from(sig_bytes).map_err(|e| SmimeError::CertChain(e.to_string()))?;
    rsa::signature::Verifier::verify(&verifying_key, tbs_der, &sig)
        .map_err(|e| SmimeError::CertChain(format!("ECDSA P-256 sig verify: {e}")))
}

/// Verify an ECDSA-P384-SHA384 signature.
fn verify_ecdsa_p384(
    issuer: &Certificate,
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), SmimeError> {
    let pub_bytes = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let verifying_key = P384VerifyingKey::from_sec1_bytes(pub_bytes)
        .map_err(|e| SmimeError::CertChain(e.to_string()))?;
    let sig = P384DerSig::try_from(sig_bytes).map_err(|e| SmimeError::CertChain(e.to_string()))?;
    rsa::signature::Verifier::verify(&verifying_key, tbs_der, &sig)
        .map_err(|e| SmimeError::CertChain(format!("ECDSA P-384 sig verify: {e}")))
}
