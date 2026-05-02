//! Certificate chain validation for S/MIME verify.
//!
//! Performs a manual chain walk using RustCrypto primitives.  No network
//! calls are made; the caller supplies a bag of intermediate certificates
//! (extracted from the CMS SignedData) and a set of trust anchors.

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
    SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use der::Encode;
use sha2::{Sha256, Sha384, Sha512};
use std::collections::HashSet;
use std::time::SystemTime;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::error::CertChainError;
use crate::key::RevocationChecker;
use crate::sig_verify;
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
    revocation: &dyn RevocationChecker,
) -> Result<(), SmimeError> {
    if trust_anchors.is_empty() {
        return Err(SmimeError::CertChain(CertChainError::NoTrustAnchors));
    }

    let mut current: &Certificate = signer_cert;

    // Track visited subjects (DER-encoded) to detect cycles in the bag.
    let mut visited: HashSet<Vec<u8>> = HashSet::new();
    if let Ok(subj) = signer_cert.tbs_certificate().subject().to_der() {
        visited.insert(subj);
    }

    // Count of non-self-issued intermediate CA certs accumulated below the
    // current position in the chain (RFC 5280 §4.2.1.9 pathLen semantics).
    let mut chain_depth: usize = 0;

    for _depth in 0..MAX_CHAIN_DEPTH {
        // Step 1 — validity period.
        check_validity(current, now)?;

        // Step 1b — revocation check (no-op unless caller injects OCSP/CRL).
        revocation.check(current)?;

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
            // RFC 5280 §6.1.3(a)(1) requires the current time to fall within
            // the validity interval of every certificate in the certification
            // path, including trust anchors.  Skipping this check would allow
            // an expired root to validate a still-valid end-entity certificate.
            let valid_candidates: Vec<&Certificate> = candidates
                .iter()
                .copied()
                .filter(|a| check_validity(a, now).is_ok())
                .collect();
            if valid_candidates.is_empty() {
                return Err(SmimeError::CertChain(
                    CertChainError::AllTrustAnchorsExpired,
                ));
            }
            // Try each valid anchor for signature verification — the CA renewal case
            // produces two simultaneously-valid certs with the same DN but different
            // keys, so the first valid anchor may not be the right one.
            for anchor in valid_candidates {
                if verify_signature(current, anchor).is_ok() {
                    // RFC 5280 §4.2.1.9: also enforce the trust anchor's own
                    // pathLen constraint.  A root CA with pathLen=0 may not
                    // have any intermediate CAs below it in the path.
                    if let Some(path_len) = get_path_len(anchor) {
                        if chain_depth > path_len as usize {
                            return Err(SmimeError::CertChain(
                                CertChainError::PathLenViolated {
                                    intermediate_count: chain_depth,
                                    path_len,
                                },
                            ));
                        }
                    }
                    return Ok(());
                }
            }
            return Err(SmimeError::CertChain(CertChainError::SignatureVerification));
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
                    return Err(SmimeError::CertChain(CertChainError::NotACa));
                }
                // RFC 5280 §4.2.1.9: check the pathLen constraint of the parent CA.
                // chain_depth is the count of CA certs already accumulated below p
                // in this chain.  If p's pathLen (if present) < chain_depth, this
                // violates the constraint.
                if let Some(path_len) = get_path_len(p) {
                    if chain_depth > path_len as usize {
                        return Err(SmimeError::CertChain(
                            CertChainError::PathLenViolated {
                                intermediate_count: chain_depth,
                                path_len,
                            },
                        ));
                    }
                }
                // Cycle detection: if this subject was already visited, the bag
                // contains a cycle (e.g. A signed by B, B signed by A).  The
                // chain is still rejected, but we surface the real cause rather
                // than exhausting MAX_CHAIN_DEPTH silently.
                let subj_der = p
                    .tbs_certificate()
                    .subject()
                    .to_der()
                    .map_err(|e| {
                        SmimeError::CertChain(CertChainError::Other(format!(
                            "subject DER encode: {e}"
                        )))
                    })?;
                if !visited.insert(subj_der) {
                    return Err(SmimeError::CertChain(CertChainError::Cycle));
                }
                current = p;
                chain_depth += 1;
            }
            None => {
                return Err(SmimeError::CertChain(CertChainError::NoMatchingIssuer));
            }
        }
    }

    Err(SmimeError::CertChain(CertChainError::TooDeep))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return `Ok(())` if `cert`'s validity period contains `now`.
fn check_validity(cert: &Certificate, now: SystemTime) -> Result<(), SmimeError> {
    let not_before = SystemTime::from(&cert.tbs_certificate().validity().not_before);
    let not_after = SystemTime::from(&cert.tbs_certificate().validity().not_after);
    if now < not_before || now > not_after {
        return Err(SmimeError::CertChain(CertChainError::CertificateExpired));
    }
    Ok(())
}

/// Return `true` if `cert` may act as a CA.
///
/// Per RFC 5280 §4.2.1.9, a CA cert must have `BasicConstraints.cA = true`.
/// Per RFC 5280 §4.2.1.3, if `KeyUsage` is present it must include
/// `keyCertSign`; a cert that explicitly excludes `keyCertSign` must not be
/// used to verify certificate signatures even if `BasicConstraints.cA = true`.
fn is_ca_cert(cert: &Certificate) -> bool {
    let tbs = cert.tbs_certificate();

    // BasicConstraints.cA must be true.
    let has_ca_flag = tbs
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .map(|(_critical, bc)| bc.ca)
        .unwrap_or(false);
    if !has_ca_flag {
        return false;
    }

    // If KeyUsage is present, keyCertSign must be asserted (RFC 5280 §4.2.1.3).
    if let Some((_critical, ku)) = tbs.get_extension::<KeyUsage>().ok().flatten() {
        if !ku.0.contains(KeyUsages::KeyCertSign) {
            return false;
        }
    }

    true
}

/// Return the pathLen constraint from a certificate's BasicConstraints extension,
/// if present.
fn get_path_len(cert: &Certificate) -> Option<u8> {
    cert.tbs_certificate()
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .and_then(|(_, bc)| bc.path_len_constraint)
}

/// Return `true` if the DER encodings of two `Name` values are identical.
///
/// RFC 5280 §7.1 technically permits case-insensitive, whitespace-folding
/// comparison of distinguished names.  We use byte-exact DER comparison
/// instead: it is simpler, avoids string normalisation edge cases, and is
/// correct for any certificate chain produced by a conformant CA — a
/// conformant CA encodes the same DN identically in issuer and subject fields.
/// Chains where the names are logically equivalent but differ in case or
/// whitespace will be rejected; such chains are themselves non-conformant.
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
        .map_err(|e| {
            SmimeError::CertChain(CertChainError::Other(format!("TBS DER encode: {e}")))
        })?;
    let sig_bytes = cert.signature().raw_bytes();
    let oid = &cert.signature_algorithm().oid;

    let e = |msg: String| SmimeError::CertChain(CertChainError::Other(msg));
    if *oid == SHA_256_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha256, _>(issuer, &tbs_der, sig_bytes, e)
    } else if *oid == SHA_384_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha384, _>(issuer, &tbs_der, sig_bytes, e)
    } else if *oid == SHA_512_WITH_RSA_ENCRYPTION {
        sig_verify::verify_rsa_pkcs1::<Sha512, _>(issuer, &tbs_der, sig_bytes, e)
    } else if *oid == ECDSA_WITH_SHA_256 {
        sig_verify::verify_ecdsa_p256(issuer, &tbs_der, sig_bytes, e)
    } else if *oid == ECDSA_WITH_SHA_384 {
        sig_verify::verify_ecdsa_p384(issuer, &tbs_der, sig_bytes, e)
    } else {
        Err(SmimeError::UnsupportedAlgorithm(oid.to_string()))
    }
}
