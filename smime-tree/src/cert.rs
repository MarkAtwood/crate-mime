//! Certificate chain validation for S/MIME verify.
//!
//! Delegates RFC 5280 path validation to [`pkix_chain::verify_chain_default`].
//!
//! Because the `cms` crate requires x509-cert 0.3.0-rc and
//! `pkix-chain` requires x509-cert 0.2, all certificates are bridged
//! via DER round-trip in [`bridge_cert`] before being passed to pkix.

use der::Encode;
use der_stable::Decode as _;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

use crate::error::{CertChainError, SmimeError};
use crate::key::RevocationChecker;

/// Validate the certificate chain from `signer_cert` up to a trust anchor.
///
/// # Arguments
///
/// * `signer_cert`   – end-entity certificate extracted from the CMS SignerInfo
/// * `bag`           – intermediate certificates from the CMS SignedData bag
/// * `trust_anchors` – caller-supplied trust anchors (must be non-empty)
/// * `now`           – current time for validity-period checks
/// * `revocation`    – revocation checker called per cert; pass `&NoRevocationCheck` to skip
///
/// # Errors
///
/// Returns `SmimeError::CertChain` if the chain cannot be built or validated.
///
/// # Algorithm support
///
/// Signature verification is performed by `pkix-chain`'s `DefaultVerifier`,
/// which supports RSA-PKCS1v15-SHA-256 and ECDSA-P-256-SHA-256. Chains whose
/// CA certificates use ECDSA-P-384 or other algorithms will fail with
/// `CertChainError::SignatureVerification`. P-384 support is planned for
/// pkix-path v0.2.
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

    // Step 1: Order intermediates from the bag into a leaf-first chain.
    let chain = build_chain(signer_cert, bag, trust_anchors)?;

    // Step 2: Bridge to x509-cert 0.2 (required by pkix-chain).
    let chain_stable: Vec<x509_cert_stable::Certificate> = chain
        .iter()
        .map(|c| bridge_cert(c))
        .collect::<Result<_, _>>()?;

    let anchors_stable: Vec<pkix_chain::TrustAnchor> = trust_anchors
        .iter()
        .map(|a| bridge_cert(a).map(pkix_chain::TrustAnchor::from_cert))
        .collect::<Result<_, _>>()?;

    // Step 3: Validate via pkix-chain (signatures, validity, chain linkage).
    // NoRevocation: revocation is applied in step 4 on the signature-verified chain.
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let policy = pkix_chain::ValidationPolicy {
        current_time_unix: now_unix,
        ..Default::default()
    };
    pkix_chain::verify_chain_default(&chain_stable, &anchors_stable, &policy, &pkix_chain::NoRevocation)
        .map_err(|e| map_pkix_error(e, &chain))?;

    // Step 4: Run the caller's revocation checker over the signature-verified chain.
    for cert in &chain {
        revocation.check(cert)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Chain assembly
// ---------------------------------------------------------------------------

/// Build an ordered leaf-first chain from `signer_cert` and the bag.
///
/// Walks issuer DN links through the bag until the current tail's issuer
/// matches a trust anchor subject. Does not verify signatures — that is
/// pkix-chain's job.
fn build_chain<'a>(
    signer_cert: &'a Certificate,
    bag: &'a [Certificate],
    trust_anchors: &[Certificate],
) -> Result<Vec<&'a Certificate>, SmimeError> {
    const MAX_DEPTH: usize = 10;

    let mut chain: Vec<&Certificate> = vec![signer_cert];
    let mut visited: HashSet<Vec<u8>> = HashSet::new();
    if let Ok(s) = signer_cert.tbs_certificate().subject().to_der() {
        visited.insert(s);
    }

    let mut current = signer_cert;
    for _ in 0..MAX_DEPTH {
        let issuer_der = current.tbs_certificate().issuer().to_der().map_err(|e| {
            SmimeError::CertChain(CertChainError::Other(format!("issuer DER encode: {e}")))
        })?;

        // Done if the current cert's issuer is one of the trust anchors.
        let anchored = trust_anchors.iter().any(|a| {
            a.tbs_certificate()
                .subject()
                .to_der()
                .map(|s| s == issuer_der)
                .unwrap_or(false)
        });
        if anchored {
            return Ok(chain);
        }

        // Find the issuer in the bag by subject DN.
        let parent = bag.iter().find(|c| {
            c.tbs_certificate()
                .subject()
                .to_der()
                .map(|s| s == issuer_der)
                .unwrap_or(false)
        });

        match parent {
            None => {
                return Err(SmimeError::CertChain(CertChainError::NoMatchingIssuer {
                    issuer: current.tbs_certificate().issuer().to_string(),
                }));
            }
            Some(p) => {
                let subj_der = p.tbs_certificate().subject().to_der().map_err(|e| {
                    SmimeError::CertChain(CertChainError::Other(format!("subject DER encode: {e}")))
                })?;
                if !visited.insert(subj_der) {
                    return Err(SmimeError::CertChain(CertChainError::Cycle {
                        subject: p.tbs_certificate().subject().to_string(),
                    }));
                }
                chain.push(p);
                current = p;
            }
        }
    }

    Err(SmimeError::CertChain(CertChainError::TooDeep))
}

// ---------------------------------------------------------------------------
// DER bridge
// ---------------------------------------------------------------------------

/// DER-encode an x509-cert 0.3-rc `Certificate` and re-parse as x509-cert 0.2.
///
/// Both crate versions represent the same RFC 5280 ASN.1 structure; the
/// round-trip is lossless. This bridge is needed because `cms` (and the
/// rest of smime-tree) is pinned to x509-cert 0.3.0-rc while
/// `pkix-chain` requires x509-cert 0.2.
fn bridge_cert(cert: &Certificate) -> Result<x509_cert_stable::Certificate, SmimeError> {
    let der = cert
        .to_der()
        .map_err(|e| SmimeError::CertChain(CertChainError::Other(format!("cert DER encode: {e}"))))?;
    x509_cert_stable::Certificate::from_der(&der)
        .map_err(|e| SmimeError::CertChain(CertChainError::Other(format!("cert DER bridge: {e}"))))
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a `pkix_chain::Error` to `SmimeError`, using the rc chain for
/// subject/not_after strings in structured error variants.
fn map_pkix_error(e: pkix_chain::Error, chain: &[&Certificate]) -> SmimeError {
    use pkix_chain::Error as CE;
    use pkix_chain::pkix_path::Error as PE;

    let subject_at = |i: usize| -> String {
        chain
            .get(i)
            .map(|c| c.tbs_certificate().subject().to_string())
            .unwrap_or_default()
    };

    let chain_err = match e {
        CE::Path(PE::NoTrustedPath) | CE::Path(PE::ChainBroken { .. }) => {
            let issuer = chain
                .last()
                .map(|c| c.tbs_certificate().issuer().to_string())
                .unwrap_or_default();
            CertChainError::NoMatchingIssuer { issuer }
        }
        CE::Path(PE::PathTooLong) => CertChainError::TooDeep,
        CE::Path(PE::SignatureInvalid { index }) => CertChainError::SignatureVerification {
            subject: subject_at(index),
        },
        CE::Path(PE::NotCA { index }) | CE::Path(PE::KeyUsageMissing { index }) => {
            CertChainError::NotACa { subject: subject_at(index) }
        }
        CE::Path(PE::ValidityPeriod { index }) => {
            if let Some(cert) = chain.get(index) {
                CertChainError::CertificateExpired {
                    subject: cert.tbs_certificate().subject().to_string(),
                    not_after: cert.tbs_certificate().validity().not_after.to_string(),
                }
            } else {
                CertChainError::Other(format!("{e}"))
            }
        }
        other => CertChainError::Other(format!("{other}")),
    };
    SmimeError::CertChain(chain_err)
}
