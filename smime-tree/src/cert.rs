//! Certificate chain validation for S/MIME verify.
//!
//! Delegates RFC 5280 path validation to [`pkix_chain::verify_chain_default`].
//!
//! Because the `cms` crate requires x509-cert 0.3.0-rc and
//! `pkix-chain` requires x509-cert 0.2, all certificates are bridged
//! via DER round-trip in [`bridge_cert`] before being passed to pkix.

use der::Encode;
use der_stable::Decode as _;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

use crate::error::{CertChainError, SmimeError};
use crate::key::RevocationChecker;

/// Maximum chain depth (leaf + intermediates, excluding the trust anchor).
/// Must match `ValidationPolicy::max_path_len` set in `validate_chain`.
const MAX_DEPTH: usize = 10;

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
/// `CertChainError::SignatureVerification`.
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
    // max_path_len is set explicitly to match build_chain::MAX_DEPTH so both limits
    // stay in sync if either changes.
    let now_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut policy = pkix_chain::ValidationPolicy::new(now_unix);
    policy.max_path_len = MAX_DEPTH as u8;
    pkix_chain::verify_chain_default(
        &chain_stable,
        &anchors_stable,
        &policy,
        &pkix_chain::NoRevocation,
    )
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
    let mut chain: Vec<&Certificate> = vec![signer_cert];
    let mut visited: HashSet<Vec<u8>> = HashSet::new();
    let signer_subject_der = signer_cert
        .tbs_certificate()
        .subject()
        .to_der()
        .map_err(|e| {
            SmimeError::CertChain(CertChainError::Other(format!(
                "signer cert subject DER encode: {e}"
            )))
        })?;
    visited.insert(signer_subject_der);

    // Pre-compute anchor subject DERs once to avoid O(depth * anchors) encodes.
    // A malformed anchor whose subject fails DER encoding is reported immediately
    // rather than silently dropped (which would produce a misleading NoMatchingIssuer).
    let anchor_subjects: HashSet<Vec<u8>> = trust_anchors
        .iter()
        .map(|a| {
            a.tbs_certificate().subject().to_der().map_err(|e| {
                SmimeError::CertChain(CertChainError::Other(format!(
                    "trust anchor subject DER encode failed: {e}"
                )))
            })
        })
        .collect::<Result<HashSet<Vec<u8>>, SmimeError>>()?;

    // Pre-compute a subject-DER → cert map for the bag so the inner find is O(1)
    // rather than O(N) with a DER encode per cert per iteration.
    //
    // Certs whose subject DER re-encoding fails are skipped: they cannot be looked
    // up by subject, so they cannot participate in the chain walk regardless. A
    // malformed extraneous cert must not prevent validation of the rest of the chain.
    // This is safe because chain building only looks up issuers by subject DN, and
    // any cert we cannot re-encode its subject for cannot appear as an issuer match.
    let bag_by_subject: HashMap<Vec<u8>, &Certificate> = bag
        .iter()
        .filter_map(|c| c.tbs_certificate().subject().to_der().ok().map(|s| (s, c)))
        .collect();

    let mut current = signer_cert;
    for _ in 0..MAX_DEPTH {
        let issuer_der = current.tbs_certificate().issuer().to_der().map_err(|e| {
            SmimeError::CertChain(CertChainError::Other(format!("issuer DER encode: {e}")))
        })?;

        // Done if the current cert's issuer is one of the trust anchors.
        if anchor_subjects.contains(&issuer_der) {
            return Ok(chain);
        }

        // Find the issuer in the bag by subject DN — O(1) via pre-computed map.
        let parent = bag_by_subject.get(&issuer_der).copied();

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
    let der = cert.to_der().map_err(|e| {
        SmimeError::CertChain(CertChainError::Other(format!("cert DER encode: {e}")))
    })?;
    x509_cert_stable::Certificate::from_der(&der)
        .map_err(|e| SmimeError::CertChain(CertChainError::Other(format!("cert DER bridge: {e}"))))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::build_chain;
    use der::Decode as _;
    use x509_cert::Certificate;

    /// Self-signed CA cert DER (hex). Issuer == subject, so it serves as its
    /// own trust anchor.  Identical fixture to CA_CERT_HEX in smime_tests.rs.
    const SELF_SIGNED_CERT_HEX: &str = concat!(
        "3082033d30820225a003020102021407333d5893a388c17b89f29c7e0a3477533bd9e4",
        "300d06092a864886f70d01010b0500302e3110300e06035504030c0754657374204341",
        "310d300b060355040a0c0454657374310b3009060355040613025553301e170d323630",
        "3530323035313331345a170d333630343239303531333134",
        "5a302e3110300e06035504030c0754657374204341310d300b060355040a0c04546573",
        "74310b300906035504061302555330820122300d06092a864886f70d01010105000382",
        "010f003082010a02820101008fc0778478543cbc2e5ded4fac3103f3bdc8dda2c737e8",
        "ada9f0ab136905e01fc697eef8c64634043c991a24d30cbf29e6415f2ed1ab34e9398",
        "a0a2a06e0a2ad1503b1277ba16436e48cef26997d2b8875bd31856142e80db9fb3e5c4",
        "01894a6a0bec9a7b93ff754922a94e9de230d31d9d9cf2cc1156f0d2b07d67fcff2cc",
        "f7acca5e27b158532195f1214662e48cf34c28f41122eeaa80e0afe0f12676a8e8cfd2",
        "44a6c3e8d21102f7a083e7f2956f0c71ff118ab305a862377f581f6115d47df986c53a",
        "5c2b4c5ff6562069c5a90e314e3f37e2b9253a7ba5fc3490ab462e8bde9bbfc58e599c",
        "63021fd72447797f79283cfa9744e349b3ca54cbe776fbe10203010001a35330513",
        "01d0603551d0e0416041429719bd1b0dc2486a27ef26a4c745f63637fd5f5301f0603",
        "551d2304183016801429719bd1b0dc2486a27ef26a4c745f63637fd5f5300f0603551d",
        "130101ff040530030101ff300d06092a864886f70d01010b050003820101004282efbb",
        "5e6d4a05cf48667814cb09ee1915721f68fce118885a42b244579c2ccaa9d81e643737",
        "ae74c3b663dbce71be5f10ccda8e52e46a913f1ecc408bdad66aee029c5be5e939b657",
        "c9f44a6cd735ee1809528f0441598b762c5e99876d85120090e63b82cba73d7327f42f",
        "c9494e125e21d7cd82e94af1e826475e4e02ae46aea987da2a79e21df66c190e6ea1e1",
        "de69db80185863f844462e22149057cbd5673692aa1dde38a221e111a90782bf28ba47",
        "0b4fa01a1c2d876c3a19855dad05ee3eac0a20316152813ca6fa4e286e39901cde034e",
        "e102fca848dc38a340327bd8f15ad721e1cfd7e0714060a8fc599d97c190e012410329",
        "c97119ff805f33"
    );

    fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    /// build_chain returns a 1-element chain when the signer cert is self-signed
    /// and that same cert is supplied as the sole trust anchor.
    ///
    /// For a self-signed cert, issuer DN == subject DN.  build_chain terminates
    /// immediately (depth = 0) once it sees the issuer in anchor_subjects.
    #[test]
    fn build_chain_self_anchored_leaf() {
        let der = from_hex(SELF_SIGNED_CERT_HEX);
        let cert = Certificate::from_der(&der).expect("parse self-signed cert");

        let chain = build_chain(&cert, &[], &[cert.clone()])
            .expect("build_chain must succeed when signer cert is its own trust anchor");

        assert_eq!(
            chain.len(),
            1,
            "chain must contain exactly the signer cert; got {} element(s)",
            chain.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a `pkix_chain::Error` to `SmimeError`, using the rc chain for
/// subject/not_after strings in structured error variants.
fn map_pkix_error(e: pkix_chain::Error, chain: &[&Certificate]) -> SmimeError {
    use pkix_chain::pkix_path::Error as PE;
    use pkix_chain::Error as CE;

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
            CertChainError::NotACa {
                subject: subject_at(index),
            }
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
