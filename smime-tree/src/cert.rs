//! Certificate chain validation for S/MIME verify.
//!
//! Delegates RFC 5280 path validation to [`pkix_chain::verify_chain`] with
//! [`SmimeChainVerifier`] as the signature backend, then applies the S/MIME
//! signer-certificate purpose checks of RFC 8550 §4.4 to the leaf.
//!
//! Because the `cms` crate requires x509-cert 0.3 and
//! `pkix-chain` requires x509-cert 0.2, all certificates are bridged
//! via DER round-trip in [`bridge_cert`] before being passed to pkix.

use const_oid::db::rfc5912::{ANY_EXTENDED_KEY_USAGE, ID_KP_EMAIL_PROTECTION};
use der::Encode;
use der_stable::Decode as _;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

use crate::error::{CertChainError, SmimeError};
use crate::key::RevocationChecker;
use crate::sig_verify::{self, EcdsaHash};

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
/// Returns `SmimeError::CertChain` if the chain cannot be built or validated,
/// or `CertChainError::UnsuitableSignerCertificate` if the chain is valid but
/// the leaf is not usable for S/MIME signing (see [`check_signer_purpose`]).
///
/// # Algorithm support
///
/// Certificate signatures are verified by [`SmimeChainVerifier`]:
///
/// - ECDSA (`ecdsa-with-SHA256`, `ecdsa-with-SHA384`, `ecdsa-with-SHA512`) with
///   an issuer key on P-256 or P-384, in any hash/curve combination — the
///   curve is taken from the issuer key, the hash from the signature OID.
/// - RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512, delegated to
///   `pkix-chain`'s `DefaultVerifier`.
///
/// Chains containing certificates signed with any other algorithm (RSA-PSS,
/// Ed25519, ECDSA with a P-521 issuer key, ...) fail with
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
    // NoRevocation: revocation is applied in step 5 on the signature-verified chain.
    // max_path_len is set explicitly to match build_chain::MAX_DEPTH so both limits
    // stay in sync if either changes.
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            SmimeError::CertChain(CertChainError::Other(
                "system clock is before the UNIX epoch".into(),
            ))
        })?
        .as_secs();
    let mut policy = pkix_chain::ValidationPolicy::new(now_unix);
    policy.max_path_len = MAX_DEPTH as u8;
    pkix_chain::verify_chain(
        &chain_stable,
        &anchors_stable,
        &policy,
        &SmimeChainVerifier,
        &pkix_chain::NoRevocation,
        &pkix_chain::NoAiaFetcher,
    )
    .map_err(|e| map_pkix_error(e, &chain))?;

    // Step 4: The chain is valid; check that the leaf may sign S/MIME messages.
    check_signer_purpose(signer_cert)?;

    // Step 5: Run the caller's revocation checker over the signature-verified chain.
    for cert in &chain {
        revocation.check(cert)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Signer certificate purpose (RFC 8550 §4.4)
// ---------------------------------------------------------------------------

/// Check that `leaf` may be used to verify an S/MIME message signature.
///
/// - **keyUsage** (RFC 8550 §4.4.2): if present, at least one of
///   `digitalSignature` or `nonRepudiation` (`contentCommitment`) must be set.
/// - **extKeyUsage** (RFC 8550 §4.4.4): if present, it must contain
///   `id-kp-emailProtection` or `anyExtendedKeyUsage`.  An absent extension
///   places no restriction.
///
/// A leaf with `basicConstraints cA=TRUE` is *not* rejected on that basis
/// alone.  RFC 8550 §4.4.1 only says end-entity certificates SHOULD NOT carry
/// the extension and places no requirement on receivers, OpenSSL's S/MIME
/// signer purpose check accepts such certificates, and self-signed signer
/// certificates made with `openssl req -x509` carry `cA=TRUE` by default.  A
/// typical CA certificate is still rejected by the keyUsage rule, because its
/// keyUsage is limited to `keyCertSign`/`cRLSign`.
///
/// An extension that is present but cannot be decoded (or appears more than
/// once) is treated as failing the check.
fn check_signer_purpose(leaf: &Certificate) -> Result<(), SmimeError> {
    use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};

    let tbs = leaf.tbs_certificate();
    let unsuitable = |reason: String| {
        SmimeError::CertChain(CertChainError::UnsuitableSignerCertificate {
            subject: tbs.subject().to_string(),
            reason,
        })
    };

    match tbs.get_extension::<KeyUsage>() {
        Ok(None) => {}
        Ok(Some((_critical, ku))) => {
            if !(ku.digital_signature() || ku.non_repudiation()) {
                return Err(unsuitable(
                    "keyUsage permits neither digitalSignature nor nonRepudiation".into(),
                ));
            }
        }
        Err(e) => return Err(unsuitable(format!("keyUsage extension is invalid: {e}"))),
    }

    match tbs.get_extension::<ExtendedKeyUsage>() {
        Ok(None) => {}
        Ok(Some((_critical, eku))) => {
            if !eku
                .0
                .iter()
                .any(|oid| *oid == ID_KP_EMAIL_PROTECTION || *oid == ANY_EXTENDED_KEY_USAGE)
            {
                return Err(unsuitable(
                    "extKeyUsage contains neither id-kp-emailProtection nor anyExtendedKeyUsage"
                        .into(),
                ));
            }
        }
        Err(e) => return Err(unsuitable(format!("extKeyUsage extension is invalid: {e}"))),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate signature verification backend
// ---------------------------------------------------------------------------

/// [`pkix_chain::SignatureVerifier`] that selects the ECDSA curve from the
/// issuer's key.
///
/// `pkix-chain`'s `DefaultVerifier` dispatches on the signature OID alone and
/// assumes `ecdsa-with-SHA256` means P-256 and `ecdsa-with-SHA384` means P-384,
/// so it rejects, for example, a certificate issued by a P-384 CA with
/// `ecdsa-with-SHA256` (the OpenSSL default digest).  This verifier handles
/// `ecdsa-with-SHA256/384/512` itself via [`sig_verify::verify_ecdsa_raw`],
/// reading the curve from the issuer SPKI's `namedCurve` and building the key
/// from the raw SEC1 point with `p256`/`p384`, and delegates every other
/// algorithm (RSA PKCS#1 v1.5) to `DefaultVerifier`.
struct SmimeChainVerifier;

impl pkix_chain::SignatureVerifier for SmimeChainVerifier {
    fn verify_signature(
        &self,
        algorithm: x509_cert_stable::spki::AlgorithmIdentifierRef<'_>,
        issuer_spki: x509_cert_stable::spki::SubjectPublicKeyInfoRef<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), signature_stable::Error> {
        let Some(hash) = EcdsaHash::from_sig_alg_oid_bytes(algorithm.oid.as_bytes()) else {
            return pkix_chain::DefaultVerifier.verify_signature(
                algorithm,
                issuer_spki,
                message,
                signature,
            );
        };
        let curve = issuer_spki.algorithm.parameters.and_then(|p| {
            p.decode_as::<x509_cert_stable::spki::ObjectIdentifier>()
                .ok()
        });
        sig_verify::verify_ecdsa_raw(
            issuer_spki.algorithm.oid.as_bytes(),
            curve.as_ref().map(|c| c.as_bytes()),
            issuer_spki.subject_public_key.raw_bytes(),
            hash,
            message,
            signature,
        )
        .map_err(|_| signature_stable::Error::new())
    }
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

/// DER-encode an x509-cert 0.3 `Certificate` and re-parse as x509-cert 0.2.
///
/// Both crate versions represent the same RFC 5280 ASN.1 structure; the
/// round-trip is lossless. This bridge is needed because `cms` (and the
/// rest of smime-tree) uses x509-cert 0.3 while
/// `pkix-chain` requires x509-cert 0.2.
fn bridge_cert(cert: &Certificate) -> Result<x509_cert_stable::Certificate, SmimeError> {
    let der = cert.to_der().map_err(|e| {
        SmimeError::CertChain(CertChainError::Other(format!("cert DER encode: {e}")))
    })?;
    x509_cert_stable::Certificate::from_der(&der)
        .map_err(|e| SmimeError::CertChain(CertChainError::Other(format!("cert DER bridge: {e}"))))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{build_chain, check_signer_purpose};
    use crate::error::{CertChainError, SmimeError};
    use der::Decode as _;
    use x509_cert::Certificate;

    /// TLS server certificate `/CN=Regress tls` (P-384 key; keyUsage=critical,
    /// keyEncipherment; extKeyUsage=serverAuth; basicConstraints=CA:FALSE),
    /// generated with OpenSSL 3.0:
    ///
    /// ```text
    /// openssl ecparam -name secp384r1 -genkey -noout -out tls.key
    /// openssl req -new -key tls.key -subj "/CN=Regress tls" -out tls.csr
    /// printf 'keyUsage=critical,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > tls.ext
    /// openssl x509 -req -in tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    ///   -sha384 -days 3650 -extfile tls.ext -outform DER -out tls.der
    /// ```
    ///
    /// `openssl cms -verify` rejects a message signed with it as "unsuitable
    /// certificate purpose" (see the regression section of
    /// `tests/smime_tests.rs`).
    const TLS_SERVER_CERT_HEX: &str = concat!(
        "308201e130820167a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1770",
        "300a06082a8648ce3d040303301a3118301606035504030c0f52656772657373205033",
        "3834204341301e170d3236313132303036323030385a170d3336313131373036323030",
        "385a30163114301206035504030c0b5265677265737320746c733076301006072a8648",
        "ce3d020106052b81040022036200044725aa72706baa25f3f3e4d72b487909b89561ea",
        "c9d47a97de03cbef912d93bbb649e0817575eb71be24208736e32a7e294a9e5d130ac2",
        "a68e86e502c6e6cb59c84709cd72f0dcaf91e08007f11e95cf7d000d3e68f62e6a6a99",
        "efd133a3a609a3723070300e0603551d0f0101ff04040302052030130603551d25040c",
        "300a06082b0601050507030130090603551d1304023000301d0603551d0e041604149c",
        "50399d12862d0e068f423f31bdfb17d1738190301f0603551d23041830168014c1ea03",
        "e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d040303036800306502",
        "3100e8a20ab00a1710b3f0d3ff1f6c84922bb98c57251e66b2ab7bafb50d4bbef601eb",
        "82f4d864d78b2f7a5b026a8b495d27023044588e5c7aa1674a2243f429a30e71cd6186",
        "f8312111050e257fd7145f82f3d44b09c1c0119841b559a0cd8951292fbb",
    );

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
        assert!(s.len().is_multiple_of(2));
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

        let chain = build_chain(&cert, &[], std::slice::from_ref(&cert))
            .expect("build_chain must succeed when signer cert is its own trust anchor");

        assert_eq!(
            chain.len(),
            1,
            "chain must contain exactly the signer cert; got {} element(s)",
            chain.len()
        );
    }

    /// RFC 8550 §4.4.2 / §4.4.4: a TLS server certificate is rejected as an
    /// S/MIME signer with the dedicated error variant, citing keyUsage (the
    /// first rule it fails).
    #[test]
    fn signer_purpose_rejects_tls_server_cert() {
        let cert = Certificate::from_der(&from_hex(TLS_SERVER_CERT_HEX)).expect("parse TLS cert");
        match check_signer_purpose(&cert) {
            Err(SmimeError::CertChain(CertChainError::UnsuitableSignerCertificate {
                subject,
                reason,
            })) => {
                assert_eq!(subject, "CN=Regress tls");
                assert!(reason.contains("keyUsage"), "{reason}");
            }
            other => panic!("expected UnsuitableSignerCertificate, got {other:?}"),
        }
    }

    /// A certificate without keyUsage or extKeyUsage passes the purpose check
    /// even though it has basicConstraints cA=TRUE (see `check_signer_purpose`
    /// for why cA=TRUE alone is not rejected).
    #[test]
    fn signer_purpose_accepts_cert_without_usage_extensions() {
        let cert = Certificate::from_der(&from_hex(SELF_SIGNED_CERT_HEX)).expect("parse cert");
        assert_eq!(check_signer_purpose(&cert), Ok(()));
    }
}
