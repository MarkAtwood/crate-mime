use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SmimeError;

/// Identifies the recipient of an encrypted message.
/// Used by [`DecryptionKey::matches_recipient`] to find the right key.
///
/// The CMS standard defines two ways to identify a recipient certificate.
/// Your `matches_recipient` implementation should handle both variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RecipientIdentifier {
    /// Identified by certificate issuer name and serial number (PKCS #7 compatibility).
    IssuerAndSerialNumber {
        /// DER-encoded `Name` (X.501 RDN sequence).
        /// Obtain from `cert.tbs_certificate().issuer().to_der()?`.
        issuer_der: Vec<u8>,
        /// Big-endian serial number bytes.
        /// Obtain from `cert.tbs_certificate().serial_number().as_bytes()`.
        serial: Vec<u8>,
    },
    /// Identified by the raw bytes of the Subject Key Identifier extension value
    /// (RFC 5652 §6.2.2).
    /// Obtain from the cert's Subject Key Identifier extension:
    /// `cert.tbs_certificate().get_extension::<SubjectKeyIdentifier>()`.
    SubjectKeyIdentifier(Vec<u8>),
}

impl fmt::Display for RecipientIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial } => {
                write!(
                    f,
                    "IssuerAndSerial(issuer={} bytes, serial=",
                    issuer_der.len()
                )?;
                for (i, b) in serial.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
            RecipientIdentifier::SubjectKeyIdentifier(ski) => {
                write!(f, "SubjectKeyIdentifier(")?;
                for (i, b) in ski.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
        }
    }
}

/// Elliptic curve selection for ECDH key agreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EcCurve {
    P256,
    P384,
}

/// Algorithm used to encrypt (wrap) the content-encryption key.
///
/// # ECDH / KARI
///
/// ECDH key agreement (`KeyAgreeRecipientInfo`, RFC 5753) uses a *separate*
/// trait method: [`DecryptionKey::agree_ecdh`].  The `EcdhEs` variant here is
/// **not** produced by the current `decrypt()` implementation; it is reserved
/// for future direct-ECDH key transport scenarios (if any).  Implementors of
/// `DecryptionKey::decrypt_cek` do not need to handle `EcdhEs` today — ECDH
/// decryption is dispatched via `agree_ecdh()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyEncryptionAlgorithm {
    /// RSA PKCS#1 v1.5 key transport (RFC 8017).
    RsaPkcs1v15,
    /// RSA-OAEP key transport (RFC 8017).
    RsaOaep,
    /// ECDH-ES key agreement (RFC 5753) with the specified curve.
    /// Reserved; currently not produced by `decrypt()`. See type-level doc.
    EcdhEs { curve: EcCurve },
}

impl fmt::Display for KeyEncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyEncryptionAlgorithm::RsaPkcs1v15 => f.write_str("RSA-PKCS1v15"),
            KeyEncryptionAlgorithm::RsaOaep => f.write_str("RSA-OAEP"),
            KeyEncryptionAlgorithm::EcdhEs { curve } => match curve {
                EcCurve::P256 => f.write_str("ECDH-ES/P-256"),
                EcCurve::P384 => f.write_str("ECDH-ES/P-384"),
            },
        }
    }
}

/// AES key wrap algorithm used to protect the content-encryption key in KARI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyWrapAlgorithm {
    /// AES-128 key wrap (`id-aes128-Wrap`, RFC 3394).
    Aes128Kw,
    /// AES-256 key wrap (`id-aes256-Wrap`, RFC 3394).
    Aes256Kw,
}

/// ECDH key derivation scheme used in `KeyAgreeRecipientInfo` (RFC 5753 §7.1.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KariKeyAgreement {
    /// `dhSinglePass-stdDH-sha256kdf-scheme` — P-256 with X9.63 KDF using SHA-256.
    StdDhSha256Kdf,
    /// `dhSinglePass-stdDH-sha384kdf-scheme` — P-384 with X9.63 KDF using SHA-384.
    StdDhSha384Kdf,
}

/// Combined algorithm parameters for ECDH key agreement (`KeyAgreeRecipientInfo`).
///
/// Passed to [`DecryptionKey::agree_ecdh`] so the implementor knows which
/// ECDH variant and key wrap algorithm to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KariAlgorithm {
    /// ECDH key derivation scheme (determines curve and KDF hash).
    pub key_agreement: KariKeyAgreement,
    /// AES key wrap algorithm used to protect the CEK.
    pub key_wrap: KeyWrapAlgorithm,
}

/// Digest algorithm used when creating or verifying a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestAlgorithm::Sha256 => f.write_str("sha-256"),
            DigestAlgorithm::Sha384 => f.write_str("sha-384"),
            DigestAlgorithm::Sha512 => f.write_str("sha-512"),
        }
    }
}

/// Abstraction over a private key capable of decrypting an S/MIME message.
///
/// Implementors provide the key-unwrap step: given an encrypted CEK and the
/// algorithm that was used to wrap it, return the raw CEK bytes.
pub trait DecryptionKey {
    /// Decrypt an encrypted content-encryption key.
    fn decrypt_cek(
        &self,
        encrypted_key: &[u8],
        algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError>;

    /// Returns `true` if this key matches the given `RecipientIdentifier`.
    ///
    /// # Example
    ///
    /// `RecipientIdentifier` is `#[non_exhaustive]`, so your implementation
    /// **must** include a catch-all arm (`_ => false`) to remain forward-compatible
    /// with future identifier variants.
    ///
    /// ```ignore
    /// fn matches_recipient(&self, id: &RecipientIdentifier) -> bool {
    ///     match id {
    ///         RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial } => {
    ///             // issuer_der: DER-encoded Name — compare against
    ///             //   cert.tbs_certificate().issuer().to_der().unwrap_or_default()
    ///             // serial: big-endian bytes — compare against
    ///             //   cert.tbs_certificate().serial_number().as_bytes()
    ///             self.cert_issuer_der() == issuer_der
    ///                 && self.cert_serial() == serial
    ///         }
    ///         RecipientIdentifier::SubjectKeyIdentifier(ski) => {
    ///             // ski: raw bytes of the Subject Key Identifier extension value —
    ///             //   obtain via cert.tbs_certificate()
    ///             //       .get_extension::<SubjectKeyIdentifier>()
    ///             self.cert_ski() == ski
    ///         }
    ///         _ => false, // required: RecipientIdentifier is #[non_exhaustive]
    ///     }
    /// }
    /// ```
    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool;

    /// Perform ECDH key agreement and unwrap the content-encryption key.
    ///
    /// Called when the `EnvelopedData` contains a KARI (`KeyAgreeRecipientInfo`)
    /// entry that matches this key (as determined by `matches_recipient`).
    ///
    /// The implementor must:
    /// 1. Perform ECDH using the recipient's private key and
    ///    `ephemeral_public_key_bytes` (SEC1 uncompressed EC point) to obtain
    ///    the shared secret *Z*.
    /// 2. Apply the X9.63 KDF (RFC 5753 §3.6.1): hash *Z* concatenated with a
    ///    counter and the `SharedInfo` structure (which encodes `alg.key_wrap`
    ///    OID and `ukm`) to derive the key-encryption key (KEK).
    /// 3. Unwrap `enc_cek` with AES-128-KW or AES-256-KW (per `alg.key_wrap`)
    ///    using the derived KEK.
    /// 4. Return the raw CEK bytes.
    ///
    /// # Default
    ///
    /// Returns `Err(SmimeError::UnsupportedAlgorithm("KARI not supported by this key"))`.
    /// Override to enable ECDH decryption.
    fn agree_ecdh(
        &self,
        ephemeral_public_key_bytes: &[u8],
        ukm: Option<&[u8]>,
        enc_cek: &[u8],
        alg: &KariAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        let _ = (ephemeral_public_key_bytes, ukm, enc_cek, alg);
        Err(SmimeError::UnsupportedAlgorithm(
            "KARI (ECDH key agreement) not supported by this key".into(),
        ))
    }

    /// Returns a hint about which key encryption algorithms this key supports.
    ///
    /// This crate does **not** consult this hint internally — `decrypt()` always
    /// tries all recipients and lets `decrypt_cek()` / `agree_ecdh()` reject
    /// unsupported algorithms.  This method is provided as an extension point for
    /// callers that want to pre-screen or log algorithm capabilities.
    ///
    /// Default: returns `None` (no hint; let `decrypt_cek()` reject unsupported ones).
    fn supported_key_enc_algorithm(&self) -> Option<KeyEncryptionAlgorithm> {
        None
    }
}

/// Trait for checking certificate revocation status during signature verification.
///
/// This crate makes no network calls. Callers that need OCSP or CRL checking
/// implement this trait and inject it into [`crate::verify()`].
///
/// The no-op implementation [`NoRevocationCheck`] is provided for cases where
/// revocation checking is not needed (e.g. tests, trusted internal PKI,
/// air-gapped deployments).
pub trait RevocationChecker {
    /// Check whether `cert` has been revoked.
    ///
    /// Return `Ok(())` if the certificate is valid (not revoked or revocation
    /// status is acceptable).  Return `Err(SmimeError::CertChain(...))` if the
    /// certificate is revoked or its revocation status cannot be confirmed.
    fn check(&self, cert: &x509_cert::Certificate) -> Result<(), SmimeError>;
}

/// A no-op [`RevocationChecker`] that accepts all certificates without
/// consulting OCSP or CRL.
///
/// Use this when revocation checking is managed out-of-band, not required
/// for the deployment, or during testing with synthetic certificates.
pub struct NoRevocationCheck;

impl RevocationChecker for NoRevocationCheck {
    fn check(&self, _cert: &x509_cert::Certificate) -> Result<(), SmimeError> {
        Ok(())
    }
}

/// Abstraction over a private key capable of signing an S/MIME message.
///
/// Implementors supply the raw signature bytes and the signer's certificate,
/// which is embedded in the `SignedData` structure.
pub trait SigningKey {
    /// Sign `data` and return the raw signature bytes.
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError>;

    /// The signer's X.509 certificate, included in `SignedData`.
    fn certificate(&self) -> &x509_cert::Certificate;

    /// Returns the preferred digest algorithm for this key.
    ///
    /// [`crate::sign`] consults this method when selecting the digest algorithm:
    /// if `Some(alg)` is returned, that algorithm is used; otherwise the default
    /// is derived from the key's certificate (P-256 → SHA-256, P-384 → SHA-384,
    /// P-521 → SHA-512, RSA → SHA-256).
    ///
    /// Override to force a specific algorithm regardless of the certificate's key type.
    ///
    /// Default: returns `None` (let `sign()` derive the algorithm from the cert).
    fn preferred_digest_algorithm(&self) -> Option<DigestAlgorithm> {
        None
    }
}
