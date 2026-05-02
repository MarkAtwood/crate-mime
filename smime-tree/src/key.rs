use serde::{Deserialize, Serialize};

use crate::error::SmimeError;

/// Identifies the recipient of an encrypted message.
/// Used by [`DecryptionKey::matches_recipient`] to find the right key.
///
/// The CMS standard defines two ways to identify a recipient certificate.
/// Your `matches_recipient` implementation should handle both variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Elliptic curve selection for ECDH key agreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcCurve {
    P256,
    P384,
}

/// Algorithm used to encrypt (wrap) the content-encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyEncryptionAlgorithm {
    /// RSA PKCS#1 v1.5 key transport (RFC 8017).
    RsaPkcs1v15,
    /// RSA-OAEP key transport (RFC 8017).
    RsaOaep,
    /// ECDH-ES key agreement (RFC 5753) with the specified curve.
    EcdhEs { curve: EcCurve },
}

/// Digest algorithm used when creating or verifying a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
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
    ///     }
    /// }
    /// ```
    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool;

    /// Returns a hint about which key encryption algorithms this key supports.
    ///
    /// This crate does not currently consult this hint internally. It is provided
    /// as an extension point for callers that coordinate multiple operations
    /// (e.g., selecting an algorithm before calling `decrypt_cek()`). Override to
    /// communicate your key's capabilities to higher-level code.
    ///
    /// Default: returns `None` (accept any algorithm; let `decrypt_cek()` reject
    /// unsupported ones).
    fn supported_key_enc_algorithm(&self) -> Option<KeyEncryptionAlgorithm> {
        None
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

    /// Returns a hint about the preferred digest algorithm for this key.
    ///
    /// This crate does not currently consult this hint internally. It is provided
    /// as an extension point for callers that coordinate multiple operations
    /// (e.g., selecting a digest algorithm before calling `sign()`). Override to
    /// communicate your key's capabilities to higher-level code.
    ///
    /// Default: returns `None` (use caller's default, currently SHA-256).
    fn preferred_digest_algorithm(&self) -> Option<DigestAlgorithm> {
        None
    }
}
