//! S/MIME sign, verify, encrypt, and decrypt via caller-provided key traits.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use smime_tree::{sign, verify, encrypt, decrypt};
//! use smime_tree::{SigningKey, DecryptionKey, NoRevocationCheck};
//! use x509_cert::Certificate;
//! use std::time::SystemTime;
//!
//! // Sign a MIME body part.
//! // key implements SigningKey; returns multipart/signed bytes.
//! let signed = sign(content_mime, &[&key], SystemTime::now()).expect("sign failed");
//!
//! // Verify a multipart/signed message.
//! // signed_content: exact bytes of the signed part (from mime-tree byte ranges).
//! // signature_der: DER of the application/pkcs7-signature part (base64-decoded).
//! let result = verify(&signed_content, &signature_der, &trust_anchors,
//!                     SystemTime::now(), &NoRevocationCheck)
//!     .expect("verify failed");
//! assert!(result.is_verified());
//!
//! // Encrypt a MIME body part to one or more recipient certificates.
//! let encrypted = encrypt(inner_mime, &recipient_certs).expect("encrypt failed");
//!
//! // Decrypt an enveloped-data blob.
//! // key implements DecryptionKey; returns inner plaintext bytes.
//! let plaintext = decrypt(&enveloped_der, &key).expect("decrypt failed");
//! ```
//!
//! # Design
//!
//! - **Trait-based keys**: [`SigningKey`] and [`DecryptionKey`] abstract over key
//!   location — in-memory, HSM, or hardware token — without the crate needing to
//!   know the difference.
//! - **No network calls**: certificate chain validation uses a trust store supplied
//!   by the caller.  [`RevocationChecker`] is an injected trait; use
//!   [`NoRevocationCheck`] to skip OCSP/CRL.
//! - **No async**: all operations are synchronous.
//! - **Supported algorithms**:
//!   - Sign/verify: RSA PKCS#1 v1.5 (SHA-256/384/512); ECDSA P-256 (SHA-256 only), P-384 (SHA-384 only). P-521 is not supported.
//!   - Encrypt: AES-128-GCM (RSA/P-256 recipients), AES-256-GCM (P-384 recipients) via `AuthEnvelopedData` (RFC 5083).
//!   - Decrypt: AES-128/256-GCM (`AuthEnvelopedData`) and AES-128/256-CBC (`EnvelopedData`, legacy).
//!   - Key transport: RSA PKCS#1 v1.5 (`KeyTransRecipientInfo`).
//!   - Key agreement: ECDH P-256 + AES-128-KW, ECDH P-384 + AES-256-KW (`KeyAgreeRecipientInfo`).
//!
//! # Known Limitations
//!
//! * **AES-CBC decryption (legacy) is unauthenticated.** `decrypt()` accepts
//!   both `AuthEnvelopedData` (AES-GCM, authenticated) and `EnvelopedData`
//!   (AES-CBC, unauthenticated).  The CBC path is retained for interoperability
//!   with existing S/MIME deployments but exposes callers to padding oracle and
//!   EFAIL-class (CVE-2017-17688) risks. See the [`decrypt`] function-level docs
//!   for mitigation guidance.
//! * **RSA-PSS signatures are not supported** for certificate chain validation.
//!   Real-world S/MIME CAs overwhelmingly use RSA-PKCS1v15 or ECDSA; RSA-PSS CA
//!   signatures are rare in practice. File an issue if you need it.
//! * **RSA key transport uses PKCS#1 v1.5** (`ktri`), not RSAES-OAEP. PKCS#1 v1.5 is
//!   deprecated by RFC 8017 in favour of OAEP and is susceptible to Bleichenbacher
//!   padding oracle attacks in interactive decryption scenarios.

mod cert;
mod decrypt;
mod encrypt;
mod error;
mod key;
mod sig_verify;
mod sign;
mod verify;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use error::{CertChainError, SignerResult, SmimeError, VerificationResult};
pub use key::{
    DecryptionKey, DigestAlgorithm, EcCurve, KariAlgorithm, KariKeyAgreement,
    KeyEncryptionAlgorithm, KeyWrapAlgorithm, NoRevocationCheck, RecipientIdentifier,
    RevocationChecker, SigningKey,
};
pub use sign::sign;
pub use verify::verify;
