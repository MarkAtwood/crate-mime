//! S/MIME sign, verify, encrypt, and decrypt via caller-provided key traits.
//!
//! This crate processes S/MIME messages (RFC 5751 / CMS RFC 5652):
//!
//! - **Sign** — produce `multipart/signed` output from MIME content and a [`SigningKey`].
//! - **Verify** — validate a `multipart/signed` message against caller-supplied trust anchors.
//! - **Encrypt** — wrap MIME content in `application/pkcs7-mime; smime-type=enveloped-data`.
//! - **Decrypt** — unwrap enveloped data using a [`DecryptionKey`]; returns raw inner bytes.
//!
//! # Design constraints
//!
//! - **No async.** All operations are synchronous.
//! - **No JMAP dependency.** This crate has no knowledge of JMAP types.
//! - **No network calls.** Certificate chain validation uses a trust store supplied by the
//!   caller; fetching or refreshing that store is the caller's responsibility.
//! - **Key operations are trait-based.** [`SigningKey`] and [`DecryptionKey`] abstract over
//!   key location — in-memory, HSM, hardware token, etc. — without the crate needing to
//!   know the difference.

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
pub use error::SmimeError;
pub use key::{
    DecryptionKey, DigestAlgorithm, EcCurve, KariAlgorithm, KariKeyAgreement,
    KeyEncryptionAlgorithm, KeyWrapAlgorithm, NoRevocationCheck, RecipientIdentifier,
    RevocationChecker, SigningKey,
};
pub use sign::sign;
pub use verify::{verify, SignerResult, VerificationResult};
