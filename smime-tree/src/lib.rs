//! S/MIME sign/verify/encrypt/decrypt via key traits.

mod cert;
mod decrypt;
mod encrypt;
mod error;
mod key;
mod sign;
mod verify;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use error::SmimeError;
pub use key::{
    DecryptionKey, DigestAlgorithm, EcCurve, KeyEncryptionAlgorithm, RecipientIdentifier,
    SigningKey,
};
pub use sign::sign;
pub use verify::{verify, SignerResult, VerificationResult};
