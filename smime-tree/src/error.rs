use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Public result types (live here so error.rs does not depend on verify.rs)
// ---------------------------------------------------------------------------

/// Overall result from verifying a `multipart/signed` S/MIME message.
///
/// `Ok(VerificationResult)` is returned only when at least one signer
/// verified successfully.  Per-signer detail (including failures for other
/// signers) is available in the `signers` vec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// One entry per `SignerInfo` found in the `SignedData`.
    pub signers: Vec<SignerResult>,
}

impl VerificationResult {
    /// Returns `true` if at least one signer verified successfully.
    pub fn is_verified(&self) -> bool {
        self.signers.iter().any(|s| s.verified)
    }
}

/// Result for a single `SignerInfo` within a `SignedData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerResult {
    /// `true` iff all of the following succeeded:
    /// message-digest check, signature verification, and cert-chain validation.
    pub verified: bool,
    /// Distinguished name of the signer's certificate subject, if found.
    pub subject: Option<String>,
    /// Human-readable error string when `verified == false`.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------

/// Error type for S/MIME operations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SmimeError {
    /// DER encoding/decoding failure.
    Der(der::Error),
    /// The algorithm identified by the given OID is not supported.
    UnsupportedAlgorithm(String),
    /// No decryption key matches any RecipientInfo in the EnvelopedData.
    NoMatchingRecipient,
    /// Signature verification failed.
    SignatureVerification,
    /// Certificate chain validation failed.
    CertChain(String),
    /// Input is structurally malformed (e.g. missing required CMS fields).
    MalformedInput(String),
    /// Catch-all for operation errors not covered by a more specific variant.
    Other(String),
    /// All signers in the CMS SignedData failed verification.
    /// The `signers` vec contains per-signer error details.
    AllSignersFailed(Vec<SignerResult>),
    /// The `ContentInfo` content type is not what this operation expects.
    /// For example, passing a `SignedData` blob to `decrypt()`.
    WrongContentType(String),
}

impl fmt::Display for SmimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmimeError::Der(e) => write!(f, "DER error: {e}"),
            SmimeError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {alg}")
            }
            SmimeError::NoMatchingRecipient => {
                write!(f, "no decryption key matches any recipient")
            }
            SmimeError::SignatureVerification => write!(f, "signature verification failed"),
            SmimeError::CertChain(msg) => write!(f, "certificate chain error: {msg}"),
            SmimeError::MalformedInput(msg) => write!(f, "malformed CMS input: {msg}"),
            SmimeError::Other(msg) => write!(f, "error: {msg}"),
            SmimeError::WrongContentType(msg) => write!(f, "wrong content type: {msg}"),
            SmimeError::AllSignersFailed(signers) => {
                let first_error = signers
                    .first()
                    .and_then(|s| s.error.as_deref())
                    .unwrap_or("unknown");
                write!(
                    f,
                    "signature verification failed: {} signer(s) all failed — first error: {}",
                    signers.len(),
                    first_error
                )
            }
        }
    }
}

impl std::error::Error for SmimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SmimeError::Der(e) => Some(e),
            _ => None,
        }
    }
}

impl From<der::Error> for SmimeError {
    fn from(e: der::Error) -> Self {
        SmimeError::Der(e)
    }
}
