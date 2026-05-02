use std::fmt;

/// Error type for S/MIME operations.
#[derive(Debug)]
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
    /// I/O or formatting error.
    Io(String),
    /// All signers in the CMS SignedData failed verification.
    /// The `signers` vec contains per-signer error details.
    AllSignersFailed(Vec<crate::verify::SignerResult>),
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
            SmimeError::Io(msg) => write!(f, "I/O error: {msg}"),
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
