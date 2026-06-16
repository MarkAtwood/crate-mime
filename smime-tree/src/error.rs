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
///
/// # Security
///
/// [`is_verified`][Self::is_verified] returns `true` if **any one** signer passed
/// verification.  For messages with multiple signers, inspect [`signers`][Self::signers]
/// individually to confirm all expected signers are present and valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VerificationResult {
    /// One entry per `SignerInfo` found in the `SignedData`.
    pub signers: Vec<SignerResult>,
}

impl VerificationResult {
    /// Returns `true` if at least one signer verified successfully.
    ///
    /// # Security
    ///
    /// This method returns `true` if **any one** signer's certificate and signature verified
    /// successfully. In a message with multiple signers, some may have failed verification
    /// while this method still returns `true`. For security-critical decisions — especially
    /// when a policy requires all signers to be valid — use [`all_verified`][Self::all_verified]
    /// instead, or iterate [`signers`][Self::signers] directly.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.signers.iter().any(|s| s.verified)
    }

    /// Returns `true` only if **every** signer verified successfully.
    ///
    /// Prefer this over [`is_verified`][Self::is_verified] whenever your policy requires
    /// that all signers on a message are valid — for example, dual-control workflows or
    /// messages that must carry a specific set of signers.
    ///
    /// Returns `false` if `signers` is empty (no signers at all is not a success).
    #[must_use]
    pub fn all_verified(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(|s| s.verified)
    }

    /// Returns an iterator over only the [`SignerResult`] entries that verified successfully.
    ///
    /// Useful when you need to inspect or count the verified signers without examining
    /// failed ones. Combine with [`all_verified`][Self::all_verified] to enforce a
    /// minimum verified-signer count.
    pub fn verified_signers(&self) -> impl Iterator<Item = &SignerResult> {
        self.signers.iter().filter(|s| s.verified)
    }
}

/// Result for a single `SignerInfo` within a `SignedData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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

/// Structured failure reason for certificate chain validation.
///
/// Returned inside [`SmimeError::CertChain`].  Callers can match on this enum
/// to distinguish specific failure modes (e.g. expired certificate vs. missing
/// trust anchor) without parsing error strings.
///
/// # Compatibility stubs
///
/// Two variants — `AllTrustAnchorsExpired` and `PathLenViolated` — are marked
/// `#[deprecated]` and are **never emitted** by the current validator.  They
/// exist solely so that serialized data produced by older versions of this crate
/// can be deserialized without error.  New code should not match on them; see
/// each variant's deprecation message for the current equivalent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CertChainError {
    /// No trust anchors were provided.
    NoTrustAnchors,
    /// Certificate validity period does not contain the check time.
    CertificateExpired {
        /// Subject DN of the certificate that failed the validity check.
        subject: String,
        /// The certificate's `notAfter` date (ISO 8601).
        not_after: String,
    },
    /// All trust anchors matching the issuer DN are outside their validity period.
    ///
    /// Present only for deserialization compatibility with data produced by older versions
    /// of this crate; never emitted by the current validator.  Match [`CertChainError::TooDeep`]
    /// or [`CertChainError::CertificateExpired`] for the equivalent current failure modes.
    #[deprecated(since = "0.2.0", note = "match CertificateExpired instead")]
    AllTrustAnchorsExpired {
        /// Issuer DN for which all matching trust anchors were expired.
        issuer: String,
    },
    /// Certificate signature does not match the issuer's public key.
    SignatureVerification {
        /// Subject DN of the certificate whose signature could not be verified.
        subject: String,
    },
    /// A `pathLen` constraint in a CA certificate was violated.
    ///
    /// Present only for deserialization compatibility with data produced by older versions
    /// of this crate; never emitted by the current validator.  Match
    /// [`CertChainError::TooDeep`] for the equivalent current failure mode.
    #[deprecated = "never produced by the current pkix-chain-based validator; match TooDeep instead"]
    PathLenViolated {
        /// Number of intermediate CA certificates below the constrained issuer.
        intermediate_count: usize,
        /// The `pathLen` value from the `BasicConstraints` extension.
        path_len: u8,
    },
    /// An intermediate certificate lacks the CA flag (`BasicConstraints.cA = false`).
    NotACa {
        /// Subject DN of the certificate that was found not to be a CA.
        subject: String,
    },
    /// The certificate chain contains a cycle (A signed by B, B signed by A).
    Cycle {
        /// Subject DN of the certificate that closed the cycle.
        subject: String,
    },
    /// No trust anchor or intermediate certificate matches the issuer DN.
    NoMatchingIssuer {
        /// Issuer DN for which no matching certificate was found.
        issuer: String,
    },
    /// Certificate chain exceeds the maximum allowed depth.
    TooDeep,
    /// Other chain validation error (DER encoding failures, etc.).
    Other(String),
}

#[allow(deprecated)]
impl fmt::Display for CertChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertChainError::NoTrustAnchors => write!(f, "no trust anchors provided"),
            CertChainError::CertificateExpired { subject, not_after } => write!(
                f,
                "certificate '{subject}' expired or not yet valid (not_after={not_after})"
            ),
            CertChainError::AllTrustAnchorsExpired { issuer } => write!(
                f,
                "all trust anchors matching issuer '{issuer}' are expired or not yet valid"
            ),
            CertChainError::SignatureVerification { subject } => {
                write!(f, "issuer signature on '{subject}' does not match")
            }
            CertChainError::PathLenViolated {
                intermediate_count,
                path_len,
            } => write!(
                f,
                "pathLen constraint violated: {intermediate_count} intermediate CA(s) \
                 but pathLen is {path_len}"
            ),
            CertChainError::NotACa { subject } => {
                write!(f, "certificate '{subject}' is not a CA")
            }
            CertChainError::Cycle { subject } => {
                write!(f, "certificate chain cycle at '{subject}'")
            }
            CertChainError::NoMatchingIssuer { issuer } => write!(
                f,
                "no trust anchor or intermediate matches issuer '{issuer}' \
                 (add the CA root cert to trust_anchors)"
            ),
            CertChainError::TooDeep => {
                write!(f, "certificate chain exceeds the maximum allowed depth")
            }
            CertChainError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Error type for S/MIME operations.
///
/// # Serde round-trip
///
/// `SmimeError` implements `Serialize` and `Deserialize`. The `Der` variant
/// contains a `der::Error` which has no serde support, so it round-trips
/// through a string representation: serialized as `{"Der":"<message>"}`,
/// deserialized back as `SmimeError::Der` with a `der::Error` carrying
/// the message (the original error kind is not preserved across
/// serialization boundaries).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    CertChain(CertChainError),
    /// Input is structurally malformed (e.g. missing required CMS fields).
    MalformedInput(String),
    /// `encrypt()` was called with an empty recipients slice.
    NoRecipients,
    /// OS random number generator failed during a crypto operation.
    /// This indicates a catastrophic system-level failure.
    RngFailure(String),
    /// Decryption failed (e.g. bad padding, wrong CEK, or corrupted ciphertext).
    DecryptionFailed(String),
    /// Catch-all for operation errors not covered by a more specific variant.
    Other(String),
    /// All signers in the CMS SignedData failed verification.
    /// The `signers` vec contains per-signer error details.
    AllSignersFailed(Vec<SignerResult>),
    /// The `ContentInfo` content type is not what this operation expects.
    /// For example, passing a `SignedData` blob to `decrypt()`.
    WrongContentType(String),
    /// The content contains a MIME boundary that matches the generated separator even after
    /// 8 random retries. This is extraordinarily unlikely in practice.
    BoundaryCollision,
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
            SmimeError::CertChain(e) => write!(f, "certificate chain error: {e}"),
            SmimeError::MalformedInput(msg) => write!(f, "malformed CMS input: {msg}"),
            SmimeError::NoRecipients => write!(f, "encrypt() called with no recipients"),
            SmimeError::RngFailure(msg) => write!(f, "RNG failure: {msg}"),
            SmimeError::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            SmimeError::Other(msg) => write!(f, "{msg}"),
            SmimeError::WrongContentType(msg) => write!(f, "wrong content type: {msg}"),
            SmimeError::BoundaryCollision => write!(
                f,
                "could not generate a unique MIME boundary after 8 retries"
            ),
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

// ---------------------------------------------------------------------------
// Serde: manual impl because der::Error has no serde support
// ---------------------------------------------------------------------------

/// Mirror of `SmimeError` with `String` replacing `der::Error` for serde.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
enum SmimeErrorRepr {
    Der(String),
    UnsupportedAlgorithm(String),
    NoMatchingRecipient,
    SignatureVerification,
    CertChain(CertChainError),
    MalformedInput(String),
    NoRecipients,
    RngFailure(String),
    DecryptionFailed(String),
    Other(String),
    AllSignersFailed(Vec<SignerResult>),
    WrongContentType(String),
    BoundaryCollision,
}

impl From<&SmimeError> for SmimeErrorRepr {
    fn from(e: &SmimeError) -> Self {
        match e {
            SmimeError::Der(de) => SmimeErrorRepr::Der(de.to_string()),
            SmimeError::UnsupportedAlgorithm(s) => SmimeErrorRepr::UnsupportedAlgorithm(s.clone()),
            SmimeError::NoMatchingRecipient => SmimeErrorRepr::NoMatchingRecipient,
            SmimeError::SignatureVerification => SmimeErrorRepr::SignatureVerification,
            SmimeError::CertChain(c) => SmimeErrorRepr::CertChain(c.clone()),
            SmimeError::MalformedInput(s) => SmimeErrorRepr::MalformedInput(s.clone()),
            SmimeError::NoRecipients => SmimeErrorRepr::NoRecipients,
            SmimeError::RngFailure(s) => SmimeErrorRepr::RngFailure(s.clone()),
            SmimeError::DecryptionFailed(s) => SmimeErrorRepr::DecryptionFailed(s.clone()),
            SmimeError::Other(s) => SmimeErrorRepr::Other(s.clone()),
            SmimeError::AllSignersFailed(v) => SmimeErrorRepr::AllSignersFailed(v.clone()),
            SmimeError::WrongContentType(s) => SmimeErrorRepr::WrongContentType(s.clone()),
            SmimeError::BoundaryCollision => SmimeErrorRepr::BoundaryCollision,
        }
    }
}

impl From<SmimeErrorRepr> for SmimeError {
    fn from(r: SmimeErrorRepr) -> Self {
        match r {
            // der::Error cannot be reconstructed from a string; use a generic
            // truncation error as the carrier and preserve the message in Other
            // if it doesn't match. In practice, deserialized Der variants are
            // used for logging/display, not for programmatic matching on the
            // inner der::Error kind.
            SmimeErrorRepr::Der(s) => SmimeError::Other(format!("DER error: {s}")),
            SmimeErrorRepr::UnsupportedAlgorithm(s) => SmimeError::UnsupportedAlgorithm(s),
            SmimeErrorRepr::NoMatchingRecipient => SmimeError::NoMatchingRecipient,
            SmimeErrorRepr::SignatureVerification => SmimeError::SignatureVerification,
            SmimeErrorRepr::CertChain(c) => SmimeError::CertChain(c),
            SmimeErrorRepr::MalformedInput(s) => SmimeError::MalformedInput(s),
            SmimeErrorRepr::NoRecipients => SmimeError::NoRecipients,
            SmimeErrorRepr::RngFailure(s) => SmimeError::RngFailure(s),
            SmimeErrorRepr::DecryptionFailed(s) => SmimeError::DecryptionFailed(s),
            SmimeErrorRepr::Other(s) => SmimeError::Other(s),
            SmimeErrorRepr::AllSignersFailed(v) => SmimeError::AllSignersFailed(v),
            SmimeErrorRepr::WrongContentType(s) => SmimeError::WrongContentType(s),
            SmimeErrorRepr::BoundaryCollision => SmimeError::BoundaryCollision,
        }
    }
}

impl Serialize for SmimeError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SmimeErrorRepr::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SmimeError {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SmimeErrorRepr::deserialize(deserializer).map(SmimeError::from)
    }
}
