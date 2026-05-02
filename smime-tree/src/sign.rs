//! S/MIME sign: produce a `multipart/signed` message.

use crate::{DigestAlgorithm, SigningKey, SmimeError};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cms::{
    cert::CertificateChoices,
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignatureValue,
        SignedAttributes, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
    },
};
use der::{
    asn1::{ObjectIdentifier, OctetStringRef, SetOfVec},
    Any, AnyRef, Decode, Encode, Tag,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    attr::{Attribute, AttributeValue},
    certificate::Certificate,
};

use const_oid::db::rfc5911::{ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNING_TIME};
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, ID_SHA_256, ID_SHA_384, ID_SHA_512,
    RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION,
    SHA_512_WITH_RSA_ENCRYPTION,
};

/// Sign MIME content. Returns `multipart/signed` outer MIME bytes.
///
/// The `content_mime` bytes are placed verbatim as the first MIME part.
/// The CMS `SignedData` blob is base64-encoded into the second MIME part.
///
/// The digest algorithm is selected based on the signing key's certificate:
/// RSA and EC P-256 use SHA-256; EC P-384 uses SHA-384.
/// P-521 keys are not supported and will return `SmimeError::UnsupportedAlgorithm`.
/// The key may override this via [`SigningKey::preferred_digest_algorithm`].
///
/// # Output format
///
/// The returned bytes are a `multipart/signed` **body part**, not a complete
/// RFC 5322 message.  They begin with a `MIME-Version: 1.0` header and the
/// `multipart/signed` Content-Type but have no `From:`, `Date:`, or other
/// RFC 5322 message headers.  To send as email, wrap the output in a full
/// RFC 5322 message envelope.
pub fn sign(content_mime: &[u8], key: &dyn SigningKey) -> Result<Vec<u8>, SmimeError> {
    let cert = key.certificate();

    // Select the digest algorithm based on the key type so that the algorithm
    // OID in SignerInfo matches the key's security level:
    //   RSA → SHA-256 (standard for 2048/4096-bit RSA)
    //   EC P-256 → SHA-256  (RFC 5753 §7.1 recommendation)
    //   EC P-384 → SHA-384  (RFC 5753 §7.1 recommendation; P-384 requires SHA-384)
    //   EC P-521 → SHA-512  (RFC 5753 §7.1 recommendation)
    // The key may override via preferred_digest_algorithm().
    let digest_alg = key
        .preferred_digest_algorithm()
        .unwrap_or_else(|| select_digest_for_cert(cert));

    // --- Step 1: build EncapsulatedContentInfo ---
    // RFC 5751 §3.4 / RFC 5652 §5.2: for multipart/signed (detached signature),
    // econtent MUST be absent. The content type OID is still present.
    let eci = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };

    // --- Step 2: hash content_mime ---
    let msg_digest = hash_content(content_mime, &digest_alg);

    // --- Step 3: build signed attributes ---
    // RFC 5652 §11.1: content-type, §11.2: message-digest, §11.3: signing-time.
    // SignedAttributes is a SetOfVec which sorts into canonical DER order.
    let ct_attr = make_content_type_attribute(ID_DATA)?;
    let md_attr = make_message_digest_attribute(&msg_digest)?;
    let st_attr = make_signing_time_attribute()?;

    let mut attrs_vec: SetOfVec<Attribute> = SetOfVec::new();
    attrs_vec.insert(ct_attr)?;
    attrs_vec.insert(md_attr)?;
    attrs_vec.insert(st_attr)?;
    let signed_attrs: SignedAttributes = attrs_vec;

    // --- Step 4: DER-encode the SignedAttributes SET and call key.sign() ---
    let attrs_der = signed_attrs.to_der()?;
    let raw_sig = key.sign(&attrs_der, &digest_alg)?;

    // --- Step 5: determine signature algorithm OID from cert SPKI ---
    let sig_alg_oid = signature_algorithm_oid(cert, &digest_alg)?;
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: sig_alg_oid,
        parameters: None,
    };

    // --- Step 6: build SignerInfo ---
    let sid = SignerIdentifier::from(cert);
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: digest_alg_oid(&digest_alg),
        parameters: None,
    };
    // RFC 5652 §5.3: SignerInfo.version is V1 for IssuerAndSerialNumber, V3 for SKI.
    let signer_info_version = match &sid {
        SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
        SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
    };
    // RFC 5652 §5.1: SignedData.version is V3 if any SignerInfo uses SKI, else V1.
    // sign() produces exactly one SignerInfo, so the SignedData version equals it.
    // If multi-signer support is added later, iterate all signers: use V3 if any
    // uses SubjectKeyIdentifier, else V1.
    let signed_data_version = signer_info_version;
    let signature_value = SignatureValue::new(raw_sig)?;

    let signer_info = SignerInfo {
        version: signer_info_version,
        sid,
        digest_alg: digest_algorithm.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature: signature_value,
        unsigned_attrs: None,
    };

    // --- Step 7: build SignedData ---
    let mut digest_alg_set: DigestAlgorithmIdentifiers = SetOfVec::new();
    digest_alg_set.insert(digest_algorithm)?;

    let mut cert_choices: CertificateSet = CertificateSet(SetOfVec::new());
    cert_choices
        .0
        .insert(CertificateChoices::Certificate(cert.clone()))?;

    let mut signer_infos_set: SignerInfos = SignerInfos(SetOfVec::new());
    signer_infos_set.0.insert(signer_info)?;

    let signed_data = SignedData {
        version: signed_data_version,
        digest_algorithms: digest_alg_set,
        encap_content_info: eci,
        certificates: Some(cert_choices),
        crls: None,
        signer_infos: signer_infos_set,
    };

    // --- Step 8: wrap in ContentInfo and DER-encode ---
    let sd_der = signed_data.to_der()?;
    let content_ref = AnyRef::try_from(sd_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::from(content_ref),
    };
    let p7s_der = content_info.to_der()?;

    // --- Step 9: build multipart/signed MIME output ---
    let micalg = micalg_param(&digest_alg);
    let boundary = random_boundary(content_mime)?;
    let p7s_b64 = BASE64.encode(&p7s_der);
    let p7s_b64_wrapped = wrap_base64(&p7s_b64, 76);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(
        b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";\r\n",
    );
    out.extend_from_slice(b"\tmicalg=");
    out.extend_from_slice(micalg.as_bytes());
    out.extend_from_slice(b"; boundary=\"");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\"\r\n");
    out.extend_from_slice(b"\r\n");
    // First part: the signed MIME content verbatim
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(content_mime);
    out.extend_from_slice(b"\r\n");
    // Second part: the detached signature
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Content-Type: application/pkcs7-signature; name=smime.p7s\r\n");
    out.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
    out.extend_from_slice(b"Content-Disposition: attachment; filename=smime.p7s\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(p7s_b64_wrapped.as_bytes());
    out.extend_from_slice(b"\r\n");
    // Closing boundary
    out.extend_from_slice(b"--");
    out.extend_from_slice(boundary.as_bytes());
    out.extend_from_slice(b"--\r\n");

    Ok(out)
}

// ---------------------------------------------------------------------------
// Signed attribute constructors
// ---------------------------------------------------------------------------

/// Build a content-type attribute (RFC 5652 §11.1).
fn make_content_type_attribute(content_type: ObjectIdentifier) -> Result<Attribute, SmimeError> {
    let value = AttributeValue::new(Tag::ObjectIdentifier, content_type.as_bytes())?;
    let mut values: SetOfVec<AttributeValue> = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute {
        oid: ID_CONTENT_TYPE,
        values,
    })
}

/// Build a message-digest attribute (RFC 5652 §11.2).
fn make_message_digest_attribute(digest: &[u8]) -> Result<Attribute, SmimeError> {
    let os_ref = OctetStringRef::new(digest)?;
    let value = AttributeValue::new(Tag::OctetString, os_ref.as_bytes())?;
    let mut values: SetOfVec<AttributeValue> = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute {
        oid: ID_MESSAGE_DIGEST,
        values,
    })
}

/// Build a signing-time attribute (RFC 5652 §11.3) set to the current UTC time.
fn make_signing_time_attribute() -> Result<Attribute, SmimeError> {
    let time = x509_cert::time::Time::now()?;
    let time_der = time.to_der()?;
    let value = AttributeValue::from_der(&time_der)?;
    let mut values: SetOfVec<AttributeValue> = SetOfVec::new();
    values.insert(value)?;
    Ok(Attribute {
        oid: ID_SIGNING_TIME,
        values,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash `content` with the specified digest algorithm.
fn hash_content(content: &[u8], alg: &DigestAlgorithm) -> Vec<u8> {
    match alg {
        DigestAlgorithm::Sha256 => Sha256::digest(content).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(content).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(content).to_vec(),
    }
}

/// Return the digest algorithm OID for use in `AlgorithmIdentifier`.
fn digest_alg_oid(alg: &DigestAlgorithm) -> ObjectIdentifier {
    match alg {
        DigestAlgorithm::Sha256 => ID_SHA_256,
        DigestAlgorithm::Sha384 => ID_SHA_384,
        DigestAlgorithm::Sha512 => ID_SHA_512,
    }
}

/// Return the `micalg` Content-Type parameter string for the digest algorithm.
fn micalg_param(alg: &DigestAlgorithm) -> &'static str {
    match alg {
        DigestAlgorithm::Sha256 => "sha-256",
        DigestAlgorithm::Sha384 => "sha-384",
        DigestAlgorithm::Sha512 => "sha-512",
    }
}

/// Determine the signature algorithm OID from the certificate's SPKI algorithm
/// combined with the chosen digest algorithm.
fn signature_algorithm_oid(
    cert: &Certificate,
    digest_alg: &DigestAlgorithm,
) -> Result<ObjectIdentifier, SmimeError> {
    let spki_oid = cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid;

    if spki_oid == RSA_ENCRYPTION {
        return Ok(match digest_alg {
            DigestAlgorithm::Sha256 => SHA_256_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha384 => SHA_384_WITH_RSA_ENCRYPTION,
            DigestAlgorithm::Sha512 => SHA_512_WITH_RSA_ENCRYPTION,
        });
    }

    if spki_oid == ID_EC_PUBLIC_KEY {
        return match digest_alg {
            DigestAlgorithm::Sha256 => Ok(ECDSA_WITH_SHA_256),
            DigestAlgorithm::Sha384 => Ok(ECDSA_WITH_SHA_384),
            // P-521 (SHA-512) is not supported: neither sign() nor verify() has
            // a P-521 implementation.  P-521 keys must not be used with this crate.
            DigestAlgorithm::Sha512 => Err(SmimeError::UnsupportedAlgorithm(
                "P-521 keys are not supported; use P-256 or P-384".into(),
            )),
        };
    }

    Err(SmimeError::UnsupportedAlgorithm(format!(
        "SPKI OID {spki_oid} not supported for signing"
    )))
}

/// Select the appropriate digest algorithm for the certificate's key type.
///
/// RFC 5753 §7.1 recommends matching the hash strength to the EC curve:
/// P-256 → SHA-256, P-384 → SHA-384.
/// RSA keys default to SHA-256.  Unknown key types fall back to SHA-256.
/// P-521 keys select SHA-512, which causes `signature_algorithm_oid` to return
/// `UnsupportedAlgorithm` — P-521 is not supported by this crate.
fn select_digest_for_cert(cert: &Certificate) -> DigestAlgorithm {
    use const_oid::db::rfc5912::{SECP_384_R_1, SECP_521_R_1};
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok());
        if let Some(c) = curve {
            if c == SECP_384_R_1 {
                return DigestAlgorithm::Sha384;
            }
            if c == SECP_521_R_1 {
                return DigestAlgorithm::Sha512;
            }
        }
    }
    DigestAlgorithm::Sha256
}

/// Generate a random MIME boundary string that does not appear in `content`.
///
/// Uses 16 random bytes (hex-encoded) to produce a 32-character token, prefixed
/// with `"----=_Part_"`.  Retries up to 8 times on the astronomically unlikely
/// event of a collision with `content`.  Returns `Err` only if all 8 attempts
/// collide, which has probability less than 2^-448 for any fixed content.
///
/// The random boundary prevents adversarial content from causing a deterministic
/// signing failure (which was possible when the boundary was derived from the
/// SHA-256 of the content).
fn random_boundary(content: &[u8]) -> Result<String, SmimeError> {
    for _ in 0..8 {
        let mut rand_bytes = [0u8; 16];
        getrandom::fill(&mut rand_bytes).map_err(|e| SmimeError::RngFailure(format!("{e}")))?;
        let mut hex = String::with_capacity(32);
        for b in rand_bytes {
            use std::fmt::Write as _;
            write!(hex, "{b:02x}").expect("writing to String cannot fail");
        }
        let boundary = format!("----=_Part_{hex}");
        // RFC 2046 §5.1.1: boundary MUST NOT appear in any encapsulated body.
        if !content
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            return Ok(boundary);
        }
    }
    Err(SmimeError::MalformedInput(
        "MIME boundary collision: failed to generate a unique boundary after 8 attempts".into(),
    ))
}

/// Wrap a base64 string at `width` characters per line using CRLF line endings.
fn wrap_base64(b64: &str, width: usize) -> String {
    let mut out = String::with_capacity(b64.len() + (b64.len() / width + 1) * 2);
    for chunk in b64.as_bytes().chunks(width) {
        // b64 is a &str, so its byte slices are always valid UTF-8.
        out.push_str(
            core::str::from_utf8(chunk)
                .expect("base64 output is a str — from_utf8 always succeeds"),
        );
        out.push_str("\r\n");
    }
    out
}
