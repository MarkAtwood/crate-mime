//! S/MIME decryption: parse EnvelopedData / AuthEnvelopedData and recover plaintext.

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit as GcmKeyInit};
use cms::authenveloped_data::AuthEnvelopedData;
use cms::content_info::ContentInfo;
use cms::enveloped_data::{
    EnvelopedData, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey,
    RecipientInfo, RecipientInfos,
};
use const_oid::db::{
    rfc5753,
    rfc5911::{
        ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_256_CBC, ID_AES_256_GCM,
        ID_AES_256_WRAP, ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA,
    },
    rfc5912::{ID_EC_PUBLIC_KEY, ID_RSAES_OAEP, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1},
};
use der::{asn1::OctetString, Decode, Encode, Sequence};
use spki::AlgorithmIdentifierOwned;

use zeroize::Zeroizing;

use crate::error::SmimeError;
use crate::key::{
    DecryptionKey, KariAlgorithm, KariKeyAgreement, KeyEncryptionAlgorithm, KeyWrapAlgorithm,
    RecipientIdentifier,
};

/// Maximum size of encrypted content accepted by [`decrypt`], in bytes.
///
/// Ciphertext exceeding this limit is rejected before the plaintext buffer is
/// allocated and before any content decryption is attempted.  The check runs
/// only *after* the whole input has been DER-decoded, so by then the
/// ciphertext itself is already in memory: this limit does **not** protect
/// against memory exhaustion from a hostile input.  Callers must bound the
/// length of `enveloped_der` before calling [`decrypt`].  The 64 MiB value is
/// generous for email (RFC 5321 recommends a 10 MB message size limit;
/// encrypted content adds ~33% overhead for base64 but is DER-decoded here,
/// so the binary content is smaller than the wire form).
///
/// This is a compile-time constant.  If a caller needs to decrypt larger
/// payloads, they should file an issue for a configurable limit.
const MAX_ENCRYPTED_CONTENT_SIZE: usize = 64 * 1024 * 1024;

/// GCM algorithm parameters per RFC 5084 section 3.2.
///
/// ```text
/// GCMParameters ::= SEQUENCE {
///     aes-nonce        OCTET STRING, -- recommended size is 12 octets
///     aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
/// ```
///
/// Note: RFC 5084 defaults `aes-ICVlen` to 12, but standard practice and
/// all interoperable implementations use 16-byte (128-bit) tags.  We accept
/// any valid tag length during decode but reject non-16-byte tags at decrypt
/// time.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct GcmParameters {
    aes_nonce: OctetString,
    #[asn1(default = "default_icv_len")]
    aes_icv_len: u8,
}

fn default_icv_len() -> u8 {
    12
}

/// Decrypt an S/MIME `EnvelopedData` or `AuthEnvelopedData` blob.
///
/// `enveloped_der` must be a DER-encoded `ContentInfo` wrapping either an
/// `EnvelopedData` (RFC 5652 section 6, AES-CBC) or an `AuthEnvelopedData`
/// (RFC 5083, AES-GCM).  Returns the inner plaintext bytes.
///
/// Only DER is accepted.  BER encodings that are not also DER — notably the
/// indefinite-length form produced by streaming encoders such as
/// `openssl cms -encrypt -stream` or `openssl smime -stream` — fail with
/// `SmimeError::Der`; re-encode such input as DER first (for example with
/// `openssl cms -cmsout -inform DER -outform DER`).
///
/// The whole input is decoded into memory before any size check runs (the
/// 64 MiB encrypted-content limit only caps the plaintext allocation), so
/// bound the length of `enveloped_der` before calling this function if it
/// comes from an untrusted source.
///
/// # Errors
///
/// Once a recipient matches, every failure that depends on the recovered CEK
/// — a `decrypt_cek` failure, a CEK of the wrong length for the content
/// cipher, bad CBC padding, or a GCM authentication failure — is reported as
/// the same `SmimeError::DecryptionFailed` value, so callers cannot (and
/// attackers observing the error cannot) tell them apart.  The exceptions are
/// `UnsupportedAlgorithm` and `RngFailure` returned by `decrypt_cek`, which are
/// passed through unchanged.  Errors from [`DecryptionKey::agree_ecdh`] are
/// passed through unchanged.
///
/// Supported recipient types:
/// - **KTRI** (`KeyTransRecipientInfo`): RSA PKCS#1 v1.5 and RSA-OAEP.
/// - **KARI** (`KeyAgreeRecipientInfo`): ECDH P-256 and P-384 via [`DecryptionKey::agree_ecdh`].
///
/// KEKRI, PWRI, and ORI recipient types are not supported.
///
/// # Security — unauthenticated CBC decryption (legacy path)
///
/// The `EnvelopedData` path decrypts content encrypted with AES-CBC, which is
/// **not** an authenticated encryption mode.  Two risks follow:
///
/// 1. **Padding oracle**: if `SmimeError::DecryptionFailed` is surfaced to any
///    interactive channel (HTTP status, SMTP bounce, UI error), an attacker
///    can mount an adaptive chosen-ciphertext attack to recover the plaintext.
///    This function returns a deliberately generic error message to mitigate
///    the risk, but callers MUST NOT add distinguishing detail when reporting
///    decryption failures to untrusted parties.
///
/// 2. **EFAIL (CVE-2017-17688 class)**: an attacker who obtains the ciphertext
///    can modify CBC blocks to redirect decrypted content to an
///    attacker-controlled exfiltration channel (e.g. `<img src=...>` in HTML
///    MIME content) without knowing the CEK.  Callers that render decrypted
///    HTML SHOULD strip or sandbox external resource references.
///
/// The `AuthEnvelopedData` path uses AES-GCM, which provides authenticated
/// encryption and is not susceptible to these attacks.
///
/// AES-CBC decryption is retained for interoperability with existing S/MIME
/// deployments.
pub fn decrypt(enveloped_der: &[u8], key: &dyn DecryptionKey) -> Result<Vec<u8>, SmimeError> {
    // Step 1: Parse the outer ContentInfo.
    let ci = ContentInfo::from_der(enveloped_der)?;

    if ci.content_type == ID_CT_AUTH_ENVELOPED_DATA {
        return decrypt_auth_enveloped(&ci, key);
    }

    // Step 2: Verify this is an EnvelopedData.
    if ci.content_type != ID_ENVELOPED_DATA {
        return Err(SmimeError::WrongContentType(format!(
            "expected EnvelopedData or AuthEnvelopedData, got OID {}",
            ci.content_type
        )));
    }

    // Step 3: Parse the EnvelopedData from the ContentInfo payload.
    // ci.content is a DER Any; re-encode it to get the raw DER bytes.
    let content_der = ci.content.to_der()?;
    let env_data = EnvelopedData::from_der(content_der.as_slice())?;

    // Step 4: Find a matching recipient and decrypt the CEK.
    let cek = find_and_decrypt_cek(&env_data.recip_infos, key)?;

    // Step 5: Decrypt the content using the recovered CEK.
    let content_enc_oid = env_data.encrypted_content.content_enc_alg.oid;
    let ct = env_data
        .encrypted_content
        .encrypted_content
        .as_ref()
        .ok_or_else(|| SmimeError::MalformedInput("EnvelopedData has no encrypted content".into()))?
        .as_bytes();

    // Reject oversized ciphertext before allocating the plaintext buffer.
    // The ciphertext is already in memory (DER decode is complete), so this
    // bounds only the additional allocation; callers bound the input size.
    if ct.len() > MAX_ENCRYPTED_CONTENT_SIZE {
        return Err(SmimeError::MalformedInput(format!(
            "encrypted content too large: {} bytes exceeds {} byte limit",
            ct.len(),
            MAX_ENCRYPTED_CONTENT_SIZE
        )));
    }

    if content_enc_oid == ID_AES_128_CBC {
        let iv = extract_cbc_iv(&env_data)?;
        decrypt_aes128_cbc(&cek, &iv, ct)
    } else if content_enc_oid == ID_AES_256_CBC {
        let iv = extract_cbc_iv(&env_data)?;
        decrypt_aes256_cbc(&cek, &iv, ct)
    } else if content_enc_oid == ID_AES_128_GCM || content_enc_oid == ID_AES_256_GCM {
        // AES-GCM in CMS uses AuthEnvelopedData (RFC 5083), not EnvelopedData.
        // OpenSSL does not produce GCM-encrypted EnvelopedData in the standard
        // S/MIME workflow.  Return an unsupported error rather than misparse.
        Err(SmimeError::UnsupportedAlgorithm(
            "AES-GCM in EnvelopedData is not supported; use AuthEnvelopedData".into(),
        ))
    } else {
        Err(SmimeError::UnsupportedAlgorithm(format!(
            "content encryption OID {}",
            content_enc_oid
        )))
    }
}

/// Decrypt an `AuthEnvelopedData` (RFC 5083) blob with AES-GCM.
///
/// The auth tag is in the `mac` field, the ciphertext (without tag) in
/// `auth_encrypted_content_info.encrypted_content`, and the nonce in
/// the `GCMParameters` from the algorithm parameters.
fn decrypt_auth_enveloped(
    ci: &ContentInfo,
    key: &dyn DecryptionKey,
) -> Result<Vec<u8>, SmimeError> {
    let content_der = ci.content.to_der()?;
    let auth_data = AuthEnvelopedData::from_der(content_der.as_slice())?;

    // Find a matching recipient and decrypt the CEK.
    let cek = find_and_decrypt_cek(&auth_data.recip_infos, key)?;

    // Extract GCM parameters (nonce + tag length).
    let content_enc_oid = auth_data.auth_encrypted_content_info.content_enc_alg.oid;
    let params = auth_data
        .auth_encrypted_content_info
        .content_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(|| SmimeError::MalformedInput("GCM algorithm parameters missing".into()))?;
    let gcm_params = params.decode_as::<GcmParameters>()?;

    let nonce = gcm_params.aes_nonce.as_bytes();
    if nonce.len() != 12 {
        return Err(SmimeError::MalformedInput(format!(
            "GCM nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }

    let icv_len = gcm_params.aes_icv_len;
    if icv_len != 16 {
        return Err(SmimeError::UnsupportedAlgorithm(format!(
            "GCM tag length must be 16 bytes, got {icv_len}"
        )));
    }

    // Extract ciphertext (without tag).
    let ct = auth_data
        .auth_encrypted_content_info
        .encrypted_content
        .as_ref()
        .ok_or_else(|| {
            SmimeError::MalformedInput("AuthEnvelopedData has no encrypted content".into())
        })?
        .as_bytes();

    if ct.len() > MAX_ENCRYPTED_CONTENT_SIZE {
        return Err(SmimeError::MalformedInput(format!(
            "encrypted content too large: {} bytes exceeds {} byte limit",
            ct.len(),
            MAX_ENCRYPTED_CONTENT_SIZE
        )));
    }

    // Extract the authentication tag from the `mac` field.
    let tag = auth_data.mac.as_bytes();
    if tag.len() != 16 {
        return Err(SmimeError::MalformedInput(format!(
            "GCM auth tag must be 16 bytes, got {}",
            tag.len()
        )));
    }

    // Reconstruct the AES-GCM input: ciphertext || tag (AEAD convention).
    let mut ct_with_tag = Vec::with_capacity(ct.len() + 16);
    ct_with_tag.extend_from_slice(ct);
    ct_with_tag.extend_from_slice(tag);

    let nonce_arr = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(nonce)
        .map_err(|_| SmimeError::MalformedInput("GCM nonce length mismatch".into()))?;

    // A CEK of the wrong length is reported exactly like a wrong CEK of the
    // right length (see `content_decryption_failed`).
    if content_enc_oid == ID_AES_128_GCM {
        let key_arr: &[u8; 16] = cek
            .as_slice()
            .try_into()
            .map_err(|_| content_decryption_failed())?;
        let cipher = aes_gcm::Aes128Gcm::new(key_arr.into());
        cipher
            .decrypt(&nonce_arr, ct_with_tag.as_ref())
            .map_err(|_| content_decryption_failed())
    } else if content_enc_oid == ID_AES_256_GCM {
        let key_arr: &[u8; 32] = cek
            .as_slice()
            .try_into()
            .map_err(|_| content_decryption_failed())?;
        let cipher = aes_gcm::Aes256Gcm::new(key_arr.into());
        cipher
            .decrypt(&nonce_arr, ct_with_tag.as_ref())
            .map_err(|_| content_decryption_failed())
    } else {
        Err(SmimeError::UnsupportedAlgorithm(format!(
            "AuthEnvelopedData content encryption OID {}",
            content_enc_oid
        )))
    }
}

/// Iterate all `RecipientInfo` entries, call the key to decrypt the CEK for
/// the first matching recipient, and return it.
///
/// The CEK is wrapped in `Zeroizing` so it is scrubbed from memory on drop.
///
/// This function accepts `&RecipientInfos` so it can be shared between the
/// `EnvelopedData` (CBC) and `AuthEnvelopedData` (GCM) code paths.
fn find_and_decrypt_cek(
    recip_infos: &RecipientInfos,
    key: &dyn DecryptionKey,
) -> Result<Zeroizing<Vec<u8>>, SmimeError> {
    // Preserve the last UnsupportedAlgorithm error from a KARI with a matching
    // recipient but unsupported originator type (e.g. static originator).  We
    // continue trying subsequent RecipientInfo entries so that a valid KTRI or
    // ephemeral KARI that follows can still succeed.  If nothing else matches,
    // UnsupportedAlgorithm is more helpful than NoMatchingRecipient.
    let mut unsupported: Option<SmimeError> = None;

    for ri in recip_infos.0.iter() {
        match ri {
            RecipientInfo::Ktri(ktri) => {
                let rid = cms_rid_to_owned(&ktri.rid)?;
                if !key.matches_recipient(&rid) {
                    continue;
                }
                let alg = map_ktri_alg(ktri)?;
                // Fold every ciphertext-dependent failure into the generic
                // content-decryption error (see `content_decryption_failed`).
                // UnsupportedAlgorithm and RngFailure describe the key or
                // the platform, not the ciphertext, and pass through.
                return key
                    .decrypt_cek(ktri.enc_key.as_bytes(), &alg)
                    .map(Zeroizing::new)
                    .map_err(|e| match e {
                        e @ (SmimeError::UnsupportedAlgorithm(_) | SmimeError::RngFailure(_)) => e,
                        _ => content_decryption_failed(),
                    });
            }

            RecipientInfo::Kari(kari) => {
                match try_decrypt_kari(kari, key) {
                    Ok(Some(cek)) => return Ok(cek),
                    Ok(None) => {}
                    // Matched but unsupported originator type: record and keep
                    // trying subsequent RecipientInfo entries.
                    Err(e @ SmimeError::UnsupportedAlgorithm(_)) => unsupported = Some(e),
                    Err(e) => return Err(e),
                }
            }

            // KEK, password, and other recipient types are out of scope for
            // standard S/MIME use cases.
            RecipientInfo::Kekri(_) | RecipientInfo::Pwri(_) | RecipientInfo::Ori(_) => continue,
        }
    }

    Err(unsupported.unwrap_or(SmimeError::NoMatchingRecipient))
}

/// Map a KTRI key-encryption algorithm OID to our `KeyEncryptionAlgorithm` enum.
fn map_ktri_alg(
    ktri: &cms::enveloped_data::KeyTransRecipientInfo,
) -> Result<KeyEncryptionAlgorithm, SmimeError> {
    let oid = ktri.key_enc_alg.oid;
    if oid == RSA_ENCRYPTION {
        Ok(KeyEncryptionAlgorithm::RsaPkcs1v15)
    } else if oid == ID_RSAES_OAEP {
        Ok(KeyEncryptionAlgorithm::RsaOaep)
    } else {
        Err(SmimeError::UnsupportedAlgorithm(format!(
            "key encryption OID {}",
            oid
        )))
    }
}

/// Extract the CBC IV from `content_enc_alg.parameters`, which is encoded as
/// a bare OCTET STRING (RFC 3565 section 4).
fn extract_cbc_iv(env_data: &EnvelopedData) -> Result<Vec<u8>, SmimeError> {
    let params = env_data
        .encrypted_content
        .content_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(|| SmimeError::MalformedInput("CBC algorithm parameters missing".into()))?;
    let iv = params.decode_as::<OctetString>()?;
    Ok(iv.as_bytes().to_vec())
}

/// Decrypt ciphertext with AES-128-CBC + PKCS#7 padding.
///
/// The error message is deliberately generic ("content decryption failed")
/// to prevent padding oracle attacks.  Do not include the underlying
/// `UnpadError` detail — it reveals whether padding was valid, which is
/// sufficient for a Bleichenbacher-style adaptive-chosen-ciphertext attack.
///
/// The IV (public, attacker-chosen) is checked before the CEK, and a CEK of
/// the wrong length yields the same error as a bad padding, so the error does
/// not reveal anything about the recovered CEK.
fn decrypt_aes128_cbc(cek: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, SmimeError> {
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| SmimeError::MalformedInput("AES-128-CBC IV must be 16 bytes".into()))?;
    let key: &[u8; 16] = cek.try_into().map_err(|_| content_decryption_failed())?;
    cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ct)
        .map_err(|_| content_decryption_failed())
}

/// Convert a CMS `RecipientIdentifier` (from the `cms` crate's ASN.1 types) into the
/// owned [`RecipientIdentifier`] exposed in smime-tree's public API.
///
/// DER-encoding the issuer `Name` is the only fallible step; all other conversions
/// are infallible byte copies.
fn cms_rid_to_owned(
    rid: &cms::enveloped_data::RecipientIdentifier,
) -> Result<RecipientIdentifier, SmimeError> {
    match rid {
        cms::enveloped_data::RecipientIdentifier::IssuerAndSerialNumber(ias) => {
            let issuer_der = ias.issuer.to_der()?;
            let serial = ias.serial_number.as_bytes().to_vec();
            Ok(RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial })
        }
        cms::enveloped_data::RecipientIdentifier::SubjectKeyIdentifier(ski) => Ok(
            RecipientIdentifier::SubjectKeyIdentifier(ski.0.as_bytes().to_vec()),
        ),
    }
}

/// Try to decrypt the CEK from a KARI (`KeyAgreeRecipientInfo`) entry.
///
/// Returns `Ok(Some(cek))` if a matching recipient was found and decrypted,
/// `Ok(None)` if no recipient in this KARI matched, or `Err` if a match was
/// found but decryption failed.
fn try_decrypt_kari(
    kari: &KeyAgreeRecipientInfo,
    key: &dyn DecryptionKey,
) -> Result<Option<Zeroizing<Vec<u8>>>, SmimeError> {
    let ukm: Option<&[u8]> = kari.ukm.as_ref().map(|u| u.as_bytes());

    // Check whether any recipient in this KARI entry matches our key FIRST.
    // If no recipient matches, this KARI isn't for us regardless of originator type.
    // If a recipient matches but the originator is static (not ephemeral), we return
    // UnsupportedAlgorithm — the caller's key is the right one but we cannot handle it.
    let matching_rek = kari.recipient_enc_keys.iter().find(|rek| {
        kari_rid_to_owned(&rek.rid)
            .map(|rid| key.matches_recipient(&rid))
            .unwrap_or(false)
    });

    let rek = match matching_rek {
        None => return Ok(None), // none of the recipients match our key
        Some(r) => r,
    };

    // A recipient matched — now check the originator type.  Only ephemeral
    // originator keys are supported (the standard S/MIME case).  Static
    // originators (IssuerAndSerialNumber or SubjectKeyIdentifier) require a
    // different key-lookup path not modelled by the current trait.
    let ephemeral_bytes = match &kari.originator {
        OriginatorIdentifierOrKey::OriginatorKey(orig) => {
            // Validate that the originator key is an id-ecPublicKey point on
            // the curve implied by the KDF scheme. Without this check, a
            // crafted KARI could supply a P-384 point in a P-256 context, or
            // a point not on the curve at all, enabling invalid-curve or
            // small-subgroup attacks against `agree_ecdh` implementations.
            let point = orig.public_key.raw_bytes();
            validate_originator_key(&orig.algorithm, point, kari.key_enc_alg.oid)?;
            point.to_vec()
        }
        _ => {
            return Err(SmimeError::UnsupportedAlgorithm(
                "KARI with static originator is not supported".into(),
            ))
        }
    };

    // A matching recipient was found — now parse the algorithm.  An
    // unsupported OID here is a hard error: the caller's key is the right
    // one but the crate cannot handle the algorithm.
    let kari_alg = map_kari_alg(kari)?;

    let cek = key.agree_ecdh(&ephemeral_bytes, ukm, rek.enc_key.as_bytes(), &kari_alg)?;
    Ok(Some(Zeroizing::new(cek)))
}

/// Validate the ephemeral originator public key of a KARI.
///
/// The KARI's `keyEncryptionAlgorithm.oid` declares which KDF scheme is in use,
/// and this crate pairs each scheme with one curve (SHA-256 KDF with P-256,
/// SHA-384 KDF with P-384; see [`KariKeyAgreement`]).  The originator's
/// `AlgorithmIdentifier` must be `id-ecPublicKey`, and per RFC 5753 §3.1.1 its
/// parameters "MUST be absent, ECParameters, or NULL" (ECParameters being a
/// `namedCurve` OID).  Absent and NULL parameters — OpenSSL omits them — mean
/// the curve is the one implied by the KDF scheme; a `namedCurve` that names
/// a different curve, or any other parameter value, is rejected.
///
/// Finally `point` must decode as a valid SEC1 point on that curve, so an
/// off-curve or wrong-length point never reaches [`DecryptionKey::agree_ecdh`].
fn validate_originator_key(
    orig_alg: &AlgorithmIdentifierOwned,
    point: &[u8],
    kdf_scheme_oid: der::asn1::ObjectIdentifier,
) -> Result<(), SmimeError> {
    // The originator key must use id-ecPublicKey.
    if orig_alg.oid != ID_EC_PUBLIC_KEY {
        return Err(SmimeError::MalformedInput(format!(
            "originator key algorithm is {}, expected id-ecPublicKey",
            orig_alg.oid
        )));
    }

    // Determine the expected curve from the KDF scheme OID.
    let expected_curve = if kdf_scheme_oid == rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME {
        SECP_256_R_1
    } else if kdf_scheme_oid == rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME {
        SECP_384_R_1
    } else {
        // Unknown KDF scheme — map_kari_alg will reject it later.
        return Ok(());
    };

    // Absent or NULL parameters: the curve is the one implied by the KDF
    // scheme.  Otherwise the parameters must be a namedCurve OID naming it.
    match orig_alg.parameters.as_ref() {
        None => {}
        Some(p) if p.is_null() => {}
        Some(p) => {
            let curve_oid = p.decode_as::<der::asn1::ObjectIdentifier>().map_err(|_| {
                SmimeError::MalformedInput(
                    "originator key parameters must be absent, NULL, or a namedCurve OID".into(),
                )
            })?;
            if curve_oid != expected_curve {
                return Err(SmimeError::MalformedInput(format!(
                    "originator key curve {} does not match KDF scheme (expected {})",
                    curve_oid, expected_curve
                )));
            }
        }
    }

    let on_curve = if expected_curve == SECP_256_R_1 {
        p256::PublicKey::from_sec1_bytes(point).is_ok()
    } else {
        p384::PublicKey::from_sec1_bytes(point).is_ok()
    };
    if !on_curve {
        return Err(SmimeError::MalformedInput(format!(
            "originator key is not a valid point on curve {expected_curve}"
        )));
    }

    Ok(())
}

/// Parse the `keyEncryptionAlgorithm` of a KARI into a [`KariAlgorithm`].
///
/// The ECDH scheme OID is in `key_enc_alg.oid`; its parameters contain a
/// DER-encoded `AlgorithmIdentifier` for the key-wrap algorithm (RFC 5753 §3.1).
fn map_kari_alg(kari: &KeyAgreeRecipientInfo) -> Result<KariAlgorithm, SmimeError> {
    let ecdh_oid = kari.key_enc_alg.oid;
    let key_agreement = if ecdh_oid == rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME {
        KariKeyAgreement::StdDhSha256Kdf
    } else if ecdh_oid == rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME {
        KariKeyAgreement::StdDhSha384Kdf
    } else {
        return Err(SmimeError::UnsupportedAlgorithm(format!(
            "ECDH algorithm OID {ecdh_oid}"
        )));
    };

    // The parameters field holds a DER-encoded AlgorithmIdentifier for the
    // key-wrap algorithm (RFC 5753 §3.1 / §7.1.4).
    let params = kari.key_enc_alg.parameters.as_ref().ok_or_else(|| {
        SmimeError::MalformedInput("KARI keyEncryptionAlgorithm has no parameters".into())
    })?;
    let wrap_alg = params.decode_as::<AlgorithmIdentifierOwned>()?;

    let key_wrap = if wrap_alg.oid == ID_AES_128_WRAP {
        KeyWrapAlgorithm::Aes128Kw
    } else if wrap_alg.oid == ID_AES_256_WRAP {
        KeyWrapAlgorithm::Aes256Kw
    } else {
        return Err(SmimeError::UnsupportedAlgorithm(format!(
            "key wrap OID {}",
            wrap_alg.oid
        )));
    };

    Ok(KariAlgorithm {
        key_agreement,
        key_wrap,
    })
}

/// Convert a `KeyAgreeRecipientIdentifier` (from the `cms` crate) into the
/// owned [`RecipientIdentifier`] in smime-tree's public API.
fn kari_rid_to_owned(rid: &KeyAgreeRecipientIdentifier) -> Result<RecipientIdentifier, SmimeError> {
    match rid {
        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias) => {
            let issuer_der = ias.issuer.to_der()?;
            let serial = ias.serial_number.as_bytes().to_vec();
            Ok(RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial })
        }
        KeyAgreeRecipientIdentifier::RKeyId(rki) => Ok(RecipientIdentifier::SubjectKeyIdentifier(
            rki.subject_key_identifier.0.as_bytes().to_vec(),
        )),
    }
}

/// Decrypt ciphertext with AES-256-CBC + PKCS#7 padding.
///
/// See [`decrypt_aes128_cbc`] for the rationale behind the generic error message.
fn decrypt_aes256_cbc(cek: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, SmimeError> {
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| SmimeError::MalformedInput("AES-256-CBC IV must be 16 bytes".into()))?;
    let key: &[u8; 32] = cek.try_into().map_err(|_| content_decryption_failed())?;
    cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ct)
        .map_err(|_| content_decryption_failed())
}

/// The single error returned for every failure that depends on the
/// recovered CEK: content padding or authentication-tag failure, a CEK of the
/// wrong length for the content cipher, and a `decrypt_cek` failure for the
/// matched KTRI recipient (see [`find_and_decrypt_cek`]).
///
/// Returning one indistinguishable error for all of these is what keeps an
/// RSA PKCS#1 v1.5 key-transport recipient from becoming a Bleichenbacher
/// oracle: if a well-formed PKCS#1 block holding a CEK of the wrong length
/// produced a different error than one holding a wrong CEK of the right
/// length, an attacker could tell valid from invalid padding (RFC 3218 §2.3).
fn content_decryption_failed() -> SmimeError {
    SmimeError::DecryptionFailed("content decryption failed".into())
}

#[cfg(test)]
mod tests {
    use super::validate_originator_key;
    use crate::error::SmimeError;
    use const_oid::db::{
        rfc5753,
        rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1},
    };
    use der::{asn1::Null, Any};
    use spki::AlgorithmIdentifierOwned;

    /// Ephemeral P-256 point (uncompressed SEC1) from the originatorKey of an
    /// `openssl cms -encrypt -aes-128-cbc -recip ec256.pem -keyopt
    /// ecdh_kdf_md:sha256` message (the KARI_OPENSSL_P256_DER_HEX fixture in
    /// `tests/smime_tests.rs`).
    const OPENSSL_P256_EPHEMERAL_HEX: &str = concat!(
        "04",
        "1602582029538b65df65e19302e4acd97d0879ff416a5214c2778f9753944911",
        "2fec6c07693868dee0e940256a9f199b60712be2561d500f38f4e9d64e5a59c5"
    );

    fn point() -> Vec<u8> {
        let h = OPENSSL_P256_EPHEMERAL_HEX;
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn ec_alg(parameters: Option<Any>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: ID_EC_PUBLIC_KEY,
            parameters,
        }
    }

    const SHA256_KDF: der::asn1::ObjectIdentifier =
        rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME;

    /// RFC 5753 §3.1.1: parameters "MUST be absent, ECParameters, or NULL".
    /// Absent (what OpenSSL emits), NULL, and the matching namedCurve are all
    /// accepted.
    #[test]
    fn accepts_absent_null_and_matching_named_curve() {
        let p = point();
        for params in [
            None,
            Some(Any::encode_from(&Null).expect("NULL")),
            Some(Any::encode_from(&SECP_256_R_1).expect("OID")),
        ] {
            let alg = ec_alg(params.clone());
            assert_eq!(
                validate_originator_key(&alg, &p, SHA256_KDF),
                Ok(()),
                "{params:?}"
            );
        }
    }

    /// A namedCurve that disagrees with the KDF scheme's curve is rejected.
    #[test]
    fn rejects_mismatching_named_curve() {
        let alg = ec_alg(Some(Any::encode_from(&SECP_384_R_1).expect("OID")));
        let err = validate_originator_key(&alg, &point(), SHA256_KDF).expect_err("mismatch");
        assert!(
            matches!(&err, SmimeError::MalformedInput(m) if m.contains("does not match")),
            "{err:?}"
        );
    }

    /// Parameters that are neither absent, NULL, nor an OID are rejected.
    #[test]
    fn rejects_other_parameter_types() {
        let alg = ec_alg(Some(Any::encode_from(&5u8).expect("INTEGER")));
        let err = validate_originator_key(&alg, &point(), SHA256_KDF).expect_err("INTEGER");
        assert!(matches!(err, SmimeError::MalformedInput(_)), "{err:?}");
    }

    /// The point itself must be on the curve, even when parameters are absent.
    #[test]
    fn rejects_off_curve_point() {
        let mut p = point();
        let last = p.len() - 1;
        p[last] ^= 0x01;
        let err = validate_originator_key(&ec_alg(None), &p, SHA256_KDF).expect_err("off curve");
        assert!(
            matches!(&err, SmimeError::MalformedInput(m) if m.contains("not a valid point")),
            "{err:?}"
        );
        // A P-256 point is also not a valid P-384 point.
        let err = validate_originator_key(
            &ec_alg(None),
            &point(),
            rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME,
        )
        .expect_err("wrong curve");
        assert!(matches!(err, SmimeError::MalformedInput(_)), "{err:?}");
    }
}
