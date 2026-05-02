//! S/MIME decryption: parse EnvelopedData and recover plaintext.

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use aes::Aes128;
use aes::Aes256;
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientInfo};
use const_oid::db::rfc5911::{ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_256_CBC, ID_AES_256_GCM};
use const_oid::db::rfc5912::{ID_RSAES_OAEP, RSA_ENCRYPTION};
use der::{asn1::OctetString, Decode, Encode};

use crate::error::SmimeError;
use crate::key::{DecryptionKey, KeyEncryptionAlgorithm, RecipientIdentifier};

// OID for EnvelopedData content type (RFC 5652 section 3): 1.2.840.113549.1.7.3
const ID_ENVELOPED_DATA: der::asn1::ObjectIdentifier = const_oid::db::rfc5911::ID_ENVELOPED_DATA;

/// Decrypt an S/MIME `EnvelopedData` blob.
///
/// `enveloped_der` must be a DER-encoded `ContentInfo` wrapping an
/// `EnvelopedData` (RFC 5652 section 6).  Returns the inner plaintext bytes.
///
/// KARI (ECDH key agreement, `KeyAgreeRecipientInfo`) is not yet implemented.
/// KEKRI, PWRI, and ORI recipient types are not supported.
pub fn decrypt(enveloped_der: &[u8], key: &dyn DecryptionKey) -> Result<Vec<u8>, SmimeError> {
    // Step 1: Parse the outer ContentInfo.
    let ci = ContentInfo::from_der(enveloped_der)?;

    // Step 2: Verify this is an EnvelopedData.
    if ci.content_type != ID_ENVELOPED_DATA {
        return Err(SmimeError::UnsupportedAlgorithm("not EnvelopedData".into()));
    }

    // Step 3: Parse the EnvelopedData from the ContentInfo payload.
    // ci.content is a DER Any; re-encode it to get the raw DER bytes.
    let content_der = ci.content.to_der()?;
    let env_data = EnvelopedData::from_der(content_der.as_slice())?;

    // Step 4: Find a matching recipient and decrypt the CEK.
    let cek = find_and_decrypt_cek(&env_data, key)?;

    // Step 5: Decrypt the content using the recovered CEK.
    let content_enc_oid = env_data.encrypted_content.content_enc_alg.oid;
    let ct = env_data
        .encrypted_content
        .encrypted_content
        .as_ref()
        .ok_or_else(|| SmimeError::Io("EnvelopedData has no encrypted content".into()))?
        .as_bytes();

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

/// Iterate all `RecipientInfo` entries, call the key to decrypt the CEK for
/// the first matching recipient, and return it.
fn find_and_decrypt_cek(
    env_data: &EnvelopedData,
    key: &dyn DecryptionKey,
) -> Result<Vec<u8>, SmimeError> {
    for ri in env_data.recip_infos.0.iter() {
        match ri {
            RecipientInfo::Ktri(ktri) => {
                let rid = cms_rid_to_owned(&ktri.rid)?;
                if !key.matches_recipient(&rid) {
                    continue;
                }
                let alg = map_ktri_alg(ktri)?;
                return key.decrypt_cek(ktri.enc_key.as_bytes(), &alg);
            }

            RecipientInfo::Kari(_kari) => {
                // KARI (ECDH key agreement, RFC 5753) requires the library to
                // perform ECDH + X9.63 KDF + AES-KW using the ephemeral public
                // key from kari.originator together with the recipient's private
                // key.  The trait interface cannot supply the ephemeral key to
                // the DecryptionKey impl without extending the trait.
                // Deferred to a follow-up issue; KTRI (RSA) is fully supported.
                continue;
            }

            // KEK, password, and other recipient types are out of scope for
            // standard S/MIME use cases.
            RecipientInfo::Kekri(_) | RecipientInfo::Pwri(_) | RecipientInfo::Ori(_) => continue,
        }
    }

    Err(SmimeError::NoMatchingRecipient)
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
        .ok_or_else(|| SmimeError::Io("CBC algorithm parameters missing".into()))?;
    let iv = params.decode_as::<OctetString>()?;
    Ok(iv.as_bytes().to_vec())
}

/// Decrypt ciphertext with AES-128-CBC + PKCS#7 padding.
fn decrypt_aes128_cbc(cek: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, SmimeError> {
    let key: &[u8; 16] = cek
        .try_into()
        .map_err(|_| SmimeError::Io("AES-128 CEK must be 16 bytes".into()))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| SmimeError::Io("AES-128-CBC IV must be 16 bytes".into()))?;
    cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ct)
        .map_err(|_| SmimeError::Io("AES-128-CBC unpad error".into()))
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

/// Decrypt ciphertext with AES-256-CBC + PKCS#7 padding.
fn decrypt_aes256_cbc(cek: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, SmimeError> {
    let key: &[u8; 32] = cek
        .try_into()
        .map_err(|_| SmimeError::Io("AES-256 CEK must be 32 bytes".into()))?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| SmimeError::Io("AES-256-CBC IV must be 16 bytes".into()))?;
    cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ct)
        .map_err(|_| SmimeError::Io("AES-256-CBC unpad error".into()))
}
