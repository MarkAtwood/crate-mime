//! S/MIME EnvelopedData encryption.
//!
//! Implements RFC 5652 (CMS EnvelopedData) and RFC 5753 (ECC in CMS).
//! All cryptographic primitives are used directly — the cms builder feature
//! has a transitive dependency conflict with the locked cipher version.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cms::{
    cert::IssuerAndSerialNumber,
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{
        EncryptedContentInfo, EncryptedKey, EnvelopedData, KeyAgreeRecipientIdentifier,
        KeyAgreeRecipientInfo, KeyTransRecipientInfo, OriginatorIdentifierOrKey,
        OriginatorPublicKey, RecipientEncryptedKey, RecipientIdentifier, RecipientInfo,
        RecipientInfos,
    },
};
use const_oid::db::{rfc5753, rfc5911, rfc5912};
use crypto_common::Generate;
use der::{
    asn1::{BitString, ObjectIdentifier, OctetString, SetOfVec},
    Any, AnyRef, Encode, Sequence,
};
use elliptic_curve::ecdh::EphemeralSecret;
use elliptic_curve::sec1::ToSec1Point;
use getrandom::{rand_core::UnwrapErr, SysRng};
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::error::SmimeError;

// OID shorthand constants used in this file.
const ID_DATA: ObjectIdentifier = rfc5911::ID_DATA;
const ID_ENVELOPED_DATA: ObjectIdentifier = rfc5911::ID_ENVELOPED_DATA;
const ID_AES_128_CBC: ObjectIdentifier = rfc5911::ID_AES_128_CBC;
const ID_AES_256_CBC: ObjectIdentifier = rfc5911::ID_AES_256_CBC;
const ID_AES_128_WRAP: ObjectIdentifier = rfc5911::ID_AES_128_WRAP;
const ID_AES_256_WRAP: ObjectIdentifier = rfc5911::ID_AES_256_WRAP;
// dhSinglePass-stdDH-sha256kdf-scheme (RFC 5753 §7.1.4)
const DH_SHA256_KDF: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME;
// dhSinglePass-stdDH-sha384kdf-scheme (RFC 5753 §7.1.4)
const DH_SHA384_KDF: ObjectIdentifier = rfc5753::DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME;

/// Shared info structure for ANSI X9.63 KDF, as defined in RFC 5753 §7.2.
///
/// ```text
/// EccCmsSharedInfo ::= SEQUENCE {
///     keyInfo         AlgorithmIdentifier,
///     entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
///     suppPubInfo [2] EXPLICIT OCTET STRING  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EccCmsSharedInfo {
    key_info: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "0",
        tag_mode = "EXPLICIT",
        constructed = "true",
        optional = "true"
    )]
    entity_u_info: Option<OctetString>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    supp_pub_info: OctetString,
}

/// Encrypt `inner_mime` bytes to all `recipients`.
///
/// Returns a complete `application/pkcs7-mime; smime-type=enveloped-data` MIME
/// message as UTF-8 bytes. The body is the base64-encoded DER of the CMS
/// `ContentInfo` wrapping an `EnvelopedData`.
///
/// # Content encryption algorithm selection
///
/// - **AES-128-CBC** is used when all recipients are RSA or P-256.
/// - **AES-256-CBC** is used when any recipient is P-384 (P-384 provides ~192-bit
///   security; pairing it with AES-128 would be a security-level mismatch).
///
/// # EnvelopedData version (RFC 5652 §6.1)
///
/// - `V0` when all recipients are KTRI (RSA key transport).
/// - `V2` when any recipient is KARI (ECDH key agreement).
///
/// # Errors
///
/// Returns `SmimeError::Other("no recipients")` when `recipients` is empty.
/// Returns `SmimeError::UnsupportedAlgorithm` for any certificate whose
/// subject public key algorithm is not RSA, P-256, or P-384.
pub fn encrypt(inner_mime: &[u8], recipients: &[Certificate]) -> Result<Vec<u8>, SmimeError> {
    if recipients.is_empty() {
        return Err(SmimeError::Other("no recipients".into()));
    }

    let mut rng = UnwrapErr(SysRng);

    // Pre-scan recipients: if any uses P-384, upgrade content encryption to
    // AES-256-CBC so the security level matches the key agreement strength.
    let use_aes256 = recipients.iter().any(|cert| {
        let spki = cert.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid != rfc5912::ID_EC_PUBLIC_KEY {
            return false;
        }
        spki.algorithm
            .parameters
            .as_ref()
            .and_then(|p: &Any| p.decode_as::<ObjectIdentifier>().ok())
            .map(|curve| curve == rfc5912::SECP_384_R_1)
            .unwrap_or(false)
    });

    use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};

    // Encrypt the content and derive per-algorithm values; recipient loop runs once below.
    let (content_enc_alg, encrypted_content, cek_bytes) = if use_aes256 {
        // AES-256-CBC: 32-byte key, 16-byte IV.
        let cek = crypto_common::Key::<cbc::Encryptor<aes::Aes256>>::generate_from_rng(&mut rng);
        let iv = crypto_common::Iv::<cbc::Encryptor<aes::Aes256>>::generate_from_rng(&mut rng);
        let ct =
            cbc::Encryptor::<aes::Aes256>::new(&cek, &iv).encrypt_padded_vec::<Pkcs7>(inner_mime);
        let cek_bytes: Vec<u8> = (cek.as_ref() as &[u8]).to_vec();
        let iv_oct = OctetString::new(iv.as_ref()).map_err(SmimeError::Der)?;
        let iv_any = Any::encode_from(&iv_oct).map_err(SmimeError::Der)?;
        let alg = AlgorithmIdentifierOwned {
            oid: ID_AES_256_CBC,
            parameters: Some(iv_any),
        };
        (alg, ct, cek_bytes)
    } else {
        // AES-128-CBC: 16-byte key, 16-byte IV.
        let cek = crypto_common::Key::<cbc::Encryptor<aes::Aes128>>::generate_from_rng(&mut rng);
        let iv = crypto_common::Iv::<cbc::Encryptor<aes::Aes128>>::generate_from_rng(&mut rng);
        let ct =
            cbc::Encryptor::<aes::Aes128>::new(&cek, &iv).encrypt_padded_vec::<Pkcs7>(inner_mime);
        let cek_bytes: Vec<u8> = (cek.as_ref() as &[u8]).to_vec();
        let iv_oct = OctetString::new(iv.as_ref()).map_err(SmimeError::Der)?;
        let iv_any = Any::encode_from(&iv_oct).map_err(SmimeError::Der)?;
        let alg = AlgorithmIdentifierOwned {
            oid: ID_AES_128_CBC,
            parameters: Some(iv_any),
        };
        (alg, ct, cek_bytes)
    };

    // Build recipient infos. All recipients use the same CEK regardless of algorithm.
    let mut recipient_infos: Vec<RecipientInfo> = Vec::with_capacity(recipients.len());
    for cert in recipients {
        recipient_infos.push(build_recipient_info(cert, &cek_bytes, &mut rng)?);
    }

    // RFC 5652 §6.1: version is V0 when all recipients are KTRI; V2 when any
    // recipient is KARI (or KEKRI/PWRI). Determine after building all infos.
    let version = if recipient_infos
        .iter()
        .all(|ri| matches!(ri, RecipientInfo::Ktri(_)))
    {
        CmsVersion::V0
    } else {
        CmsVersion::V2
    };

    let enc_content = OctetString::new(encrypted_content).map_err(SmimeError::Der)?;

    // RecipientInfos is a newtype over SetOfVec.
    let set: SetOfVec<RecipientInfo> =
        SetOfVec::try_from(recipient_infos).map_err(SmimeError::Der)?;
    let recip_infos = RecipientInfos::from(set);

    let env_data = EnvelopedData {
        version,
        originator_info: None,
        recip_infos,
        encrypted_content: EncryptedContentInfo {
            content_type: ID_DATA,
            content_enc_alg,
            encrypted_content: Some(enc_content),
        },
        unprotected_attrs: None,
    };

    // Wrap in ContentInfo and DER-encode.
    let env_der = env_data.to_der().map_err(SmimeError::Der)?;
    let content = AnyRef::try_from(env_der.as_slice()).map_err(SmimeError::Der)?;
    let ci = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::from(content),
    };
    let ci_der = ci.to_der().map_err(SmimeError::Der)?;

    Ok(build_mime(&ci_der))
}

/// Inspect a certificate's SPKI and return the appropriate `RecipientInfo`.
fn build_recipient_info(
    cert: &Certificate,
    cek: &[u8],
    rng: &mut UnwrapErr<SysRng>,
) -> Result<RecipientInfo, SmimeError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let alg_oid = spki.algorithm.oid;

    if alg_oid == rfc5912::RSA_ENCRYPTION || alg_oid == rfc5912::ID_RSAES_OAEP {
        build_rsa_recipient(cert, cek, rng)
    } else if alg_oid == rfc5912::ID_EC_PUBLIC_KEY {
        let curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p: &Any| p.decode_as::<ObjectIdentifier>().ok())
            .ok_or_else(|| {
                SmimeError::UnsupportedAlgorithm("EC public key missing curve OID parameter".into())
            })?;

        if curve_oid == rfc5912::SECP_256_R_1 {
            build_p256_recipient(cert, cek, rng)
        } else if curve_oid == rfc5912::SECP_384_R_1 {
            build_p384_recipient(cert, cek, rng)
        } else {
            Err(SmimeError::UnsupportedAlgorithm(format!(
                "EC curve {} not supported",
                curve_oid
            )))
        }
    } else {
        Err(SmimeError::UnsupportedAlgorithm(format!(
            "recipient key algorithm {} not supported",
            alg_oid
        )))
    }
}

/// Build a KTRI (RSA PKCS#1v15 key transport) RecipientInfo.
fn build_rsa_recipient(
    cert: &Certificate,
    cek: &[u8],
    rng: &mut UnwrapErr<SysRng>,
) -> Result<RecipientInfo, SmimeError> {
    use rsa::Pkcs1v15Encrypt;

    let spki_der = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(SmimeError::Der)?;
    let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| SmimeError::Other(e.to_string()))?;

    let encrypted_key = rsa_pub
        .encrypt(rng, Pkcs1v15Encrypt, cek)
        .map_err(|e| SmimeError::Other(e.to_string()))?;

    let ias = IssuerAndSerialNumber {
        issuer: cert.tbs_certificate().issuer().clone(),
        serial_number: cert.tbs_certificate().serial_number().clone(),
    };

    Ok(RecipientInfo::Ktri(KeyTransRecipientInfo {
        version: CmsVersion::V0,
        rid: RecipientIdentifier::IssuerAndSerialNumber(ias),
        key_enc_alg: AlgorithmIdentifierOwned {
            oid: rfc5912::RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        enc_key: EncryptedKey::new(encrypted_key).map_err(SmimeError::Der)?,
    }))
}

/// Build a KARI (P-256 ECDH + AES-128-KW) RecipientInfo.
fn build_p256_recipient(
    cert: &Certificate,
    cek: &[u8],
    rng: &mut UnwrapErr<SysRng>,
) -> Result<RecipientInfo, SmimeError> {
    use p256::NistP256;

    let raw_bits = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let recipient_pub =
        p256::PublicKey::from_sec1_bytes(raw_bits).map_err(|e| SmimeError::Other(e.to_string()))?;

    let ephemeral: EphemeralSecret<NistP256> = EphemeralSecret::generate_from_rng(rng);
    let ephemeral_pub = ephemeral.public_key();
    let shared_secret = ephemeral.diffie_hellman(&recipient_pub);

    // AES-128-KW: KEK size = 16 bytes = 128 bits.
    let wrapped_cek = ecdh_wrap_cek::<sha2::Sha256>(
        shared_secret.raw_secret_bytes().as_ref(),
        ID_AES_128_WRAP,
        128u32,
        cek,
    )?;

    build_kari_recipient(
        cert,
        ephemeral_pub.to_sec1_point(false).as_bytes().to_vec(),
        rfc5912::SECP_256_R_1,
        DH_SHA256_KDF,
        ID_AES_128_WRAP,
        wrapped_cek,
    )
}

/// Build a KARI (P-384 ECDH + AES-256-KW) RecipientInfo.
///
/// P-384 provides ~192-bit security; AES-256-KW matches that level.
/// The caller must supply a 32-byte CEK (AES-256-CBC).
fn build_p384_recipient(
    cert: &Certificate,
    cek: &[u8],
    rng: &mut UnwrapErr<SysRng>,
) -> Result<RecipientInfo, SmimeError> {
    use p384::NistP384;

    let raw_bits = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let recipient_pub =
        p384::PublicKey::from_sec1_bytes(raw_bits).map_err(|e| SmimeError::Other(e.to_string()))?;

    let ephemeral: EphemeralSecret<NistP384> = EphemeralSecret::generate_from_rng(rng);
    let ephemeral_pub = ephemeral.public_key();
    let shared_secret = ephemeral.diffie_hellman(&recipient_pub);

    // AES-256-KW: KEK size = 32 bytes = 256 bits, matching P-384 security level.
    let wrapped_cek = ecdh_wrap_cek::<sha2::Sha384>(
        shared_secret.raw_secret_bytes().as_ref(),
        ID_AES_256_WRAP,
        256u32,
        cek,
    )?;

    build_kari_recipient(
        cert,
        ephemeral_pub.to_sec1_point(false).as_bytes().to_vec(),
        rfc5912::SECP_384_R_1,
        DH_SHA384_KDF,
        ID_AES_256_WRAP,
        wrapped_cek,
    )
}

/// Assemble a KARI `RecipientInfo` from pre-computed ECDH outputs.
///
/// Both `build_p256_recipient` and `build_p384_recipient` call this after
/// performing their curve-specific key generation and CEK wrapping.
///
/// `ephemeral_pub_bytes` — uncompressed SEC1 point bytes of the ephemeral public key.
/// `curve_oid`           — OID of the named curve (goes into OriginatorPublicKey).
/// `kdf_oid`             — ECDH+KDF scheme OID (e.g. dhSinglePass-stdDH-sha256kdf-scheme).
/// `wrap_oid`            — AES key-wrap algorithm OID (e.g. id-aes128-Wrap).
/// `wrapped_cek`         — CEK after AES-KW, ready to place in RecipientEncryptedKey.
fn build_kari_recipient(
    cert: &Certificate,
    ephemeral_pub_bytes: Vec<u8>,
    curve_oid: ObjectIdentifier,
    kdf_oid: ObjectIdentifier,
    wrap_oid: ObjectIdentifier,
    wrapped_cek: Vec<u8>,
) -> Result<RecipientInfo, SmimeError> {
    let originator_pub = OriginatorPublicKey {
        algorithm: AlgorithmIdentifierOwned {
            oid: rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(&curve_oid)),
        },
        public_key: BitString::from_bytes(&ephemeral_pub_bytes).map_err(SmimeError::Der)?,
    };

    let ias = IssuerAndSerialNumber {
        issuer: cert.tbs_certificate().issuer().clone(),
        serial_number: cert.tbs_certificate().serial_number().clone(),
    };

    Ok(RecipientInfo::Kari(KeyAgreeRecipientInfo {
        version: CmsVersion::V3,
        originator: OriginatorIdentifierOrKey::OriginatorKey(originator_pub),
        ukm: None,
        key_enc_alg: AlgorithmIdentifierOwned {
            oid: kdf_oid,
            parameters: Some(wrap_alg_any(wrap_oid)?),
        },
        recipient_enc_keys: vec![RecipientEncryptedKey {
            rid: KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(ias),
            enc_key: EncryptedKey::new(wrapped_cek).map_err(SmimeError::Der)?,
        }],
    }))
}

/// Derive a KEK via ANSI X9.63 KDF and wrap `cek` with AES-KW.
///
/// `shared_secret_bytes` — raw ECDH shared secret field bytes.
/// `wrap_oid`            — OID of the AES key wrap algorithm (goes into EccCmsSharedInfo).
/// `wrap_key_bits`       — size of the wrap key in bits (goes into suppPubInfo).
/// `cek`                 — the content-encryption key to wrap.
fn ecdh_wrap_cek<D>(
    shared_secret_bytes: &[u8],
    wrap_oid: ObjectIdentifier,
    wrap_key_bits: u32,
    cek: &[u8],
) -> Result<Vec<u8>, SmimeError>
where
    D: sha2::digest::Digest + sha2::digest::FixedOutputReset,
{
    // Build EccCmsSharedInfo per RFC 5753 §7.2.
    let key_wrap_alg = AlgorithmIdentifierOwned {
        oid: wrap_oid,
        parameters: None,
    };
    let supp_bytes = wrap_key_bits.to_be_bytes();
    let shared_info = EccCmsSharedInfo {
        key_info: key_wrap_alg,
        entity_u_info: None,
        supp_pub_info: OctetString::new(supp_bytes.as_slice()).map_err(SmimeError::Der)?,
    };
    let shared_info_der = shared_info.to_der().map_err(SmimeError::Der)?;

    // Derive the KEK: kek_len = wrap_key_bits / 8 bytes.
    let kek_len = (wrap_key_bits / 8) as usize;
    let mut kek = vec![0u8; kek_len];
    ansi_x963_kdf::derive_key_into::<D>(shared_secret_bytes, &shared_info_der, &mut kek)
        .map_err(|_| SmimeError::Other("ANSI X9.63 KDF failed".into()))?;

    // Wrap the CEK with AES-KW. Wrapped output = cek.len() + 8 bytes.
    let wrapped_len = cek.len() + 8;
    let mut wrapped = vec![0u8; wrapped_len];
    match kek_len {
        16 => {
            use aes_kw::cipher::KeyInit;
            let kek_arr: &[u8; 16] = kek
                .as_slice()
                .try_into()
                .map_err(|_| SmimeError::Other("KEK length mismatch".into()))?;
            let wrapper = aes_kw::KwAes128::new(kek_arr.into());
            wrapper
                .wrap_key(cek, &mut wrapped)
                .map_err(|e| SmimeError::Other(e.to_string()))?;
        }
        32 => {
            use aes_kw::cipher::KeyInit;
            let kek_arr: &[u8; 32] = kek
                .as_slice()
                .try_into()
                .map_err(|_| SmimeError::Other("KEK length mismatch".into()))?;
            let wrapper = aes_kw::KwAes256::new(kek_arr.into());
            wrapper
                .wrap_key(cek, &mut wrapped)
                .map_err(|e| SmimeError::Other(e.to_string()))?;
        }
        _ => {
            return Err(SmimeError::Other(format!(
                "unsupported KEK length: {kek_len} bytes"
            )));
        }
    }

    Ok(wrapped)
}

/// Encode a key-wrap `AlgorithmIdentifier` as `Any`.
///
/// Per RFC 5753 §7.1 the `parameters` field of the key-agreement
/// `AlgorithmIdentifier` contains the `AlgorithmIdentifier` of the key-wrap
/// algorithm as a DER-encoded inner value.
fn wrap_alg_any(wrap_oid: ObjectIdentifier) -> Result<Any, SmimeError> {
    let alg = AlgorithmIdentifierOwned {
        oid: wrap_oid,
        parameters: None,
    };
    Any::encode_from(&alg).map_err(SmimeError::Der)
}

/// Wrap DER bytes in an `application/pkcs7-mime` MIME outer message.
///
/// Base64 is folded at 76 characters per line (RFC 2045 §6.8).
fn build_mime(der: &[u8]) -> Vec<u8> {
    let b64 = BASE64.encode(der);
    // Fold at 76 chars; base64 output is always ASCII.
    let mut folded = String::with_capacity(b64.len() + b64.len() / 76 * 2 + 4);
    for chunk in b64.as_bytes().chunks(76) {
        // b64 is a String, so its byte slices are always valid UTF-8.
        folded.push_str(
            core::str::from_utf8(chunk)
                .expect("base64 output is a String — from_utf8 always succeeds"),
        );
        folded.push_str("\r\n");
    }

    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=smime.p7m\r\n\
         \r\n\
         {folded}"
    );
    mime.into_bytes()
}
