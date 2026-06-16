//! S/MIME AuthEnvelopedData encryption (AES-GCM).
//!
//! Implements RFC 5083 (AuthEnvelopedData), RFC 5084 (AES-GCM in CMS), and
//! RFC 5753 (ECC in CMS).  All cryptographic primitives are used directly —
//! the cms builder feature has a transitive dependency conflict with the
//! locked cipher version.

use aes_gcm::aead::{Aead, KeyInit as GcmKeyInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cms::{
    authenveloped_data::AuthEnvelopedData,
    cert::IssuerAndSerialNumber,
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{
        EncryptedContentInfo, EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo,
        KeyTransRecipientInfo, OriginatorIdentifierOrKey, OriginatorPublicKey,
        RecipientEncryptedKey, RecipientIdentifier, RecipientInfo, RecipientInfos,
    },
};
use const_oid::db::{rfc5753, rfc5911, rfc5912};
use crypto_common::Generate as _;
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

use zeroize::Zeroizing;

use crate::error::SmimeError;

// OID shorthand constants used in this file.
const ID_DATA: ObjectIdentifier = rfc5911::ID_DATA;
const ID_CT_AUTH_ENVELOPED_DATA: ObjectIdentifier = rfc5911::ID_CT_AUTH_ENVELOPED_DATA;
const ID_AES_128_GCM: ObjectIdentifier = rfc5911::ID_AES_128_GCM;
const ID_AES_256_GCM: ObjectIdentifier = rfc5911::ID_AES_256_GCM;
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
/// Returns a MIME body part (`application/pkcs7-mime; smime-type=authEnveloped-data`)
/// as UTF-8 bytes: the Content-Type, Content-Transfer-Encoding,
/// Content-Disposition headers, blank line, and base64-encoded DER of the CMS
/// `ContentInfo` wrapping an `AuthEnvelopedData` (RFC 5083).
///
/// Content is encrypted with AES-GCM, which provides authenticated encryption
/// (integrity + confidentiality).  This is the preferred mode for new S/MIME
/// deployments, replacing the legacy AES-CBC `EnvelopedData` path.
///
/// This is the encrypted body part, not a complete RFC 5322 message. The caller
/// must add message-level headers (`From`, `To`, `Subject`, etc.) when assembling
/// the full outgoing message.
///
/// # Security
///
/// RSA recipients use PKCS#1 v1.5 key transport (`KeyTransRecipientInfo`), which is
/// deprecated by [RFC 8017 §7.2](https://www.rfc-editor.org/rfc/rfc8017#section-7.2) in
/// favour of RSAES-OAEP.  PKCS#1 v1.5 encryption is vulnerable to Bleichenbacher-style
/// padding oracle attacks when the decryption result is observable.  For new deployments,
/// OAEP (`id-RSAES-OAEP`) is strongly preferred; PKCS#1 v1.5 is retained here for
/// compatibility with existing S/MIME infrastructure.
///
/// # Content encryption algorithm selection
///
/// - **AES-128-GCM** is used when all recipients are RSA or P-256.
/// - **AES-256-GCM** is used when any recipient is P-384 (P-384 provides ~192-bit
///   security; pairing it with AES-128 would be a security-level mismatch).
///
/// When a mixed list of RSA and P-384 recipients is supplied, AES-256-GCM is
/// used throughout; each RSA recipient receives the 256-bit CEK wrapped with
/// RSA PKCS#1 v1.5.
///
/// # AuthEnvelopedData version (RFC 5083)
///
/// Always `V0`.
///
/// # Errors
///
/// Returns `SmimeError::NoRecipients` when `recipients` is empty.
/// Returns `SmimeError::UnsupportedAlgorithm` for any certificate whose
/// subject public key algorithm is not RSA, P-256, or P-384.
/// Returns `SmimeError::RngFailure` when the OS RNG fails during:
/// - CEK/nonce generation, or
/// - the 256-byte RNG preflight check that precedes RSA PKCS#1v15 key
///   transport (in `build_rsa_recipient`), or
/// - ephemeral ECDH key generation for P-256 or P-384 recipients.
///
/// # Panics
///
/// **RSA PKCS#1v15 encrypt call**: after the RNG preflight check succeeds,
/// `rsa_pub.encrypt()` is called with `UnwrapErr(SysRng)`, which panics if
/// the OS RNG fails at that point.  The `rsa` crate does not expose a
/// fallible encrypt variant.  A preflight check of 256 bytes immediately
/// before the call covers all practical failure scenarios; the residual panic
/// window is a narrow TOCTOU gap that would only trigger on catastrophic
/// OS-level RNG failure after the preflight succeeds.
///
/// All other RNG uses in this function (CEK/nonce generation, ECDH ephemeral
/// key generation) go through `getrandom` directly and return
/// `Err(SmimeError::RngFailure)` rather than panicking.
pub fn encrypt(inner_mime: &[u8], recipients: &[Certificate]) -> Result<Vec<u8>, SmimeError> {
    if recipients.is_empty() {
        return Err(SmimeError::NoRecipients);
    }

    // Pre-scan recipients: if any uses P-384, upgrade content encryption to
    // AES-256-GCM so the security level matches the key agreement strength.
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

    // Encrypt the content with AES-GCM.
    let (content_enc_alg, encrypted_content, mac, cek_bytes) = if use_aes256 {
        encrypt_aes_gcm(32, ID_AES_256_GCM, inner_mime)?
    } else {
        encrypt_aes_gcm(16, ID_AES_128_GCM, inner_mime)?
    };

    // Build recipient infos. All recipients use the same CEK regardless of algorithm.
    let mut recipient_infos: Vec<RecipientInfo> = Vec::with_capacity(recipients.len());
    for cert in recipients {
        recipient_infos.push(build_recipient_info(cert, &cek_bytes)?);
    }

    let enc_content = OctetString::new(encrypted_content)?;

    // RecipientInfos is a newtype over SetOfVec.
    let set: SetOfVec<RecipientInfo> = SetOfVec::try_from(recipient_infos)?;
    let recip_infos = RecipientInfos::from(set);

    let auth_env_data = AuthEnvelopedData {
        version: CmsVersion::V0,
        originator_info: None,
        recip_infos,
        auth_encrypted_content_info: EncryptedContentInfo {
            content_type: ID_DATA,
            content_enc_alg,
            encrypted_content: Some(enc_content),
        },
        auth_attrs: None,
        mac: OctetString::new(mac)?,
        unauth_attrs: None,
    };

    // Wrap in ContentInfo and DER-encode.
    let auth_env_der = auth_env_data.to_der()?;
    let content = AnyRef::try_from(auth_env_der.as_slice())?;
    let ci = ContentInfo {
        content_type: ID_CT_AUTH_ENVELOPED_DATA,
        content: Any::from(content),
    };
    let ci_der = ci.to_der()?;

    Ok(build_mime(&ci_der))
}

/// GCM algorithm parameters per RFC 5084 section 3.2.
///
/// ```text
/// GCMParameters ::= SEQUENCE {
///     aes-nonce        OCTET STRING, -- recommended size is 12 octets
///     aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct GcmParameters {
    aes_nonce: OctetString,
    #[asn1(default = "default_icv_len")]
    aes_icv_len: u8,
}

fn default_icv_len() -> u8 {
    12
}

/// Generate a random CEK and nonce, encrypt content with AES-GCM, and
/// assemble the `AlgorithmIdentifier` + `GCMParameters`.
///
/// `key_len` must be 16 (AES-128) or 32 (AES-256).  Returns the algorithm
/// identifier, ciphertext (without tag), tag (16 bytes), and CEK.
///
/// The CEK bytes are returned as `Zeroizing<Vec<u8>>` so they are scrubbed
/// on drop.
#[allow(clippy::type_complexity)]
fn encrypt_aes_gcm(
    key_len: usize,
    cek_oid: ObjectIdentifier,
    plaintext: &[u8],
) -> Result<
    (
        AlgorithmIdentifierOwned,
        Vec<u8>,
        Vec<u8>,
        Zeroizing<Vec<u8>>,
    ),
    SmimeError,
> {
    let mut cek_buf = vec![0u8; key_len];
    let mut nonce_buf = [0u8; 12];
    getrandom::fill(&mut cek_buf).map_err(|e| SmimeError::RngFailure(format!("{e}")))?;
    getrandom::fill(&mut nonce_buf).map_err(|e| SmimeError::RngFailure(format!("{e}")))?;

    // Encrypt with AES-GCM. The crate returns ciphertext || 16-byte tag.
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(nonce_buf.as_slice())
        .map_err(|_| SmimeError::Other("nonce length mismatch".into()))?;
    let ct_with_tag = if key_len == 32 {
        let key_arr: &[u8; 32] = cek_buf
            .as_slice()
            .try_into()
            .map_err(|_| SmimeError::Other("AES-256-GCM key length mismatch".into()))?;
        let cipher = aes_gcm::Aes256Gcm::new(key_arr.into());
        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SmimeError::Other("AES-256-GCM encrypt failed".into()))?
    } else {
        let key_arr: &[u8; 16] = cek_buf
            .as_slice()
            .try_into()
            .map_err(|_| SmimeError::Other("AES-128-GCM key length mismatch".into()))?;
        let cipher = aes_gcm::Aes128Gcm::new(key_arr.into());
        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SmimeError::Other("AES-128-GCM encrypt failed".into()))?
    };

    // Split: everything except the last 16 bytes is ciphertext, last 16 is the tag.
    let tag_start = ct_with_tag.len() - 16;
    let ct = ct_with_tag[..tag_start].to_vec();
    let tag = ct_with_tag[tag_start..].to_vec();

    let cek_bytes = Zeroizing::new(cek_buf);

    // Build GCMParameters per RFC 5084 §3.2.
    let gcm_params = GcmParameters {
        aes_nonce: OctetString::new(nonce_buf.as_slice())?,
        aes_icv_len: 16,
    };
    let params_any = Any::encode_from(&gcm_params)?;

    let alg = AlgorithmIdentifierOwned {
        oid: cek_oid,
        parameters: Some(params_any),
    };

    Ok((alg, ct, tag, cek_bytes))
}

/// Inspect a certificate's SPKI and return the appropriate `RecipientInfo`.
fn build_recipient_info(cert: &Certificate, cek: &[u8]) -> Result<RecipientInfo, SmimeError> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let alg_oid = spki.algorithm.oid;

    if alg_oid == rfc5912::RSA_ENCRYPTION {
        build_rsa_recipient(cert, cek)
    } else if alg_oid == rfc5912::ID_RSAES_OAEP {
        // id-RSAES-OAEP in the SPKI field is not the same as RSA + PKCS#1v15.
        // Routing to build_rsa_recipient() here would produce a PKCS#1v15-wrapped
        // CEK that the recipient cannot decrypt with an OAEP key.  RSAES-OAEP
        // encryption is not yet implemented; fail explicitly rather than silently
        // producing a malformed message.
        Err(SmimeError::UnsupportedAlgorithm(
            "RSAES-OAEP recipient certs (id-RSAES-OAEP SPKI OID) are not supported; \
             use RSA with PKCS#1v1.5"
                .into(),
        ))
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
            build_p256_recipient(cert, cek)
        } else if curve_oid == rfc5912::SECP_384_R_1 {
            build_p384_recipient(cert, cek)
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
fn build_rsa_recipient(cert: &Certificate, cek: &[u8]) -> Result<RecipientInfo, SmimeError> {
    use rsa::Pkcs1v15Encrypt;

    // The rsa crate's encrypt() uses UnwrapErr(SysRng) internally, which panics
    // if the OS RNG fails.  We do a 256-byte preflight check first: on any
    // real OS, once getrandom succeeds the RNG stays functional for the rest
    // of the call, so this covers all practical failure scenarios.  A narrow
    // TOCTOU window between the preflight and the encrypt call remains but
    // would only trigger on catastrophic OS-level RNG failure.
    let mut preflight = [0u8; 256];
    getrandom::fill(&mut preflight).map_err(|e| SmimeError::RngFailure(format!("{e}")))?;
    let _ = preflight;

    let spki_der = cert.tbs_certificate().subject_public_key_info().to_der()?;
    let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| {
        SmimeError::MalformedInput(format!("RSA public key in recipient cert: {e}"))
    })?;

    // UnwrapErr panics (rather than returning Err) when the OS RNG fails, so
    // RNG failures here propagate as a panic, not as SmimeError::RngFailure.
    // The map_err below converts non-RNG errors (e.g. key-size / data-too-long)
    // into SmimeError::Other.  The preflight above ensures getrandom
    // is operational before reaching this point.
    let mut rng = UnwrapErr(SysRng);
    let encrypted_key = rsa_pub
        .encrypt(&mut rng, Pkcs1v15Encrypt, cek)
        .map_err(|e| SmimeError::Other(format!("RSA PKCS#1v15 encrypt: {e}")))?;

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
        enc_key: EncryptedKey::new(encrypted_key)?,
    }))
}

/// Build a KARI (P-256 ECDH + AES-128-KW) RecipientInfo.
fn build_p256_recipient(cert: &Certificate, cek: &[u8]) -> Result<RecipientInfo, SmimeError> {
    use p256::NistP256;

    let raw_bits = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let recipient_pub = p256::PublicKey::from_sec1_bytes(raw_bits).map_err(|e| {
        SmimeError::MalformedInput(format!("P-256 public key in recipient cert: {e}"))
    })?;

    let ephemeral: EphemeralSecret<NistP256> = EphemeralSecret::try_generate_from_rng(&mut SysRng)
        .map_err(|e| SmimeError::RngFailure(format!("{e}")))?;
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
        ephemeral_pub.to_sec1_point(false).as_bytes(),
        rfc5912::SECP_256_R_1,
        DH_SHA256_KDF,
        ID_AES_128_WRAP,
        wrapped_cek,
    )
}

/// Build a KARI (P-384 ECDH + AES-256-KW) RecipientInfo.
///
/// P-384 provides ~192-bit security; AES-256-KW matches that level.
/// The caller must supply a 32-byte CEK (AES-256-GCM).
fn build_p384_recipient(cert: &Certificate, cek: &[u8]) -> Result<RecipientInfo, SmimeError> {
    use p384::NistP384;

    let raw_bits = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let recipient_pub = p384::PublicKey::from_sec1_bytes(raw_bits).map_err(|e| {
        SmimeError::MalformedInput(format!("P-384 public key in recipient cert: {e}"))
    })?;

    let ephemeral: EphemeralSecret<NistP384> = EphemeralSecret::try_generate_from_rng(&mut SysRng)
        .map_err(|e| SmimeError::RngFailure(format!("{e}")))?;
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
        ephemeral_pub.to_sec1_point(false).as_bytes(),
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
    ephemeral_pub_bytes: &[u8],
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
        public_key: BitString::from_bytes(ephemeral_pub_bytes)?,
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
            enc_key: EncryptedKey::new(wrapped_cek)?,
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
        supp_pub_info: OctetString::new(supp_bytes.as_slice())?,
    };
    let shared_info_der = shared_info.to_der()?;

    // Derive the KEK: kek_len = wrap_key_bits / 8 bytes.
    let kek_len = (wrap_key_bits / 8) as usize;
    let mut kek = Zeroizing::new(vec![0u8; kek_len]);
    ansi_x963_kdf::derive_key_into::<D>(shared_secret_bytes, &shared_info_der, &mut kek)
        .map_err(|_| SmimeError::Other("ANSI X9.63 KDF failed".into()))?;

    // Wrap the CEK with AES-KW. Wrapped output = cek.len() + 8 bytes.
    let wrapped_len = cek.len() + 8;
    let mut wrapped = vec![0u8; wrapped_len];
    // Macro avoids duplicating the try_into + KeyInit + wrap_key pattern for
    // the two supported KEK sizes; only the array size and KW type differ.
    macro_rules! do_wrap {
        ($n:literal, $kw:ty) => {{
            use aes_kw::cipher::KeyInit;
            let kek_arr: &[u8; $n] = kek
                .as_slice()
                .try_into()
                .map_err(|_| SmimeError::Other("KEK length mismatch".into()))?;
            let wrapper = <$kw>::new(kek_arr.into());
            wrapper
                .wrap_key(cek, &mut wrapped)
                .map_err(|e| SmimeError::Other(e.to_string()))?;
        }};
    }
    match kek_len {
        16 => do_wrap!(16, aes_kw::KwAes128),
        32 => do_wrap!(32, aes_kw::KwAes256),
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
                .unwrap_or_else(|_| unreachable!("base64 output is always valid UTF-8")),
        );
        folded.push_str("\r\n");
    }

    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: application/pkcs7-mime; smime-type=authEnveloped-data; name=smime.p7m\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=smime.p7m\r\n\
         \r\n\
         {folded}"
    );
    mime.into_bytes()
}
