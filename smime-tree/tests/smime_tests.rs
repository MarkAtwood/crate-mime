//! Integration tests for smime-tree using OpenSSL as the oracle.
//!
//! Test fixtures (keys, certs, signed/encrypted blobs) were generated with:
//!
//!   openssl genrsa -out ca_key.pem 2048
//!   openssl req -new -x509 -key ca_key.pem -out ca_cert.pem -days 3650 \
//!     -subj "/CN=Test CA/O=Test/C=US"
//!   openssl genrsa -out rsa_key.pem 2048
//!   openssl req -new -key rsa_key.pem -out rsa_csr.pem -subj "/CN=Test User/O=Test/C=US"
//!   openssl x509 -req -in rsa_csr.pem -CA ca_cert.pem -CAkey ca_key.pem \
//!     -CAcreateserial -out rsa_cert.pem -days 3650
//!
//! Signed fixture produced by:
//!   echo -n "Test message content" > plaintext.txt
//!   openssl smime -sign -in plaintext.txt -signer rsa_cert.pem -inkey rsa_key.pem \
//!     -certfile ca_cert.pem -outform PEM > signed_rsa.pem
//!   # PKCS7 PEM -> DER  (this is a detached SignedData: no econtent)
//!   openssl pkcs7 -inform PEM -in signed_rsa.pem -outform DER > sig_only_rsa.der
//!
//! Encrypted fixture produced by:
//!   echo -n "Secret plaintext" > secret.txt
//!   openssl smime -encrypt -aes-128-cbc -in secret.txt \
//!     -outform DER -out encrypted_rsa.der rsa_cert.pem
//!
//! Oracle cross-checks:
//!   - SHA-256("Test message content") == messageDigest in the SignedData (verified externally)
//!   - openssl smime -decrypt of encrypted_rsa.der recovers "Secret plaintext" (verified externally)

use der::{Decode, Encode};
use rsa::signature::SignatureEncoding;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use sha2::Sha256;
use smime_tree::{
    decrypt, encrypt, sign, verify, DecryptionKey, DigestAlgorithm, KeyEncryptionAlgorithm,
    NoRevocationCheck, RecipientIdentifier, SigningKey, SmimeError,
};
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// Oracle-generated DER fixtures (hex-encoded, created by OpenSSL commands above)
// ---------------------------------------------------------------------------

/// CA cert DER (self-signed, /CN=Test CA/O=Test/C=US).
const CA_CERT_HEX: &str = "3082033d30820225a003020102021407333d5893a388c17b89f29c7e0a3477533bd9e4300d06092a864886f70d01010b0500302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323035313331345a170d3336303432393035313331345a302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a02820101008fc0778478543cbc2e5ded4fac3103f3bdc8dda2c737e8ada9f0ab136905e01fc697eef8c64634043c991a24d30cbf29e6415f2ed1ab34e9398a0a2a06e0a2ad1503b1277ba16436e48cef26997d2b8875bd31856142e80db9fb3e5c401894a6a0bec9a7b93ff754922a94e9de230d31d9d9cf2cc1156f0d2b07d67fcff2ccf7acca5e27b158532195f1214662e48cf34c28f41122eeaa80e0afe0f12676a8e8cfd244a6c3e8d21102f7a083e7f2956f0c71ff118ab305a862377f581f6115d47df986c53a5c2b4c5ff6562069c5a90e314e3f37e2b9253a7ba5fc3490ab462e8bde9bbfc58e599c63021fd72447797f79283cfa9744e349b3ca54cbe776fbe10203010001a3533051301d0603551d0e0416041429719bd1b0dc2486a27ef26a4c745f63637fd5f5301f0603551d2304183016801429719bd1b0dc2486a27ef26a4c745f63637fd5f5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101004282efbb5e6d4a05cf48667814cb09ee1915721f68fce118885a42b244579c2ccaa9d81e643737ae74c3b663dbce71be5f10ccda8e52e46a913f1ecc408bdad66aee029c5be5e939b657c9f44a6cd735ee1809528f0441598b762c5e99876d85120090e63b82cba73d7327f42fc9494e125e21d7cd82e94af1e826475e4e02ae46aea987da2a79e21df66c190e6ea1e1de69db80185863f844462e22149057cbd5673692aa1dde38a221e111a90782bf28ba470b4fa01a1c2d876c3a19855dad05ee3eac0a20316152813ca6fa4e286e39901cde034ee102fca848dc38a340327bd8f15ad721e1cfd7e0714060a8fc599d97c190e012410329c97119ff805f33";

/// RSA leaf cert DER (/CN=Test User/O=Test/C=US, signed by CA above).
const RSA_CERT_HEX: &str = "308202e5308201cd0214583180b4a0db0f23bf5f2cbc7cae324024ee0c8d300d06092a864886f70d01010b0500302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323035313331345a170d3336303432393035313331345a30303112301006035504030c09546573742055736572310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100b77e4d796c27f31a2946f045da26d984b595864a53258237a7dbe8bef3252d251a3de492530f972984c81383840cd8ce0ccc8ef006f2388f481bdd134fcde16db68377665c6afc8f799349030abff1d35f579191434e6dd1d148cadb70c8c528691e4ec43b28d4026fd4472f98a781fa3b490b2a8c269278dfba44e9a8febdc1c00a17e29a34cf7696110628a1f620c5a4658f8f7a0778590118a672d695f24cca12c4159ad98db5e2639fc45031b39312152314912e1f29e84135dbd4749998c55c228790cde0b28c0344546acb969d34ea5cbcc29d9c23fd1c9dfd22249b15ac702916d6ddeedcfce1c02b5706d83cdfeda2e8d7841c7f516e1d4fa18475fb0203010001300d06092a864886f70d01010b0500038201010032d3647b952e1c3424de6a066a562fd0157fb7371c07944241a26a8cd980f2ad00d2fa3fa1a96040b6caea7f93ce1e41d4309c983b3d377dde07175dad231099f76be6e6a6544cb77683dcf0065c1bd1c6233801d4ddfb1ec1b0f8afbd995f87557e5d46b3917cfe960ef3c28e0c23f916a87c2e8e1e586281002a17334cab20e97e794b557279d5828402919cc782166f6bdd2e9f5560d040ee8130c4a56037071728c3ea632d2e5987f30b6cb8ed677c71efc294360c01d39a9d357d986324007b9558935d21296515331adbdbbdfc521c475f94b999c9ffffc72f1cbce9f4dc07ba37473b50aad346ffd059db045818d2d32256672b5ef761104af0f3d735";

/// RSA private key DER (PKCS#8 unencrypted) — matches RSA_CERT_HEX above.
const RSA_KEY_PKCS8_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b77e4d796c27f31a2946f045da26d984b595864a53258237a7dbe8bef3252d251a3de492530f972984c81383840cd8ce0ccc8ef006f2388f481bdd134fcde16db68377665c6afc8f799349030abff1d35f579191434e6dd1d148cadb70c8c528691e4ec43b28d4026fd4472f98a781fa3b490b2a8c269278dfba44e9a8febdc1c00a17e29a34cf7696110628a1f620c5a4658f8f7a0778590118a672d695f24cca12c4159ad98db5e2639fc45031b39312152314912e1f29e84135dbd4749998c55c228790cde0b28c0344546acb969d34ea5cbcc29d9c23fd1c9dfd22249b15ac702916d6ddeedcfce1c02b5706d83cdfeda2e8d7841c7f516e1d4fa18475fb0203010001028201000f30109892c7b1bb021ca1899e97659cb2ecf7eb11fbc24dfa025d3ee4e0385ee04fac2a225ee17ba9c667bb14847db37c62b8180cf32294557b1ceedac5a7398e084eab35ce132e8af9126b8289c5a9e1b3dd5421368e277643a8aac628900d1aba4bf9b90dd5928810117e528bd6d9cfeb6955b1b90599a4a705ca3357367c7d97f187b8513632815056acd53005dae07e2dd7c07cc947e2d3a8ba4bfda5baf29593bd7318f9aca9116303f392bbea700f0285a20056630ca8879e8c09b80a644ecec15c15bf443d64a27f9a39959e412abb4e937dc728e775892a657d044608db608a606dfc37d738afab84816d76591ce1eae51c6130adbd0f662ddb646d02818100da5fafe94626fca8c467b596bdfd335b50abdb9183132ade513ceaacab117ce7a6b6115030fbe0ef32e2d8ef251b41c02f24b56c8cd7252d7e5e7ec0d7df1b8054e9602385f7bd3861cce828c9a6d81b4c7087e39d8260b72df23504bd13944c3c1456f1132b33f1ad649dea8730c65f652bf1523bcb59457a15ef12a186312f02818100d71c10babbcfc98530204a1eb2bba518aa8ef42792d4fa2cca127398134f55041808d8198b11e7b0c6c4608c8293457a423992fabee56f4a4dd3513019259dfe2eef4093e763a7986e8ddc8c6f9af883fea84b621c0144c8c889aff9cda6a3f6321154c43dacfd3be5598e209e24ee68f4ab6ac2fe032c1630a58015709ddcf502818100c11ddfee7708a1660a9300a6b78bc4b01b8e7015a609fc5e310fa32561ff8c2b3c6644b75b2a54c89482c27ff29bc130d94028653fc43fef9492b29b8e0c93409156f59b54ad3b1c3279485251ca87d0d46fabece1ed5be482f0706ca95d384796d611f10e17a5cf339d087e506214fc65f74f697ed19d37f0f896bd2e350327028180253889fc85baf297c538111b36ba195b27480d1f3bdcf65d01aa27ae4cc91160dff7c7ccc3af9973913131b39e7475352e785fe25b5dbfe00f8f5d210178ecd9aaad6373343a9e295617ddedbef205c6712e15bd28335fff8e13a50b88762930d4810335e1a6293b4ff82b0ba1d1aa1f2716f2264365b11f35d3ad52086688710281801e29f084f3b8168feb1f1073d96cdf62c3609137f5d418062aa3482dcf000c3417a4cf0cbfc4f39281e51ac911d8a67e9c6a7d98854d18192166b79b36f6b99a8765433f9087ec5c3ddec17be46624adfd5bc7435fc6f848b5ed725e7422ea6d7c20de6cb44ad8c51cc567aef7f97f6305daba6d48533810c8c662764cf038a3";

/// Detached CMS SignedData DER (ContentInfo wrapping SignedData).
///
/// Signed by the RSA key above over the bytes b"Test message content".
/// Oracle cross-check: SHA-256("Test message content") ==
///   0xc83281e9259a19cee1bd3e3c176689e7c1e63c35eca4a788b13c46e3aa0eeefd
/// which matches the messageDigest signed attribute in this blob.
/// Certificate bag contains both the leaf cert and the CA cert.
const SIG_RSA_DER_HEX: &str = "308208be06092a864886f70d010702a08208af308208ab020101310f300d06096086480165030402010500300b06092a864886f70d010701a082062a3082033d30820225a003020102021407333d5893a388c17b89f29c7e0a3477533bd9e4300d06092a864886f70d01010b0500302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323035313331345a170d3336303432393035313331345a302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a02820101008fc0778478543cbc2e5ded4fac3103f3bdc8dda2c737e8ada9f0ab136905e01fc697eef8c64634043c991a24d30cbf29e6415f2ed1ab34e9398a0a2a06e0a2ad1503b1277ba16436e48cef26997d2b8875bd31856142e80db9fb3e5c401894a6a0bec9a7b93ff754922a94e9de230d31d9d9cf2cc1156f0d2b07d67fcff2ccf7acca5e27b158532195f1214662e48cf34c28f41122eeaa80e0afe0f12676a8e8cfd244a6c3e8d21102f7a083e7f2956f0c71ff118ab305a862377f581f6115d47df986c53a5c2b4c5ff6562069c5a90e314e3f37e2b9253a7ba5fc3490ab462e8bde9bbfc58e599c63021fd72447797f79283cfa9744e349b3ca54cbe776fbe10203010001a3533051301d0603551d0e0416041429719bd1b0dc2486a27ef26a4c745f63637fd5f5301f0603551d2304183016801429719bd1b0dc2486a27ef26a4c745f63637fd5f5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101004282efbb5e6d4a05cf48667814cb09ee1915721f68fce118885a42b244579c2ccaa9d81e643737ae74c3b663dbce71be5f10ccda8e52e46a913f1ecc408bdad66aee029c5be5e939b657c9f44a6cd735ee1809528f0441598b762c5e99876d85120090e63b82cba73d7327f42fc9494e125e21d7cd82e94af1e826475e4e02ae46aea987da2a79e21df66c190e6ea1e1de69db80185863f844462e22149057cbd5673692aa1dde38a221e111a90782bf28ba470b4fa01a1c2d876c3a19855dad05ee3eac0a20316152813ca6fa4e286e39901cde034ee102fca848dc38a340327bd8f15ad721e1cfd7e0714060a8fc599d97c190e012410329c97119ff805f33308202e5308201cd0214583180b4a0db0f23bf5f2cbc7cae324024ee0c8d300d06092a864886f70d01010b0500302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323035313331345a170d3336303432393035313331345a30303112301006035504030c09546573742055736572310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100b77e4d796c27f31a2946f045da26d984b595864a53258237a7dbe8bef3252d251a3de492530f972984c81383840cd8ce0ccc8ef006f2388f481bdd134fcde16db68377665c6afc8f799349030abff1d35f579191434e6dd1d148cadb70c8c528691e4ec43b28d4026fd4472f98a781fa3b490b2a8c269278dfba44e9a8febdc1c00a17e29a34cf7696110628a1f620c5a4658f8f7a0778590118a672d695f24cca12c4159ad98db5e2639fc45031b39312152314912e1f29e84135dbd4749998c55c228790cde0b28c0344546acb969d34ea5cbcc29d9c23fd1c9dfd22249b15ac702916d6ddeedcfce1c02b5706d83cdfeda2e8d7841c7f516e1d4fa18475fb0203010001300d06092a864886f70d01010b0500038201010032d3647b952e1c3424de6a066a562fd0157fb7371c07944241a26a8cd980f2ad00d2fa3fa1a96040b6caea7f93ce1e41d4309c983b3d377dde07175dad231099f76be6e6a6544cb77683dcf0065c1bd1c6233801d4ddfb1ec1b0f8afbd995f87557e5d46b3917cfe960ef3c28e0c23f916a87c2e8e1e586281002a17334cab20e97e794b557279d5828402919cc782166f6bdd2e9f5560d040ee8130c4a56037071728c3ea632d2e5987f30b6cb8ed677c71efc294360c01d39a9d357d986324007b9558935d21296515331adbdbbdfc521c475f94b999c9ffffc72f1cbce9f4dc07ba37473b50aad346ffd059db045818d2d32256672b5ef761104af0f3d73531820258308202540201013046302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b30090603550406130255530214583180b4a0db0f23bf5f2cbc7cae324024ee0c8d300d06096086480165030402010500a081e4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236303530323035313331395a302f06092a864886f70d01090431220420c83281e9259a19cee1bd3e3c176689e7c1e63c35eca4a788b13c46e3aa0eeefd307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300d06092a864886f70d010101050004820100ad7ed2b5c13be4d024462516c9c563d4f7a82712e72506a0490db922a2e05de8e33340a784ecf770ffa26482fffced018eca319f0a0742ace4cfd7981d7b2b990844c9b56bd86806187a81f7ee33be7fa6027e28d0dce63f32ba17bb7e579818a3d4946b85dc64be4b7d7292dc3b11fba5b5c6a58fc18bb928e4da62572481a228c653cc94edde47362077fcab5104a406c1ff95bcc30b7c61bf1d8ca67bdab72960bbaad793787ac3ba2dc3ff809fef8751eb02bccf549d91897e1f59e0a609f4d9ee5ceee3f101fff3e201fd7c25839fb17aace6f9e2080c77919809dfec0530439b4e5baa415abe90f5b234c13d7104d7a936a5da3e2c8e5f19e766559959";

/// CMS EnvelopedData DER (ContentInfo wrapping EnvelopedData, AES-128-CBC).
///
/// Encrypted with the RSA cert above.  Oracle: openssl smime -decrypt recovers
/// exactly the bytes b"Secret plaintext".
const ENCRYPTED_RSA_DER_HEX: &str = "308201ca06092a864886f70d010703a08201bb308201b7020100318201623082015e0201003046302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b30090603550406130255530214583180b4a0db0f23bf5f2cbc7cae324024ee0c8d300d06092a864886f70d0101010500048201006396dd8c3e5db02777f8e37c4bc07c5f079a0be59371eb1d6fcf5f65f02d86aaca1a72cc6e19324a1ed4c3ff339c58ad490856f362f273ee6c41b9e4d20232505bcc6dd71bc798612628bb3a7fbe080c63bd1b9a9a432d59f88c433f68194f0fe783ae2f3eedcd213c6a5c83931d246cb751b4965363a05672ce839db85bd3e04ffac0f79ac7f47522ee9e99a82c22e729fef0c650681e6137213fd15180470262b595f9c9b786bb57bd2d36ffff1961e4b4010a63e45a5ab5bc5b1e270106db24464c95d8e07586d562884f96a8e6d0173b09dcd2cca2cb6cf10194f993b99dd5a1c43fb0c02809bc3f375ba024cdd80c1c464eb250905849c0df1574bdfef1304c06092a864886f70d010701301d060960864801650304010204109ee41e5339511f49fa6e2e5e3643a23a802006f13e3074e1cf6825b206e9a822e7780bcfeee5f10d80006d58a7df7a94d911";

// ---------------------------------------------------------------------------
// Helper: decode a hex string to bytes (panics on invalid hex)
// ---------------------------------------------------------------------------

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// Test key implementations
// ---------------------------------------------------------------------------

/// `DecryptionKey` backed by an RSA private key, matching by issuer+serial.
struct TestRsaDecryptionKey {
    private_key: RsaPrivateKey,
    cert: Certificate,
}

impl DecryptionKey for TestRsaDecryptionKey {
    fn decrypt_cek(
        &self,
        encrypted_key: &[u8],
        algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        match algorithm {
            KeyEncryptionAlgorithm::RsaPkcs1v15 => self
                .private_key
                .decrypt(rsa::Pkcs1v15Encrypt, encrypted_key)
                .map_err(|e| SmimeError::Other(e.to_string())),
            other => Err(SmimeError::UnsupportedAlgorithm(format!(
                "test key only supports RsaPkcs1v15, got {:?}",
                other
            ))),
        }
    }

    fn matches_recipient(&self, id: &RecipientIdentifier) -> bool {
        match id {
            RecipientIdentifier::IssuerAndSerialNumber { issuer_der, serial } => {
                let issuer_ok = self
                    .cert
                    .tbs_certificate()
                    .issuer()
                    .to_der()
                    .map(|a| a == *issuer_der)
                    .unwrap_or(false);
                let serial_ok =
                    self.cert.tbs_certificate().serial_number().as_bytes() == serial.as_slice();
                issuer_ok && serial_ok
            }
            RecipientIdentifier::SubjectKeyIdentifier(_) => false,
            _ => false,
        }
    }
}

/// `SigningKey` backed by an RSA private key (SHA-256 + PKCS#1 v1.5).
struct TestRsaSigningKey {
    private_key: rsa::pkcs1v15::SigningKey<Sha256>,
    cert: Certificate,
}

impl SigningKey for TestRsaSigningKey {
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError> {
        match algorithm {
            DigestAlgorithm::Sha256 => {
                use rsa::signature::Signer;
                let sig = self.private_key.sign(data);
                Ok(sig.to_vec())
            }
            other => Err(SmimeError::UnsupportedAlgorithm(format!(
                "test key only supports SHA-256, got {:?}",
                other
            ))),
        }
    }

    fn certificate(&self) -> &Certificate {
        &self.cert
    }
}

// ---------------------------------------------------------------------------
// Test A: verify() accepts an OpenSSL-signed message
//
// Oracle: the messageDigest signed attribute in SIG_RSA_DER_HEX was set by
// OpenSSL to SHA-256(b"Test message content"), confirmed externally:
//   echo -n "Test message content" | sha256sum
//   => c83281e9259a19cee1bd3e3c176689e7c1e63c35eca4a788b13c46e3aa0eeefd
// ---------------------------------------------------------------------------

#[test]
fn test_verify_openssl_rsa_signed() {
    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_cert = Certificate::from_der(&ca_cert_der).expect("parse CA cert");

    let sig_der = from_hex(SIG_RSA_DER_HEX);

    // The signed content is the exact bytes OpenSSL hashed (no trailing newline;
    // created via: echo -n "Test message content").
    let signed_content: &[u8] = b"Test message content";

    let result = verify(
        signed_content,
        &sig_der,
        &[ca_cert],
        // Fixed time within cert validity window (2026-05-02 to 2036-04-29).
        // Using SystemTime::now() would create a time-bomb when the certs expire.
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    )
    .expect("verify() must not return a DER parse error");

    assert!(
        !result.signers.is_empty(),
        "SignedData must contain at least one SignerInfo"
    );

    let verified_count = result.signers.iter().filter(|s| s.verified).count();
    assert!(
        verified_count >= 1,
        "at least one signer must verify successfully; results: {:?}",
        result.signers
    );
}

// ---------------------------------------------------------------------------
// Test B: decrypt() recovers the known plaintext from an OpenSSL-encrypted blob
//
// Oracle: openssl smime -decrypt -inform DER -in encrypted_rsa.der \
//           -recip rsa_cert.pem -inkey rsa_key.pem
//         => "Secret plaintext"
// ---------------------------------------------------------------------------

#[test]
fn test_decrypt_openssl_encrypted() {
    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let private_key = RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");

    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let key = TestRsaDecryptionKey { private_key, cert };

    let encrypted_der = from_hex(ENCRYPTED_RSA_DER_HEX);
    let plaintext = decrypt(&encrypted_der, &key).expect("decrypt() must succeed");

    // Oracle: the plaintext encrypted by OpenSSL was "Secret plaintext"
    assert_eq!(
        plaintext, b"Secret plaintext",
        "decrypted plaintext must match the OpenSSL oracle"
    );
}

// ---------------------------------------------------------------------------
// Test C: sign() output is accepted by `openssl smime -verify`
//
// Oracle: OpenSSL exit code 0 and stdout == "Verification successful"
// ---------------------------------------------------------------------------

#[test]
fn test_sign_output_accepted_by_openssl() {
    if !openssl_available() {
        eprintln!("SKIP test_sign_output_accepted_by_openssl: openssl not found in PATH");
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let private_key = RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);

    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let test_key = TestRsaSigningKey {
        private_key: signing_key,
        cert,
    };

    let content_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nHello from smime-tree\r\n";
    let signed_bytes = sign(content_mime, &test_key).expect("sign() must succeed");

    // Write the signed MIME message to a temp file.
    let mut signed_file = tempfile::NamedTempFile::new().expect("create temp file");
    signed_file
        .write_all(&signed_bytes)
        .expect("write signed bytes");
    let signed_path = signed_file.path().to_path_buf();

    // Write the CA cert DER to a temp PEM file for openssl to use as trust anchor.
    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&ca_cert_der)
    );
    let mut ca_file = tempfile::NamedTempFile::new().expect("create CA temp file");
    ca_file.write_all(ca_pem.as_bytes()).expect("write CA cert");
    let ca_path = ca_file.path().to_path_buf();

    // Verify against the CA cert. -noverify is intentionally omitted so that
    // OpenSSL validates the full certificate chain, not just the signature bytes.
    let output = Command::new("openssl")
        .args([
            "smime",
            "-verify",
            "-in",
            signed_path.to_str().unwrap(),
            "-CAfile",
            ca_path.to_str().unwrap(),
            "-out",
            "/dev/null",
        ])
        .output()
        .expect("openssl must be available");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "openssl smime -verify must exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Verification successful"),
        "openssl must report 'Verification successful'; stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test D: encrypt() output is decrypted by `openssl smime -decrypt`
//
// Oracle: OpenSSL recovers the original inner_mime bytes
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_output_decrypted_by_openssl() {
    if !openssl_available() {
        eprintln!("SKIP test_encrypt_output_decrypted_by_openssl: openssl not found in PATH");
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nSecret from smime-tree\r\n";

    let encrypted_bytes = encrypt(inner_mime, &[cert]).expect("encrypt() must succeed");

    // Write the encrypted MIME message to a temp file.
    let mut enc_file = tempfile::NamedTempFile::new().expect("create temp file");
    enc_file
        .write_all(&encrypted_bytes)
        .expect("write encrypted bytes");
    let enc_path = enc_file.path().to_path_buf();

    // Write RSA private key to temp PEM for openssl.
    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode_pem(&rsa_key_der)
    );
    let mut key_file = tempfile::NamedTempFile::new().expect("create key temp file");
    key_file.write_all(key_pem.as_bytes()).expect("write key");
    let key_path = key_file.path().to_path_buf();

    // Write RSA cert to temp PEM for openssl.
    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&rsa_cert_der)
    );
    let mut cert_file = tempfile::NamedTempFile::new().expect("create cert temp file");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("write cert");
    let cert_path = cert_file.path().to_path_buf();

    let output = Command::new("openssl")
        .args([
            "smime",
            "-decrypt",
            "-in",
            enc_path.to_str().unwrap(),
            "-recip",
            cert_path.to_str().unwrap(),
            "-inkey",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("openssl must be available");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "openssl smime -decrypt must exit 0; stderr: {stderr}"
    );

    // Oracle: OpenSSL decrypts to the exact bytes we encrypted.
    assert_eq!(
        output.stdout.as_slice(),
        inner_mime,
        "openssl must recover the original inner_mime bytes"
    );
}

// ---------------------------------------------------------------------------
// Helper: base64-encode bytes with 64-char line wrapping for PEM
// ---------------------------------------------------------------------------

fn base64_encode_pem(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let encoded = base64_encode(bytes);
    let mut out = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        writeln!(out, "{}", std::str::from_utf8(chunk).unwrap()).unwrap();
    }
    // Remove trailing newline added by the last writeln
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Returns `true` if the `openssl` binary is available in PATH.
///
/// Tests that shell out to openssl call this first and return early if the
/// binary is absent, rather than panicking with a confusing error message.
fn openssl_available() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Test E: sign() → mime_tree::parse() → verify() round-trip
//
// Exercises MIME-6uo.3: verifies that when a caller extracts the signed
// content bytes using mime-tree body/header ranges and feeds them to verify(),
// the digest matches what sign() computed.
// ---------------------------------------------------------------------------

#[test]
fn test_sign_verify_roundtrip_via_mime_tree() {
    use base64::Engine as _;

    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let private_key = RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);

    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_cert = Certificate::from_der(&ca_cert_der).expect("parse CA cert");

    let test_key = TestRsaSigningKey {
        private_key: signing_key,
        cert,
    };

    let content_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nHello roundtrip\r\n";
    let signed_bytes = sign(content_mime, &test_key).expect("sign() must succeed");

    // Parse the multipart/signed output with mime-tree.
    // The root is multipart, so children get IDs "1" (signed content) and
    // "2" (application/pkcs7-signature) per IMAP dotted-path rules.
    let parsed = mime_tree::parse(&signed_bytes).expect("mime_tree::parse must succeed");

    // Part "1": the signed MIME content.
    let part1 = parsed
        .part_index
        .find_by_id("1")
        .expect("part '1' (signed content) must exist");

    // The signed content is the full MIME part: headers + blank line + body.
    // header_range covers the headers (including the trailing blank line);
    // body_range covers the body text.  Spanning from header_range start to
    // body_range end reconstructs the exact bytes sign() hashed.
    let content_start = part1.header_range.0 as usize;
    let content_end = (part1.body_range.0 + part1.body_range.1) as usize;
    let extracted_content = &signed_bytes[content_start..content_end];

    // Part "2": application/pkcs7-signature (base64-encoded CMS blob).
    let part2 = parsed
        .part_index
        .find_by_id("2")
        .expect("part '2' (pkcs7-signature) must exist");

    let sig_start = part2.body_range.0 as usize;
    let sig_end = (part2.body_range.0 + part2.body_range.1) as usize;
    let sig_b64: Vec<u8> = signed_bytes[sig_start..sig_end]
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let signature_der = base64::engine::general_purpose::STANDARD
        .decode(&sig_b64)
        .expect("pkcs7-signature part must be valid base64");

    let result = verify(
        extracted_content,
        &signature_der,
        &[ca_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    )
    .expect("verify() must not return a parse error");

    let verified = result.signers.iter().any(|s| s.verified);
    assert!(
        verified,
        "sign() → mime_tree::parse() → verify() round-trip must succeed; \
         signers: {:?}",
        result.signers
    );
}

// ---------------------------------------------------------------------------
// Tests F-H: cert chain validation edge cases
//
// These tests reuse the existing OpenSSL-generated fixtures (no new fixture
// generation needed) and exercise error paths in validate_chain() that are
// not covered by the happy-path tests.
// ---------------------------------------------------------------------------

/// Test F: cert chain validation fails when time is before notBefore.
///
/// Oracle: cert validity window is "2026-05-02 to 2036-04-29".  Passing a
/// time far in the past (1970-01-01) must cause certificate chain validation
/// to fail, producing AllSignersFailed with a CertificateExpired error.
#[test]
fn test_verify_fails_before_cert_not_before() {
    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_cert = Certificate::from_der(&ca_cert_der).expect("parse CA cert");
    let sig_der = from_hex(SIG_RSA_DER_HEX);

    let result = verify(
        b"Test message content",
        &sig_der,
        &[ca_cert],
        std::time::UNIX_EPOCH, // 1970-01-01 — before any cert's notBefore
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(signers)) => {
            let error_str = signers[0].error.as_deref().unwrap_or("");
            assert!(
                error_str.contains("expired") || error_str.contains("valid"),
                "expected an expiry/validity error, got: {error_str}"
            );
        }
        other => panic!("expected AllSignersFailed; got: {other:?}"),
    }
}

/// Test G: verify() fails with no trust anchors.
///
/// Oracle: validate_chain() returns CertChain(NoTrustAnchors) immediately
/// when trust_anchors is empty.  verify() wraps this into AllSignersFailed.
#[test]
fn test_verify_fails_with_no_trust_anchors() {
    let sig_der = from_hex(SIG_RSA_DER_HEX);

    let result = verify(
        b"Test message content",
        &sig_der,
        &[], // no trust anchors
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(signers)) => {
            let error_str = signers[0].error.as_deref().unwrap_or("");
            assert!(
                error_str.contains("trust anchor"),
                "expected 'trust anchor' in error, got: {error_str}"
            );
        }
        other => panic!("expected AllSignersFailed; got: {other:?}"),
    }
}

/// Test H: verify() fails when the trust anchor does not sign the signer cert.
///
/// The RSA leaf cert is passed as the trust anchor instead of the CA cert.
/// The chain walk finds no matching issuer and fails with NoMatchingIssuer.
#[test]
fn test_verify_fails_with_wrong_trust_anchor() {
    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let wrong_anchor = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");
    let sig_der = from_hex(SIG_RSA_DER_HEX);

    let result = verify(
        b"Test message content",
        &sig_der,
        &[wrong_anchor], // leaf cert, not the CA
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(signers)) => {
            // With the wrong trust anchor, the chain walker either detects a
            // "no matching issuer" (NoMatchingIssuer) or, when the CA cert is
            // in the signature bag and re-encountered during chain building, a
            // "cycle" (Cycle). Both indicate the chain could not be verified.
            let error_str = signers[0].error.as_deref().unwrap_or("");
            assert!(
                error_str.contains("trust anchor")
                    || error_str.contains("issuer")
                    || error_str.contains("cycle"),
                "expected a chain error (trust anchor / issuer / cycle), got: {error_str}"
            );
        }
        other => panic!("expected AllSignersFailed; got: {other:?}"),
    }
}
