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
use rsa::{pkcs8::DecodePrivateKey, PrivateKey as RsaPrivateKey};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashSigner as _;
use smime_tree::{
    decrypt, encrypt, sign, verify, DecryptionKey, DigestAlgorithm, KariAlgorithm,
    KariKeyAgreement, KeyEncryptionAlgorithm, NoRevocationCheck, RecipientIdentifier, SigningKey,
    SmimeError,
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
// 3-cert chain fixtures
//
// Generated by:
//   openssl genrsa -out chain_root_key.pem 2048
//   openssl req -new -x509 -key chain_root_key.pem -out chain_root_cert.pem -days 3650
//     -subj "/CN=Chain Root CA/O=Test/C=US" -addext "basicConstraints=critical,CA:true"
//   openssl genrsa -out chain_int_key.pem 2048
//   openssl req -new -key chain_int_key.pem -out chain_int_csr.pem
//     -subj "/CN=Chain Intermediate CA/O=Test/C=US"
//   openssl x509 -req -in chain_int_csr.pem -CA chain_root_cert.pem -CAkey chain_root_key.pem
//     -CAcreateserial -out chain_int_cert.pem -days 3650
//     -extfile <(printf '[v3_ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n')
//   openssl genrsa -out chain_leaf_key.pem 2048
//   openssl req -new -key chain_leaf_key.pem -out chain_leaf_csr.pem
//     -subj "/CN=Chain Leaf User/O=Test/C=US"
//   openssl x509 -req -in chain_leaf_csr.pem -CA chain_int_cert.pem -CAkey chain_int_key.pem
//     -CAcreateserial -out chain_leaf_cert.pem -days 3650
//   echo -n "Chain test content" > chain_plain.txt
//   openssl smime -sign -in chain_plain.txt -signer chain_leaf_cert.pem
//     -inkey chain_leaf_key.pem -certfile chain_int_cert.pem -outform PEM > chain_signed.pem
//   openssl pkcs7 -inform PEM -in chain_signed.pem -outform DER > chain_sig.der
//
// Oracle cross-check:
//   openssl verify -CAfile chain_root_cert.pem -untrusted chain_int_cert.pem chain_leaf_cert.pem
//   openssl smime -verify -in chain_signed.pem -CAfile chain_root_cert.pem
//     -content chain_plain.txt -out /dev/null  => "Verification successful"
//
// The SignedData bag contains: intermediate CA cert + leaf cert (not the root).
// The root is supplied as trust anchor in verify().
// ---------------------------------------------------------------------------

/// Root CA cert DER (self-signed, /CN=Chain Root CA/O=Test/C=US).
const CHAIN_ROOT_CERT_HEX: &str = "3082034930820231a00302010202141b519c38e31faf9dacd26e12e40744773fdddacb300d06092a864886f70d01010b050030343116301406035504030c0d436861696e20526f6f74204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323134323431305a170d3336303432393134323431305a30343116301406035504030c0d436861696e20526f6f74204341310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100c4f086d98462959528763e738483abf89847a19b9ea76d263c555e5676ed174d79b059ef9e8fa58dc068a8a58021c179dce41fa9243ae8b4b010b48049724108618f00c0728b2a57d9777cd9508b4f81837b07c4ad168cde5eb4fa46fd1e330ce5d65eabd71196f3c61661f29a04af43f6f2f276401acddf782fdb32cfa8ab9eb131f6764a786f07061b22df342ea1140dda154f155d717a71acc69d52171d1435596561b37c20fe65b661b81a807d60a271779d2a406e30f5e42e04822db2790a2f3b6290e982138ff9152eec4c96f008d344dde4a3b14256eba71ffd23210f348b9510fb8976cb5ddceea024ae26eb251718c20eff3dc4dc1d2250a6e10b750203010001a3533051301d0603551d0e041604141110735a6ae8e4a1007ebba869246a12fcc937b2301f0603551d230418301680141110735a6ae8e4a1007ebba869246a12fcc937b2300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100306253ea21487adcaed9a4437636a025061f0229185c63fc9161344c289f1e89e4f040e94c84b646fb5d256ac80e8ed53a9f824a449ea1da949ce931b1fd6909e5173c9ba5f14750789ec649a94116e21b6f104d47916c197bb864953e9644d3fc9681840dd2227fc14aab9ad899ed69113dbeb6f454e288e62a59c115916306d462bd555b2310bcb220775ea9dcf88fa57295b2ba96db897b9ce62361c81c77bee3d43097dce8ba12fa7594d365d5591a723893394075c745ba9f6a165cb0ecf5a7d33d211ba44b8be73ffe29720ce504bbac891f000a5954bbf77309e489b19bcf651e53d271392976b61e8ae41de7fb806a3e88a0fde36878d434622ed7b6";

/// Leaf cert DER (/CN=Chain Leaf User/O=Test/C=US, signed by intermediate CA).
const CHAIN_LEAF_CERT_HEX: &str = "308202f9308201e10214474dd37a0dab22f2921cc510ab9b90403a812584300d06092a864886f70d01010b0500303c311e301c06035504030c15436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323134323431395a170d3336303432393134323431395a30363118301606035504030c0f436861696e204c6561662055736572310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100c16ae1252c4e80dc5f5b244313cc975bb8543382624488722968d50fcb5666f08516f12db9a97b8ac50704ccae2de5076ad2a27d3462bf13ac9a23eae3c44d5a20252b1a2ddd1c1ba9259d0f7562cfca8e01416a734564bd5ffa6633f1c5905a40a11d7c21767589fa709c2a6e990fa2766325133671384f041c9542a86791badd889d785fe8f55a954efb39df8e9e822d079659b69e865a08732b66ce83113917ffc67e83ce316a4223c100090ea40d0b4ee8e4ff1cf0f2a18c23f05333aabaadd7c91cdcad733fbd791ab55670b392b3c5df862c691d392bd09ab77d79d2a20f393b155b381c757ebd1a68e85a164c085220dc6d8e806173b5284fd60f36a90203010001300d06092a864886f70d01010b0500038201010076bd8147c88f223888d61f851db6d46107151de57760c098015244c3e8ab5fef48bdb30d8092f53d4bdef635d4716ed8c737f47f9ea4afa01b8de28b194dfb0320a8eaa0aa32410d044ee01ad3ee4c718d8abc231312ba1c82c88239c335a916ec3f626affa80891a833c7a9b2fe9e4090704fd935ef8f4bfd9ae0d96ace90c5436e7495ca7fe5c1291a7f89ae9c628f5c235d20a7617e72e966e97c9d9affd993c3cf1f73dc73d219b9a4500e99ea7a93e52d30eca051089d24bb1604e6c6da06a00258d6df95515b724744be3c8aa4ad9c1a21ee33cc8ce6a9b2e9615f91b5db3f973a6185b036b74163792d2986b66cfe3d4cb310e801ddc646db8da22b7b";

/// CMS SignedData DER: signed by leaf key; bag contains intermediate CA + leaf certs.
///
/// Oracle cross-check: SHA-256("Chain test content") ==
///   0x5405c54eb79ec127bb40e0cf952d0cbc7681aac6fa8fb0c3db656890867d7b32
/// which matches the messageDigest signed attribute in this blob.
const CHAIN_SIG_HEX: &str = "3082090406092a864886f70d010702a08208f5308208f1020101310f300d06096086480165030402010500300b06092a864886f70d010701a08206623082036130820249a0030201020214245de0fb3deefbecdbc83365db7c98bce821dc03300d06092a864886f70d01010b050030343116301406035504030c0d436861696e20526f6f74204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323134323431345a170d3336303432393134323431345a303c311e301c06035504030c15436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100bfe1006c27a9259d4c9d3dff5108e0401ceac89cd6b4e1e4cc269470cd8b6db8e2b351dbddbcae331d7865956766a54ac8acb723f67cd585e3cfa0366392bd7decbccbef3907a72f2670dc4285af52e2c1180a2dcbd8536eeb23001bf7aceddebb6c251e7d17210b37d5954ec6fa818244e665d71f1574ab01e56a5b645a0a1a82c633e984200cf35cfe361fc4100d5899d0c0893330e2d179b9354391943731035b0e74d9c6fb440d037faddbc32c32453fc988c6c3e54ded87726a8f17cc7dd224ecbb1c402b98b600f2994a237f36a314d9fb68dea6b092bd40cd722d6e48a2f9e307ec040c8c7e965e762be86cb7d1848e728653947eb581d313ab2938610203010001a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414a83405b53838c0e804f80520f79b526a333cdbc7301f0603551d230418301680141110735a6ae8e4a1007ebba869246a12fcc937b2300d06092a864886f70d01010b05000382010100161904f581b4895563897cb7173fe70327b1ae27d0268d54c4adca76c60644a265451095e2b4c41847cdd90977954d88ad62ca154b496fac098616910b7974ed548294a4437882fb006ecec096dd2c7fa0487f9b86b0e862a3d6f3d9903deb1c01a46e53f282eafe5d404d4550732d009cc8e0b3e3bf52313a7c5e160f0501d5dec7df4c2622e50e97fe4a425bef96e6f39793b7bc4e808ac576e98ce59421d1734e18a7a41cf5f99c6211eb36a29765ca19c45a64ccbffdc7277482a1761c446ab8a1ac91b9d4d5deeb299903c3d8e571b3139c36bfaa76892dede0320fbfb34dc8515f97fd7eda1c1b607eb57586bc381d5b9ce879e6e9f8d95d0008baf46a308202f9308201e10214474dd37a0dab22f2921cc510ab9b90403a812584300d06092a864886f70d01010b0500303c311e301c06035504030c15436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323134323431395a170d3336303432393134323431395a30363118301606035504030c0f436861696e204c6561662055736572310d300b060355040a0c0454657374310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100c16ae1252c4e80dc5f5b244313cc975bb8543382624488722968d50fcb5666f08516f12db9a97b8ac50704ccae2de5076ad2a27d3462bf13ac9a23eae3c44d5a20252b1a2ddd1c1ba9259d0f7562cfca8e01416a734564bd5ffa6633f1c5905a40a11d7c21767589fa709c2a6e990fa2766325133671384f041c9542a86791badd889d785fe8f55a954efb39df8e9e822d079659b69e865a08732b66ce83113917ffc67e83ce316a4223c100090ea40d0b4ee8e4ff1cf0f2a18c23f05333aabaadd7c91cdcad733fbd791ab55670b392b3c5df862c691d392bd09ab77d79d2a20f393b155b381c757ebd1a68e85a164c085220dc6d8e806173b5284fd60f36a90203010001300d06092a864886f70d01010b0500038201010076bd8147c88f223888d61f851db6d46107151de57760c098015244c3e8ab5fef48bdb30d8092f53d4bdef635d4716ed8c737f47f9ea4afa01b8de28b194dfb0320a8eaa0aa32410d044ee01ad3ee4c718d8abc231312ba1c82c88239c335a916ec3f626affa80891a833c7a9b2fe9e4090704fd935ef8f4bfd9ae0d96ace90c5436e7495ca7fe5c1291a7f89ae9c628f5c235d20a7617e72e966e97c9d9affd993c3cf1f73dc73d219b9a4500e99ea7a93e52d30eca051089d24bb1604e6c6da06a00258d6df95515b724744be3c8aa4ad9c1a21ee33cc8ce6a9b2e9615f91b5db3f973a6185b036b74163792d2986b66cfe3d4cb310e801ddc646db8da22b7b31820266308202620201013054303c311e301c06035504030c15436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b30090603550406130255530214474dd37a0dab22f2921cc510ab9b90403a812584300d06096086480165030402010500a081e4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236303530323134323432335a302f06092a864886f70d010904312204205405c54eb79ec127bb40e0cf952d0cbc7681aac6fa8fb0c3db656890867d7b32307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300d06092a864886f70d01010105000482010050e2e47755f34c26dd7e86df4329108c872f7ad15615db2c96fb197404b3e006b42606538c6209229c8d83eb9ab8e2519e6a04f544f0ab1ee170cc39e1d5ed9b6f8e04b6bdeab66638247324581533e21c3a178ee4b1a56910c9bd8645aaf538684e8b82a00438c224fa5ebd4019a77ae5fac24eb9ed99abeb7d8dfbabac70e8deabd9f79590a3276a500511413a2a8314e20638076c906904f439cec31128d252649df473bcbbcae5d17732d7b81e04f9c1edc42f139bd6b84df65fc1880586d38141a16d168d01189de5bd680cd2d0ea4205199c5545aa8c45a62ac93224cb35fe96424ded9fe1416069cb30bf298cf7d50cb036d06828e510e8b9263842e7";

// ---------------------------------------------------------------------------
// Helper: decode a hex string to bytes (panics on invalid hex)
// ---------------------------------------------------------------------------

fn from_hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "from_hex: hex string must have even length, got {}",
        s.len()
    );
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

// ---------------------------------------------------------------------------
// EC signing test fixtures
//
// Generated by:
//   openssl ecparam -name prime256v1 -genkey -noout -out ec_sign_ca_key.pem
//   openssl req -new -x509 -key ec_sign_ca_key.pem -out ec_sign_ca_cert.pem -days 3650 \
//     -subj "/CN=EC Sign CA/O=Test/C=US"
//   openssl ecparam -name prime256v1 -genkey -noout -out ec_sign_leaf_key.pem
//   openssl req -new -key ec_sign_leaf_key.pem -out ec_sign_leaf_csr.pem \
//     -subj "/CN=EC Sign User/O=Test/C=US"
//   openssl x509 -req -in ec_sign_leaf_csr.pem -CA ec_sign_ca_cert.pem \
//     -CAkey ec_sign_ca_key.pem -CAcreateserial -out ec_sign_leaf_cert.pem -days 3650
//   openssl x509 -in ec_sign_ca_cert.pem -outform DER | xxd -p | tr -d '\n'
//   openssl x509 -in ec_sign_leaf_cert.pem -outform DER | xxd -p | tr -d '\n'
//   openssl pkcs8 -topk8 -nocrypt -in ec_sign_leaf_key.pem -outform DER | xxd -p | tr -d '\n'
//
// Cert validity: notBefore=2026-05-05, notAfter=2036-05-02
// Tests use UNIX_EPOCH + 1_893_456_000 (2030-01-01), which is within the window.
// ---------------------------------------------------------------------------

/// EC P-256 CA cert DER (self-signed, /CN=EC Sign CA/O=Test/C=US).
const EC_SIGN_CA_CERT_HEX: &str = "308201b73082015da003020102021430ccd2dfcd9180793aa1112694e285216c87518c300a06082a8648ce3d04030230313113301106035504030c0a4543205369676e204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530353034323733335a170d3336303530323034323733335a30313113301106035504030c0a4543205369676e204341310d300b060355040a0c0454657374310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200048f6d700c04a89ef8c27d6201f4276ae317ffb3456bfbedbbd6cce0e6d5b7ecb2b67c4f10c59ae1a4da3f3c627927a717c635f310397578c8b8836f385fa06b18a3533051301d0603551d0e041604141768696070175e447f0a4de97819734ac403141f301f0603551d230418301680141768696070175e447f0a4de97819734ac403141f300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022015850837d4d18a19d8b868479aa07852340bf7c66c3207830d530e96eaa002dc022100942c019f9dde9ab3e3d749cba7fdeb4303e70d36608c1595629df2ef2d8b1820";

/// EC P-256 leaf cert DER (/CN=EC Sign User/O=Test/C=US, signed by EC_SIGN_CA_CERT_HEX).
const EC_SIGN_CERT_HEX: &str = "3082015e308201050214283335ff00760f1c7e8302a1978c66ff2e013dde300a06082a8648ce3d04030230313113301106035504030c0a4543205369676e204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530353034323733335a170d3336303530323034323733335a30333115301306035504030c0c4543205369676e2055736572310d300b060355040a0c0454657374310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004b869426a5b2827e5807ba8c5a15921c17d8d83979b53fe0aa14ac77d1c89518703092a61abf59fe316040a094e4e6ebcdb6f42af2b9ea196f5038a864a009fd3300a06082a8648ce3d040302034700304402202452a21cc87c54ff0ffb0c1049fa4a3a039cdd9b8ad440256863f72c47f0c96f02203b7e3bc7cab0f4ea5e8efd6bd3d13c123dfa9a18687d0fd7fc5652453bb49eb7";

/// EC P-256 private key DER (PKCS#8 unencrypted) — matches EC_SIGN_CERT_HEX above.
const EC_SIGN_KEY_PKCS8_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420456ca19f76e16c9ef15b2a6d765d4f18b6498f190bd5d2240a8a59c6268d2bb8a14403420004b869426a5b2827e5807ba8c5a15921c17d8d83979b53fe0aa14ac77d1c89518703092a61abf59fe316040a094e4e6ebcdb6f42af2b9ea196f5038a864a009fd3";

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

/// `SigningKey` backed by a P-256 ECDSA private key (SHA-256 + DER-encoded ECDSA).
struct TestEcP256SigningKey {
    signing_key: p256::ecdsa::SigningKey,
    cert: Certificate,
}

impl SigningKey for TestEcP256SigningKey {
    fn sign(&self, data: &[u8], algorithm: &DigestAlgorithm) -> Result<Vec<u8>, SmimeError> {
        match algorithm {
            DigestAlgorithm::Sha256 => {
                let prehash = Sha256::digest(data);
                let sig: p256::ecdsa::DerSignature = self
                    .signing_key
                    .sign_prehash(prehash.as_slice())
                    .map_err(|e| SmimeError::Other(format!("P-256 sign: {e}")))?;
                Ok(sig.as_bytes().to_vec())
            }
            other => Err(SmimeError::UnsupportedAlgorithm(format!(
                "TestEcP256SigningKey only supports SHA-256, got {:?}",
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
    let signed_bytes = sign(
        content_mime,
        &[&test_key as &dyn SigningKey],
        std::time::SystemTime::now(),
    )
    .expect("sign() must succeed");

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

    // Extract DER from the MIME wrapper (strip headers + base64-decode).
    let der_bytes = mime_body_to_der(&encrypted_bytes);

    // Write the encrypted DER to a temp file.
    let mut enc_file = tempfile::NamedTempFile::new().expect("create temp file");
    enc_file.write_all(&der_bytes).expect("write encrypted DER");
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

    // Use `openssl cms -decrypt` (not `smime -decrypt`) because we now emit
    // AuthEnvelopedData (AES-GCM), which the PKCS#7-based `smime` subcommand
    // does not support.
    let output = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-inform",
            "DER",
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
        "openssl cms -decrypt must exit 0; stderr: {stderr}"
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
    let signed_bytes = sign(
        content_mime,
        &[&test_key as &dyn SigningKey],
        std::time::SystemTime::now(),
    )
    .expect("sign() must succeed");

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

    // Independent oracle: verify the same signed output with OpenSSL.
    // If openssl is not installed, skip only this step — the smime-tree
    // verify above already ran unconditionally.
    if !openssl_available() {
        eprintln!(
            "SKIP openssl oracle step in test_sign_verify_roundtrip_via_mime_tree: \
             openssl not found in PATH"
        );
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let mut signed_file = tempfile::NamedTempFile::new().expect("create temp signed file");
    signed_file
        .write_all(&signed_bytes)
        .expect("write signed bytes");
    let signed_path = signed_file.path().to_path_buf();

    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&ca_cert_der)
    );
    let mut ca_file = tempfile::NamedTempFile::new().expect("create temp CA file");
    ca_file.write_all(ca_pem.as_bytes()).expect("write CA cert");
    let ca_path = ca_file.path().to_path_buf();

    // -noverify is intentionally omitted so OpenSSL validates the full chain.
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
        .expect("openssl invocation failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "openssl smime -verify must exit 0 (independent oracle); stderr: {stderr}"
    );
    assert!(
        stderr.contains("Verification successful"),
        "openssl must report 'Verification successful' (independent oracle); stderr: {stderr}"
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

// ---------------------------------------------------------------------------
// EC (P-256 / P-384) fixture constants
//
// Generated by:
//   openssl ecparam -name prime256v1 -genkey -noout -out ec256_key.pem
//   openssl req -new -key ec256_key.pem -out ec256_csr.pem -subj "/CN=EC Test User/O=Test/C=US"
//   openssl ecparam -name prime256v1 -genkey -noout -out ec256_ca_key.pem
//   openssl req -new -x509 -key ec256_ca_key.pem -out ec256_ca_cert.pem -days 3650 \
//     -subj "/CN=EC Test CA/O=Test/C=US"
//   openssl x509 -req -in ec256_csr.pem -CA ec256_ca_cert.pem -CAkey ec256_ca_key.pem \
//     -CAcreateserial -out ec256_cert.pem -days 3650
//   openssl pkcs8 -topk8 -nocrypt -in ec256_key.pem -outform DER | xxd -p | tr -d '\n'
//
//   (same pattern for secp384r1 / ec384_*)
//
// Oracle cross-check (encrypt side):
//   openssl cms -encrypt -aes-128-cbc -in p256_plain.txt -outform DER -out p256.der ec256_cert.pem
//   openssl cms -decrypt -in p256.der -inform DER -recip ec256_cert.pem -inkey ec256_key.pem
//   => "P256 plaintext"   (verified externally before committing these fixtures)
// ---------------------------------------------------------------------------

/// P-256 leaf cert DER (/CN=EC Test User/O=Test/C=US).
const EC256_CERT_HEX: &str = "3082015e30820105021470f5150810906a5ae45ce460932b47d1e33dab3a300a06082a8648ce3d04030230313113301106035504030c0a45432054657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323134323334365a170d3336303432393134323334365a30333115301306035504030c0c454320546573742055736572310d300b060355040a0c0454657374310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000474b184d83e31889a67cb2ff86b785a6cb2ff9ef7655f36595bfa66581d2af0f56b8e9c2fb298a21b369b573e9baab218e587489f8506338e1d2fadbc6ccdfea5300a06082a8648ce3d040302034700304402206d808bf4ab81df1adccc95b8bf2b5beb9f135327d322594714ca9b4421b57091022003c6edee8db49ae0219916f04bd8fbb498d944bcac63719102255bcbc252dd8d";

/// P-256 private key DER (PKCS#8 unencrypted) — matches EC256_CERT_HEX above.
const EC256_KEY_PKCS8_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104208129913fffd405d87c5ab78084faebd02d9d29179a65b99fe59759ff561b9ff0a1440342000474b184d83e31889a67cb2ff86b785a6cb2ff9ef7655f36595bfa66581d2af0f56b8e9c2fb298a21b369b573e9baab218e587489f8506338e1d2fadbc6ccdfea5";

/// P-384 leaf cert DER (/CN=EC384 Test User/O=Test/C=US).
///
/// Regenerated 2026-05-02 — the previous cert had notBefore > notAfter (structurally invalid).
/// notBefore=2026-05-02, notAfter=2036-04-29.
const EC384_CERT_HEX: &str = "308201a23082012802141b63089f14bf39f4fe13e74c88efede74833b982300a06082a8648ce3d04030230343116301406035504030c0d45433338342054657374204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303530323135313835395a170d3336303432393135313835395a30363118301606035504030c0f454333383420546573742055736572310d300b060355040a0c0454657374310b30090603550406130255533076301006072a8648ce3d020106052b8104002203620004268c977a5d67e7be6b766317388cbd1efa6aec7bfd6969127b095f7e09835f3648a2b1bd5f93a72eff6e659c45f552551e742d78a0680f07220e0eb7db268db7c640a836d3dcb7a62b960efb127d8b7e5c3af2b0beedd1ee119806bd505ef474300a06082a8648ce3d0403020368003065023100eff3b261d400d48db794346d5a702d74073c61562b00430dda15d42153874a9148ac65091bd598c7dd5d58e4c27c9a42023040874bdab44339f403a2323a1a260aa413e25baf02d921564f3efeac59e584d89f5b71a04dfe86d6847a5491e8ad9f3b";

/// P-384 private key DER (PKCS#8 unencrypted) — matches EC384_CERT_HEX above.
const EC384_KEY_PKCS8_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309c1fc92e9b0f8928b9919aea3cbdff59135b7502849ac927e3304f382e838c3a64b4f8d1dbdbd958c61a82550ce406cba16403620004268c977a5d67e7be6b766317388cbd1efa6aec7bfd6969127b095f7e09835f3648a2b1bd5f93a72eff6e659c45f552551e742d78a0680f07220e0eb7db268db7c640a836d3dcb7a62b960efb127d8b7e5c3af2b0beedd1ee119806bd505ef474";

// ---------------------------------------------------------------------------
// Helper: strip MIME headers from encrypt() output and base64-decode to DER
// ---------------------------------------------------------------------------

/// Extract the base64 body from a MIME part produced by `encrypt()`, decode
/// it, and return the raw DER bytes.  Headers end at the first `\r\n\r\n`.
fn mime_body_to_der(mime_bytes: &[u8]) -> Vec<u8> {
    let separator = b"\r\n\r\n";
    let body_start = mime_bytes
        .windows(separator.len())
        .position(|w| w == separator)
        .expect("encrypt() output must contain CRLF header/body separator")
        + separator.len();
    let b64_raw = &mime_bytes[body_start..];
    let b64_clean: Vec<u8> = b64_raw
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(&b64_clean)
        .expect("encrypt() MIME body must be valid base64")
}

// ---------------------------------------------------------------------------
// Test I: P-256 encrypt() output is decrypted by `openssl cms -decrypt`
//
// Oracle: OpenSSL recovers the original inner_mime bytes via ECDH/KARI path.
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_p256_decrypted_by_openssl() {
    if !openssl_available() {
        eprintln!("SKIP test_encrypt_p256_decrypted_by_openssl: openssl not found in PATH");
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let ec256_cert_der = from_hex(EC256_CERT_HEX);
    let cert = Certificate::from_der(&ec256_cert_der).expect("parse P-256 cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nP-256 secret from smime-tree\r\n";

    let encrypted_bytes = encrypt(inner_mime, &[cert]).expect("encrypt() must succeed for P-256");

    let der_bytes = mime_body_to_der(&encrypted_bytes);

    let mut enc_file = tempfile::NamedTempFile::new().expect("create temp file");
    enc_file.write_all(&der_bytes).expect("write encrypted DER");
    let enc_path = enc_file.path().to_path_buf();

    let ec256_key_der = from_hex(EC256_KEY_PKCS8_HEX);
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode_pem(&ec256_key_der)
    );
    let mut key_file = tempfile::NamedTempFile::new().expect("create key temp file");
    key_file.write_all(key_pem.as_bytes()).expect("write key");
    let key_path = key_file.path().to_path_buf();

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&ec256_cert_der)
    );
    let mut cert_file = tempfile::NamedTempFile::new().expect("create cert temp file");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("write cert");
    let cert_path = cert_file.path().to_path_buf();

    let output = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-inform",
            "DER",
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
        "openssl cms -decrypt must exit 0 for P-256; stderr: {stderr}"
    );
    assert_eq!(
        output.stdout.as_slice(),
        inner_mime,
        "openssl must recover the original P-256 inner_mime bytes"
    );
}

// ---------------------------------------------------------------------------
// Test J: P-384 encrypt() output is decrypted by `openssl cms -decrypt`
//
// Oracle: OpenSSL recovers the original inner_mime bytes via ECDH/KARI path.
// P-384 selects AES-256-CBC for content encryption (security-level match).
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_p384_decrypted_by_openssl() {
    if !openssl_available() {
        eprintln!("SKIP test_encrypt_p384_decrypted_by_openssl: openssl not found in PATH");
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let ec384_cert_der = from_hex(EC384_CERT_HEX);
    let cert = Certificate::from_der(&ec384_cert_der).expect("parse P-384 cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nP-384 secret from smime-tree\r\n";

    let encrypted_bytes = encrypt(inner_mime, &[cert]).expect("encrypt() must succeed for P-384");

    let der_bytes = mime_body_to_der(&encrypted_bytes);

    let mut enc_file = tempfile::NamedTempFile::new().expect("create temp file");
    enc_file.write_all(&der_bytes).expect("write encrypted DER");
    let enc_path = enc_file.path().to_path_buf();

    let ec384_key_der = from_hex(EC384_KEY_PKCS8_HEX);
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode_pem(&ec384_key_der)
    );
    let mut key_file = tempfile::NamedTempFile::new().expect("create key temp file");
    key_file.write_all(key_pem.as_bytes()).expect("write key");
    let key_path = key_file.path().to_path_buf();

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&ec384_cert_der)
    );
    let mut cert_file = tempfile::NamedTempFile::new().expect("create cert temp file");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("write cert");
    let cert_path = cert_file.path().to_path_buf();

    let output = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-inform",
            "DER",
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
        "openssl cms -decrypt must exit 0 for P-384; stderr: {stderr}"
    );
    assert_eq!(
        output.stdout.as_slice(),
        inner_mime,
        "openssl must recover the original P-384 inner_mime bytes"
    );
}

// ---------------------------------------------------------------------------
// Test K: encrypt() to P-256 cert produces a structurally valid KARI recipient
//
// A DecryptionKey that matches the P-256 cert's issuer+serial but declines to
// perform ECDH (agree_ecdh returns UnsupportedAlgorithm) is used to probe the
// KARI dispatch path.  The expected result is UnsupportedAlgorithm with a
// message containing "KARI" (specifically "KARI not supported by this key")
// — NOT a DER parse error.  This confirms:
//   (a) encrypt() emits a parseable, structurally valid KARI RecipientInfo, and
//   (b) decrypt() correctly dispatches to agree_ecdh for matching KARI entries.
// ---------------------------------------------------------------------------

/// Stub DecryptionKey that matches the P-256 cert by issuer+serial but
/// declines ECDH.  Used to probe the KARI dispatch path in decrypt().
struct StubKariKey {
    cert: Certificate,
}

impl DecryptionKey for StubKariKey {
    fn decrypt_cek(
        &self,
        _encrypted_key: &[u8],
        _algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        Err(SmimeError::UnsupportedAlgorithm(
            "StubKariKey: RSA path not applicable".into(),
        ))
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
            _ => false,
        }
    }

    fn agree_ecdh(
        &self,
        _ephemeral_public_key_bytes: &[u8],
        _ukm: Option<&[u8]>,
        _enc_cek: &[u8],
        _alg: &KariAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        Err(SmimeError::UnsupportedAlgorithm(
            "KARI not supported by this key".into(),
        ))
    }
}

#[test]
fn test_encrypt_p256_kari_structure_is_valid() {
    let ec256_cert_der = from_hex(EC256_CERT_HEX);
    let cert = Certificate::from_der(&ec256_cert_der).expect("parse P-256 cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nKARI probe\r\n";
    let encrypted_bytes =
        encrypt(inner_mime, std::slice::from_ref(&cert)).expect("encrypt() must succeed for P-256");

    let der_bytes = mime_body_to_der(&encrypted_bytes);

    let stub_key = StubKariKey { cert };
    let result = decrypt(&der_bytes, &stub_key);

    match result {
        Err(SmimeError::UnsupportedAlgorithm(msg)) => {
            assert!(
                msg.contains("KARI"),
                "UnsupportedAlgorithm message must mention KARI; got: {msg}"
            );
        }
        Err(SmimeError::Der(e)) => {
            panic!(
                "Got a DER parse error — encrypt() produced a structurally invalid \
                 KARI RecipientInfo: {e}"
            );
        }
        other => panic!("Expected UnsupportedAlgorithm from agree_ecdh stub; got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests L-M: 3-cert chain (leaf → intermediate → root trust anchor)
// ---------------------------------------------------------------------------

/// Test L: verify() succeeds when the chain is leaf → intermediate → root trust anchor.
///
/// Oracle: OpenSSL generated the signature with the leaf key; the intermediate
/// cert is in the SignedData certificate bag; the root is supplied as trust anchor.
#[test]
fn test_verify_three_cert_chain() {
    let root_der = from_hex(CHAIN_ROOT_CERT_HEX);
    let root_cert = Certificate::from_der(&root_der).expect("parse root cert");
    let sig_der = from_hex(CHAIN_SIG_HEX);

    let result = verify(
        b"Chain test content",
        &sig_der,
        &[root_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    )
    .expect("verify() must succeed for a valid 3-cert chain");

    assert!(
        result.is_verified(),
        "3-cert chain (leaf → intermediate → root) must verify; signers: {:?}",
        result.signers
    );
}

// ---------------------------------------------------------------------------
// Test N: Python-generated P-256 KARI oracle decrypted correctly by agree_ecdh
//
// Oracle: Python pyca/cryptography builds a CMS EnvelopedData with
// KARI P-256 / dhSinglePass-stdDH-sha256kdf-scheme / AES-128-KW / AES-128-CBC.
// The fixture is deterministic (fixed ephemeral key, CEK, IV).
// Our decrypt() dispatches to agree_ecdh, exercising the full KARI path.
//
// Generated with (smime-tree/tests/gen_kari_oracle.py):
//   python3 gen_kari_oracle.py  # deterministic; seed = "smime-tree-test-kari-p256-oracle"
//
// Oracle cross-check:
//   openssl cms -decrypt -inform DER -in py_kari.der \
//     -recip ec256_cert.pem -inkey ec256_key.pem
//   => "Oracle P-256 KARI plaintext"  (verified before committing)
//
// Note: `openssl cms -encrypt` uses dhSinglePass-stdDH-sha1kdf-scheme by default,
// which our decrypt() does not support.  The Python oracle uses SHA-256 KDF,
// matching what our encrypt() emits and what RFC 5753 §7.1.4 specifies.
// ---------------------------------------------------------------------------

/// CMS EnvelopedData DER built by Python pyca/cryptography (KARI P-256, AES-128-CBC).
const KARI_P256_ORACLE_DER_HEX: &str = "3082014a06092a864886f70d010703a082013b308201370201023181e3a181e0020103a05ba159301306072a8648ce3d020106082a8648ce3d03010703420004569e4197d13155472f77ddab2ce6eb56fb6486ed95b3c8561500110836b0d2509b2afdaa4f7d931a987102c7af3ba1688acdfe9141a671999e0661a8f1051505301506062b8104010b01300b060960864801650304010530673065304930313113301106035504030c0a45432054657374204341310d300b060355040a0c0454657374310b3009060355040613025553021470f5150810906a5ae45ce460932b47d1e33dab3a04182f1b43eb1daefe5fd377e7b2589905d1db4ea3a4e3e9e51c304c06092a864886f70d010701301d060960864801650304010204100102030405060708090a0b0c0d0e0f108020174cafb427c57278614c85e200e540e35baf3d6e3406aed2619470d8806dcd9a";

/// `agree_ecdh` implementation backed by a static P-256 private key.
///
/// Performs ECDH, X9.63 KDF (SHA-256), and AES-128-KW unwrap.
/// Used in Test N to exercise the full KARI decrypt path end-to-end.
struct TestEcP256DecryptionKey {
    secret_key: p256::SecretKey,
    cert: Certificate,
}

impl DecryptionKey for TestEcP256DecryptionKey {
    fn decrypt_cek(
        &self,
        _encrypted_key: &[u8],
        _algorithm: &KeyEncryptionAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        Err(SmimeError::UnsupportedAlgorithm(
            "TestEcP256DecryptionKey: RSA path not applicable".into(),
        ))
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
            _ => false,
        }
    }

    fn agree_ecdh(
        &self,
        ephemeral_public_key_bytes: &[u8],
        ukm: Option<&[u8]>,
        enc_cek: &[u8],
        alg: &KariAlgorithm,
    ) -> Result<Vec<u8>, SmimeError> {
        // Step 1: parse the sender's ephemeral public key.
        let eph_pub = p256::PublicKey::from_sec1_bytes(ephemeral_public_key_bytes)
            .map_err(|e| SmimeError::Other(format!("ephemeral key parse: {e}")))?;

        // Step 2: ECDH — static private key × ephemeral public key → shared secret Z.
        let shared = elliptic_curve::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            eph_pub.as_affine(),
        );
        let z = shared.raw_secret_bytes();

        // Step 3: X9.63 KDF with EccCmsSharedInfo (RFC 5753 §7.2).
        // This test only handles StdDhSha256Kdf (P-256) with no UKM.
        if !matches!(alg.key_agreement, KariKeyAgreement::StdDhSha256Kdf) {
            return Err(SmimeError::UnsupportedAlgorithm(
                "TestEcP256DecryptionKey only supports StdDhSha256Kdf".into(),
            ));
        }
        if ukm.is_some() {
            return Err(SmimeError::UnsupportedAlgorithm(
                "TestEcP256DecryptionKey does not support UKM".into(),
            ));
        }
        // EccCmsSharedInfo DER for id-aes128-Wrap (2.16.840.1.101.3.4.1.5), 128-bit key, no UKM:
        //   SEQUENCE { AlgorithmIdentifier { id-aes128-Wrap }, [2] EXPLICIT OCTET STRING(0x00000080) }
        const AES128_SHARED_INFO: &[u8] = &[
            0x30, 0x15, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
            0x05, 0xa2, 0x06, 0x04, 0x04, 0x00, 0x00, 0x00, 0x80,
        ];
        let mut kek = [0u8; 16];
        ansi_x963_kdf::derive_key_into::<sha2::Sha256>(z.as_ref(), AES128_SHARED_INFO, &mut kek)
            .map_err(|_| SmimeError::Other("X9.63 KDF failed".into()))?;

        // Step 4: AES-128-KW unwrap → raw CEK.
        use aes_kw::cipher::KeyInit as _;
        let unwrapper = aes_kw::KwAes128::new(&kek.into());
        let mut cek =
            vec![
                0u8;
                enc_cek
                    .len()
                    .checked_sub(8)
                    .ok_or_else(|| SmimeError::Other("enc_cek too short for AES-KW".into()))?
            ];
        unwrapper
            .unwrap_key(enc_cek, &mut cek)
            .map_err(|e| SmimeError::Other(format!("AES-128-KW unwrap: {e}")))?;

        Ok(cek)
    }
}

/// Test N: OpenSSL-encrypted P-256 KARI oracle.
///
/// OpenSSL encrypts to the EC256 cert; our decrypt() exercises the full KARI
/// path (ECDH → X9.63 KDF → AES-128-KW unwrap → AES-128-CBC content decrypt).
/// This is the reverse direction of Tests I and J, which proved our encryption
/// can be decrypted by OpenSSL.
#[test]
fn test_decrypt_openssl_kari_p256() {
    let ec256_cert_der = from_hex(EC256_CERT_HEX);
    let cert = Certificate::from_der(&ec256_cert_der).expect("parse P-256 cert");

    let ec256_key_der = from_hex(EC256_KEY_PKCS8_HEX);
    let secret_key =
        p256::SecretKey::from_pkcs8_der(&ec256_key_der).expect("parse P-256 private key");

    let key = TestEcP256DecryptionKey { secret_key, cert };

    let enveloped_der = from_hex(KARI_P256_ORACLE_DER_HEX);
    let plaintext = decrypt(&enveloped_der, &key).expect("decrypt() must succeed for P-256 KARI");

    assert_eq!(
        plaintext, b"Oracle P-256 KARI plaintext",
        "decrypted P-256 KARI must match oracle plaintext"
    );
}

// ---------------------------------------------------------------------------
// Tests O-Q: negative tests for tampered cryptographic inputs
//
// These tests verify that the library rejects tampered inputs rather than
// silently returning incorrect results.  Each test flips one byte in the
// middle of a cryptographic payload and asserts that the operation fails.
//
// All three use the same OpenSSL-generated fixtures as the happy-path tests
// (no new fixture generation needed).
// ---------------------------------------------------------------------------

/// Test O: verify() rejects a tampered signature blob.
///
/// One byte in the middle of the DER-encoded CMS SignedData is flipped.
/// The signature bytes no longer match the signed attributes, so RSA
/// signature verification must fail → AllSignersFailed.
#[test]
fn test_verify_tampered_sig_bytes() {
    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_cert = Certificate::from_der(&ca_cert_der).expect("parse CA cert");

    let mut sig_der = from_hex(SIG_RSA_DER_HEX);

    // Flip one byte near the end of the DER blob where the RSA signature value
    // lives.  The last ~256 bytes of a 2048-bit RSA SignedData are the
    // signature octets; flipping anywhere in that region corrupts the signature
    // without touching the DER framing that wraps it.
    let flip_pos = sig_der.len() - 64;
    sig_der[flip_pos] ^= 0xff;

    let result = verify(
        b"Test message content",
        &sig_der,
        &[ca_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(_)) => {}
        Ok(vr) if !vr.is_verified() => {}
        Ok(vr) => panic!(
            "expected verification failure for tampered sig_bytes, got Ok with verified=true; \
             signers: {:?}",
            vr.signers
        ),
        Err(e) => {
            panic!("expected AllSignersFailed for tampered sig_bytes, got other error: {e:?}")
        }
    }
}

/// Test P: verify() rejects unmodified sig_bytes when the signed content is tampered.
///
/// The signed content bytes are changed (one byte flipped) while the original
/// DER signature blob is kept intact.  The SHA-256 digest of the modified
/// content no longer matches the messageDigest signed attribute, so the
/// message-digest check must fail → AllSignersFailed.
#[test]
fn test_verify_tampered_content() {
    let ca_cert_der = from_hex(CA_CERT_HEX);
    let ca_cert = Certificate::from_der(&ca_cert_der).expect("parse CA cert");

    let sig_der = from_hex(SIG_RSA_DER_HEX);

    // Original signed content was b"Test message content".
    // Flip the first byte to produce different content with a different digest.
    let mut tampered_content = b"Test message content".to_vec();
    tampered_content[0] ^= 0x01;

    let result = verify(
        &tampered_content,
        &sig_der,
        &[ca_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(_)) => {}
        Ok(vr) if !vr.is_verified() => {}
        Ok(vr) => panic!(
            "expected verification failure for tampered content, got Ok with verified=true; \
             signers: {:?}",
            vr.signers
        ),
        Err(e) => panic!("expected AllSignersFailed for tampered content, got other error: {e:?}"),
    }
}

/// Test Q: decrypt() returns an error when the ciphertext is tampered.
///
/// One byte near the end of the DER-encoded EnvelopedData is flipped,
/// corrupting the AES-128-CBC ciphertext.  PKCS#7 unpadding must fail,
/// returning an Err.  The exact variant is not asserted — any error is
/// acceptable; the important property is that Ok is not returned.
#[test]
fn test_decrypt_tampered_ciphertext() {
    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let private_key = RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");

    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let key = TestRsaDecryptionKey { private_key, cert };

    let mut encrypted_der = from_hex(ENCRYPTED_RSA_DER_HEX);

    // The AES-128-CBC ciphertext is in the last ~32 bytes of the EnvelopedData.
    // Flipping a byte there corrupts the PKCS#7 padding block, causing
    // unpadding to fail without touching any DER framing.
    let flip_pos = encrypted_der.len() - 8;
    encrypted_der[flip_pos] ^= 0xff;

    let result = decrypt(&encrypted_der, &key);

    assert!(
        result.is_err(),
        "decrypt() must return Err for tampered ciphertext, but returned Ok"
    );
}

/// Test M: verify() fails when the supplied trust anchor does not anchor the chain.
///
/// The leaf cert is passed as the trust anchor instead of the root.  The chain
/// walker cannot build a path from the leaf's issuer (the intermediate) to the
/// leaf-as-trust-anchor, so the verification must fail with AllSignersFailed
/// carrying a chain error (issuer / trust anchor / cycle / signature).
#[test]
fn test_verify_three_cert_chain_fails_without_intermediate() {
    let leaf_der = from_hex(CHAIN_LEAF_CERT_HEX);
    let leaf_cert = Certificate::from_der(&leaf_der).expect("parse leaf cert");
    let sig_der = from_hex(CHAIN_SIG_HEX);

    let result = verify(
        b"Chain test content",
        &sig_der,
        &[leaf_cert], // wrong trust anchor — leaf cannot sign intermediate
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    );

    match result {
        Err(SmimeError::AllSignersFailed(signers)) => {
            let error_str = signers[0].error.as_deref().unwrap_or("");
            assert!(
                error_str.contains("issuer")
                    || error_str.contains("trust anchor")
                    || error_str.contains("cycle")
                    || error_str.contains("signature"),
                "expected chain error, got: {error_str}"
            );
        }
        other => panic!("expected AllSignersFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test P384: verify() succeeds with a 3-cert P-384 chain (SHA-384 CA sigs).
//
// This test exercises pkix-chain's P-384 signature verification support
// (ECDSA P-384 + SHA-384, OID 1.2.840.10045.4.3.3) in the CA certificate
// chain. Prior to pkix-path 0.3.1 this would fail with
// CertChainError::SignatureVerification.
//
// Oracle: OpenSSL (all certs and SignedData generated with openssl 3.x):
//   openssl ecparam -name secp384r1 -genkey → root, intermediate, leaf keys
//   openssl req -new -x509 -sha384 → self-signed root
//   openssl x509 -req -sha384 → intermediate signed by root, leaf by intermediate
//   openssl smime -sign -md sha384 → SignedData with leaf + intermediate in bag
//   openssl smime -verify -CAfile root_cert.pem → "Verification successful"
//   openssl verify -CAfile root -untrusted int leaf → leaf.pem: OK
// ---------------------------------------------------------------------------

/// P-384 root CA cert DER (self-signed with ecdsa-with-SHA384).
const P384_CHAIN_ROOT_CERT_HEX: &str = "308202153082019aa00302010202146bc528e9e1227fb1ced1de568af2e57f2e40f9d8300a06082a8648ce3d0403033039311b301906035504030c125033383420436861696e20526f6f74204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303630343232353433315a170d3336303630313232353433315a3039311b301906035504030c125033383420436861696e20526f6f74204341310d300b060355040a0c0454657374310b30090603550406130255533076301006072a8648ce3d020106052b81040022036200044165161199790fc40112704226d4e43cc0ca8061a199014cb34564987e4e1b0f5f6f1fa874355897a27ee962904fa67d4e865462f7412d81048a436216a0979e2139d140b55b10906b796ac26cafcb5322fa7dc3d733cd90c7f0064d1d9b276ca3633061301d0603551d0e04160414b10db2e80d27d7b8a15d5219b949cbf4fe0e8d49301f0603551d23041830168014b10db2e80d27d7b8a15d5219b949cbf4fe0e8d49300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d04030303690030660231009c5c30d9225221887c94e3493446f62e63d30f33e69e46d9ec8553a73d02c1acc8130215034758814f0eb10d7414606c023100e9a318a617e8207f1d166d0234f3382126b074a6179de0b668f99a5074351bf4e4db02a15988d8dac817a7259a9b18b2";

/// CMS SignedData DER: P-384 leaf key signs "P384 chain test content" (SHA-384 digest).
/// Certificate bag contains intermediate CA + leaf cert. Root is the trust anchor.
///
/// Oracle cross-check: SHA-384("P384 chain test content") ==
///   6875d4ce44716697707dec7229420e3226c480c0efd8c61d26236860fa903355
///   ed500b7f308c1d82463c82ef7e94a2c5
/// which matches the messageDigest signed attribute in this blob.
const P384_CHAIN_SIG_HEX: &str = "308205f006092a864886f70d010702a08205e1308205dd020101310f300d06096086480165030402020500300b06092a864886f70d010701a08203d63082021b308201a2a00302010202144a722d15b05e9f715f25cdd0c24f6a5821f0a69d300a06082a8648ce3d0403033039311b301906035504030c125033383420436861696e20526f6f74204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303630343232353433315a170d3336303630313232353433315a30413123302106035504030c1a5033383420436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b30090603550406130255533076301006072a8648ce3d020106052b8104002203620004f4f3cd699ace6fd22fab209f984cfef2ffe2ed4919d875dd098bd7f01c2df2518371ec7d1f7ed5182255e6668c0c14b10f1a3b1a4938dcf803b699b5b77a1ab3c8db3fa9ea0af652e4d78b7c685f742ba9615759bf84980a7b8edb54778cc557a3633061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e04160414c7e8d2b0919c3239074886fc1eb36572fdf83549301f0603551d23041830168014b10db2e80d27d7b8a15d5219b949cbf4fe0e8d49300a06082a8648ce3d040303036700306402304b3092f021dd031583de44ddbd8c3c496abdd566ce6d961830721274927693c402a4482d5c51a1205cd57bc99b5f48ad02307678d031e93a1ed9bf9a477159d5c8d5d6e98a2fa9d4fa4b4deca0d5971468146fc0882c03112625f475464b117ff39f308201b33082013a021472f3194749a09320476e77f1d2e72f398269775b300a06082a8648ce3d04030330413123302106035504030c1a5033383420436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b3009060355040613025553301e170d3236303630343232353433315a170d3336303630313232353433315a303b311d301b06035504030c145033383420436861696e204c6561662055736572310d300b060355040a0c0454657374310b30090603550406130255533076301006072a8648ce3d020106052b81040022036200047728b469ceadfe66016ceb81361fb3eabcd002713af1887b5b5030c4b18780fc2623f338afa46881e4b53e772370647f9b8f285a21b44ca2518d20b36d8afe448ff4057b00728c8c8d766857ba75ab0490cb7dbc20b4dbc15d31e1af2c637c32300a06082a8648ce3d040303036700306402300279858e45a8a164443423dcdd1d5dba137d8179b0413558a4bdb9a2ec7c62d8fd8060c7b743f323b0c3cb73b871f1040230463043cc9a43000230482aeaba934e36535bafbcbe8418bea884d344265eb6d133c5da44ff6677f6fd97e3cd29da5d55318201de308201da020101305930413123302106035504030c1a5033383420436861696e20496e7465726d656469617465204341310d300b060355040a0c0454657374310b3009060355040613025553021472f3194749a09320476e77f1d2e72f398269775b300d06096086480165030402020500a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236303630343232353433375a303f06092a864886f70d010904313204306875d4ce44716697707dec7229420e3226c480c0efd8c61d26236860fa903355ed500b7f308c1d82463c82ef7e94a2c5307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d04030304683066023100e9c0e50003dc4c4eed4c72975f1e94dd5970a5057f3ce5501f03a27fce2ac0b96f703dd44f77189e8e77f979fc4b6f87023100c0eec972c47e74e7b12944fed83305e0693029e83f67bdaaf916fa4d1067cbdff836f6310ec2931fde57c1e7ee38d60e";

/// Test P384: verify() succeeds with a 3-cert P-384/SHA-384 chain.
///
/// The root, intermediate, and leaf certificates all use ECDSA P-384 keys
/// with SHA-384 signatures (OID 1.2.840.10045.4.3.3). This exercises
/// pkix-path's `EcdsaP384Verifier` during chain validation.
#[test]
fn test_verify_p384_chain() {
    let root_der = from_hex(P384_CHAIN_ROOT_CERT_HEX);
    let root_cert = Certificate::from_der(&root_der).expect("parse P-384 root cert");
    let sig_der = from_hex(P384_CHAIN_SIG_HEX);

    let result = verify(
        b"P384 chain test content",
        &sig_der,
        &[root_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    )
    .expect("verify() must succeed for a valid P-384/SHA-384 3-cert chain");

    assert!(
        result.is_verified(),
        "P-384/SHA-384 chain (leaf -> intermediate -> root) must verify; signers: {:?}",
        result.signers
    );
}

// ---------------------------------------------------------------------------
// Tests R-T: multi-signer tests
//
// These tests exercise sign() with two keys (RSA + P-256 ECDSA).
// Fixture key/cert pairs:
//   RSA: RSA_KEY_PKCS8_HEX / RSA_CERT_HEX, CA trust anchor: CA_CERT_HEX
//   P-256: EC_SIGN_KEY_PKCS8_HEX / EC_SIGN_CERT_HEX, CA: EC_SIGN_CA_CERT_HEX
// Both CAs are supplied as trust anchors to verify().
// ---------------------------------------------------------------------------

/// Test R: sign() with two keys produces a SignedData with two verified signers.
///
/// Oracle: verify() with both trust anchors returns two SignerResults both
/// with verified=true, and is_verified() == true.  Optionally, openssl smime
/// -verify is used as an independent oracle if openssl is available.
#[test]
fn test_sign_multi_signer_two_keys() {
    use base64::Engine as _;

    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let rsa_private_key =
        RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");
    let rsa_signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private_key);
    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let rsa_cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");
    let rsa_key = TestRsaSigningKey {
        private_key: rsa_signing_key,
        cert: rsa_cert,
    };

    let ec_key_der = from_hex(EC_SIGN_KEY_PKCS8_HEX);
    let ec_secret_key =
        p256::SecretKey::from_pkcs8_der(&ec_key_der).expect("parse EC P-256 private key");
    let ec_signing_key = p256::ecdsa::SigningKey::from(ec_secret_key);
    let ec_cert_der = from_hex(EC_SIGN_CERT_HEX);
    let ec_cert = Certificate::from_der(&ec_cert_der).expect("parse EC P-256 cert");
    let ec_key = TestEcP256SigningKey {
        signing_key: ec_signing_key,
        cert: ec_cert,
    };

    let content_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nHello multi-signer\r\n";
    let signed_bytes = sign(
        content_mime,
        &[&rsa_key as &dyn SigningKey, &ec_key as &dyn SigningKey],
        std::time::SystemTime::now(),
    )
    .expect("sign() must succeed with two keys");

    // Parse the multipart/signed output with mime-tree.
    let parsed =
        mime_tree::parse(&signed_bytes).expect("mime_tree::parse must succeed on sign() output");

    let part1 = parsed
        .part_index
        .find_by_id("1")
        .expect("part '1' (signed content) must exist");
    let content_start = part1.header_range.0 as usize;
    let content_end = (part1.body_range.0 + part1.body_range.1) as usize;
    let extracted_content = &signed_bytes[content_start..content_end];

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

    // Both trust anchors: RSA CA and EC signing CA.
    let rsa_ca_cert = Certificate::from_der(&from_hex(CA_CERT_HEX)).expect("parse RSA CA cert");
    let ec_ca_cert =
        Certificate::from_der(&from_hex(EC_SIGN_CA_CERT_HEX)).expect("parse EC CA cert");

    let result = verify(
        extracted_content,
        &signature_der,
        &[rsa_ca_cert, ec_ca_cert],
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        &NoRevocationCheck,
    )
    .expect("verify() must not return a parse error");

    assert_eq!(
        result.signers.len(),
        2,
        "multi-signer SignedData must have exactly two SignerResults; got: {:?}",
        result.signers
    );
    assert!(
        result.signers[0].verified,
        "first signer must verify; result: {:?}",
        result.signers[0]
    );
    assert!(
        result.signers[1].verified,
        "second signer must verify; result: {:?}",
        result.signers[1]
    );
    assert!(
        result.is_verified(),
        "is_verified() must be true for multi-signer SignedData; signers: {:?}",
        result.signers
    );

    // Independent oracle: verify with openssl smime if available.
    if !openssl_available() {
        eprintln!(
            "SKIP openssl oracle in test_sign_multi_signer_two_keys: openssl not found in PATH"
        );
        return;
    }

    use std::io::Write;
    use std::process::Command;

    let mut signed_file = tempfile::NamedTempFile::new().expect("create temp signed file");
    signed_file
        .write_all(&signed_bytes)
        .expect("write signed bytes");
    let signed_path = signed_file.path().to_path_buf();

    // Write both CA certs to a combined PEM trust bundle.
    let rsa_ca_der = from_hex(CA_CERT_HEX);
    let ec_ca_der = from_hex(EC_SIGN_CA_CERT_HEX);
    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode_pem(&rsa_ca_der),
        base64_encode_pem(&ec_ca_der),
    );
    let mut ca_file = tempfile::NamedTempFile::new().expect("create temp CA file");
    ca_file
        .write_all(ca_pem.as_bytes())
        .expect("write CA certs");
    let ca_path = ca_file.path().to_path_buf();

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
        .expect("openssl invocation failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "openssl smime -verify must exit 0 for multi-signer output; stderr: {stderr}"
    );
    assert!(
        stderr.contains("Verification successful"),
        "openssl must report 'Verification successful' for multi-signer; stderr: {stderr}"
    );
}

/// Test S: two-key sign() produces SignedData.version == V1.
///
/// Both keys use IssuerAndSerialNumber (default), so per RFC 5652 §5.1 the
/// SignedData version must be V1.  The version is parsed from the DER blob
/// produced by sign() — not inferred from the API output.
#[test]
fn test_sign_multi_signer_version_v1() {
    use base64::Engine as _;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::SignedData;

    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let rsa_private_key =
        RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");
    let rsa_signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private_key);
    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let rsa_cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");
    let rsa_key = TestRsaSigningKey {
        private_key: rsa_signing_key,
        cert: rsa_cert,
    };

    let ec_key_der = from_hex(EC_SIGN_KEY_PKCS8_HEX);
    let ec_secret_key =
        p256::SecretKey::from_pkcs8_der(&ec_key_der).expect("parse EC P-256 private key");
    let ec_signing_key = p256::ecdsa::SigningKey::from(ec_secret_key);
    let ec_cert_der = from_hex(EC_SIGN_CERT_HEX);
    let ec_cert = Certificate::from_der(&ec_cert_der).expect("parse EC P-256 cert");
    let ec_key = TestEcP256SigningKey {
        signing_key: ec_signing_key,
        cert: ec_cert,
    };

    let content_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nHello multi-signer\r\n";
    let signed_bytes = sign(
        content_mime,
        &[&rsa_key as &dyn SigningKey, &ec_key as &dyn SigningKey],
        std::time::SystemTime::now(),
    )
    .expect("sign() must succeed with two keys");

    // Extract the pkcs7-signature part (part "2") and base64-decode to DER.
    let parsed =
        mime_tree::parse(&signed_bytes).expect("mime_tree::parse must succeed on sign() output");
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

    // Parse ContentInfo → SignedData and check version.
    let ci = ContentInfo::from_der(&signature_der).expect("parse ContentInfo from DER");
    let content_der = ci.content.to_der().expect("re-encode SignedData content");
    let sd = SignedData::from_der(&content_der).expect("parse SignedData from DER");

    assert_eq!(
        sd.version,
        CmsVersion::V1,
        "SignedData.version must be V1 when all signers use IssuerAndSerialNumber"
    );
}

/// Test T: sign() with an empty key slice returns MalformedInput.
///
/// RFC 5652 §5.1 requires at least one SignerInfo.  sign() must reject an
/// empty key list rather than producing a structurally invalid SignedData.
#[test]
fn test_sign_empty_keys_returns_error() {
    let result = sign(b"content", &[], std::time::SystemTime::now());
    match result {
        Err(SmimeError::MalformedInput(_)) => {}
        other => {
            panic!("expected Err(SmimeError::MalformedInput(_)) for empty keys, got: {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// Test U: AES-GCM encrypt → decrypt roundtrip (RSA recipient)
//
// encrypt() now produces AuthEnvelopedData (AES-GCM).  This test encrypts
// to the RSA cert and then decrypts with the matching RSA private key.
// No OpenSSL dependency — pure in-process roundtrip.
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_decrypt_gcm_roundtrip_rsa() {
    let rsa_cert_der = from_hex(RSA_CERT_HEX);
    let cert = Certificate::from_der(&rsa_cert_der).expect("parse RSA cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nGCM roundtrip test\r\n";

    let encrypted_bytes =
        encrypt(inner_mime, std::slice::from_ref(&cert)).expect("encrypt() must succeed");

    // Verify the MIME Content-Type uses authEnveloped-data.
    let mime_str = std::str::from_utf8(&encrypted_bytes).expect("MIME output must be UTF-8");
    assert!(
        mime_str.contains("smime-type=authEnveloped-data"),
        "encrypt() output must use smime-type=authEnveloped-data; got: {}",
        mime_str.lines().take(4).collect::<Vec<_>>().join("\n")
    );

    // Extract DER from the MIME wrapper.
    let der_bytes = mime_body_to_der(&encrypted_bytes);

    // Decrypt using the RSA private key.
    let rsa_key_der = from_hex(RSA_KEY_PKCS8_HEX);
    let private_key = RsaPrivateKey::from_pkcs8_der(&rsa_key_der).expect("parse RSA private key");
    let key = TestRsaDecryptionKey { private_key, cert };

    let plaintext = decrypt(&der_bytes, &key).expect("decrypt() must succeed for GCM roundtrip");
    assert_eq!(
        plaintext, inner_mime,
        "GCM roundtrip: decrypted plaintext must match original"
    );
}

// ---------------------------------------------------------------------------
// Test V: AES-GCM encrypt → decrypt roundtrip (P-256 KARI recipient)
// ---------------------------------------------------------------------------

#[test]
fn test_encrypt_decrypt_gcm_roundtrip_p256() {
    let ec256_cert_der = from_hex(EC256_CERT_HEX);
    let cert = Certificate::from_der(&ec256_cert_der).expect("parse P-256 cert");

    let inner_mime: &[u8] = b"Content-Type: text/plain\r\n\r\nGCM P-256 roundtrip\r\n";

    let encrypted_bytes =
        encrypt(inner_mime, std::slice::from_ref(&cert)).expect("encrypt() must succeed");

    let der_bytes = mime_body_to_der(&encrypted_bytes);

    // Decrypt using the P-256 private key.
    let ec256_key_der = from_hex(EC256_KEY_PKCS8_HEX);
    let secret_key =
        p256::SecretKey::from_pkcs8_der(&ec256_key_der).expect("parse P-256 private key");
    let key = TestEcP256DecryptionKey { secret_key, cert };

    let plaintext =
        decrypt(&der_bytes, &key).expect("decrypt() must succeed for GCM P-256 roundtrip");
    assert_eq!(
        plaintext, inner_mime,
        "GCM P-256 roundtrip: decrypted plaintext must match original"
    );
}

// ===========================================================================
// Regression tests (maintenance 2026-11)
//
// All fixtures below were generated with OpenSSL 3.0 by this script
// (run in an empty directory; `rsa.pem`/`rsa.key` and `ec256.pem`/`ec256.key`
// are RSA_CERT_HEX/RSA_KEY_PKCS8_HEX and EC256_CERT_HEX/EC256_KEY_PKCS8_HEX
// converted to PEM):
//
//   printf 'Content-Type: text/plain\r\n\r\nsmime-tree regression\r\n' > msg.txt
//   openssl ecparam -name secp384r1 -genkey -noout -out ca.key
//   openssl req -new -x509 -key ca.key -sha384 -days 3650 -subj "/CN=Regress P384 CA" \
//     -addext basicConstraints=critical,CA:TRUE \
//     -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem
//   leaf() { # name curve issuing-md extension-lines...
//     n=$1 curve=$2 md=$3; shift 3
//     openssl ecparam -name $curve -genkey -noout -out $n.key
//     openssl req -new -key $n.key -subj "/CN=Regress $n" -out $n.csr
//     printf '%s\n' "$@" > $n.ext
//     openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -$md \
//       -days 3650 -extfile $n.ext -out $n.pem
//   }
//   SM="keyUsage=critical,digitalSignature"; EM="extendedKeyUsage=emailProtection"
//   leaf l384s256 secp384r1 sha256 "$SM" "$EM"
//   leaf l384s384 secp384r1 sha384 "$SM" "$EM"
//   leaf l256s384 prime256v1 sha384 "$SM" "$EM"
//   leaf tls secp384r1 sha384 "keyUsage=critical,keyEncipherment" \
//     "extendedKeyUsage=serverAuth" "basicConstraints=CA:FALSE"
//   leaf ekuserver secp384r1 sha384 "$SM" "extendedKeyUsage=serverAuth"
//   leaf kuenc secp384r1 sha384 "keyUsage=critical,keyAgreement"
//   leaf nronly secp384r1 sha384 "keyUsage=critical,nonRepudiation" "$EM"
//   leaf anyeku secp384r1 sha384 "$SM" "extendedKeyUsage=anyExtendedKeyUsage"
//   sig() { openssl cms -sign -binary -in msg.txt -signer $2.pem -inkey $2.key \
//             -md $3 -outform DER -out $1.der; }
//   sig s_l384s256_md256 l384s256 sha256    sig s_l384s384_md256 l384s384 sha256
//   sig s_l384s256_md384 l384s256 sha384    sig s_l384s384_md512 l384s384 sha512
//   sig s_l256s384_md384 l256s384 sha384    sig s_tls tls sha384
//   sig s_ekuserver ekuserver sha384        sig s_kuenc kuenc sha384
//   sig s_nronly nronly sha384              sig s_anyeku anyeku sha384
//   openssl ecparam -name prime256v1 -genkey -noout -out ss.key
//   openssl req -new -x509 -key ss.key -days 3650 -subj "/CN=Regress self-signed" -out ss.pem
//   sig s_ss ss sha256
//   printf 'OpenSSL KARI plaintext\r\n' > kari_msg.txt
//   openssl cms -encrypt -binary -aes-128-cbc -in kari_msg.txt -recip ec256.pem \
//     -keyopt ecdh_kdf_md:sha256 -outform DER -out enc_kari.der
//   printf 'GCM KTRI plaintext\r\n' > gcm_msg.txt
//   openssl cms -encrypt -binary -aes-128-gcm -in gcm_msg.txt -recip rsa.pem \
//     -outform DER -out enc_gcm_rsa.der
//   openssl x509 -in rsa.pem -pubkey -noout > rsa_pub.pem
//   head -c 15 /dev/zero | tr '\0' A > cek15.bin; head -c 16 /dev/zero | tr '\0' A > cek16.bin
//   openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -pkeyopt rsa_padding_mode:pkcs1 \
//     -in cek15.bin -out ek15.bin       # likewise cek16.bin -> ek16.bin
//
// Oracle results (`openssl cms -verify -binary -inform DER -in X.der -content msg.txt
// -CAfile ca.pem`, or `-CAfile ss.pem` for s_ss):
//   "Verification successful": s_l384s256_md256, s_l384s384_md256, s_l384s256_md384,
//                              s_l384s384_md512, s_l256s384_md384, s_nronly, s_ss
//   "unsuitable certificate purpose": s_tls, s_ekuserver, s_kuenc, s_anyeku
// s_anyeku is the one deliberate divergence: OpenSSL 3.0 does not treat
// anyExtendedKeyUsage as permitting S/MIME, but RFC 8550 §4.4.4 says receiving
// agents MUST accept id-kp-emailProtection *or* anyExtendedKeyUsage; for that
// case the RFC text is the oracle.
// `openssl cms -decrypt` recovers the plaintexts of enc_kari.der and enc_gcm_rsa.der,
// and `openssl pkeyutl -decrypt -inkey rsa.key -in ek15.bin` yields the 15 bytes.
//
// Certificates are valid 2026-11-20 .. 2036-11-17; tests use 2030-01-01.
// ===========================================================================

/// P-384 root CA `/CN=Regress P384 CA` (self-signed, ecdsa-with-SHA384).
const REGRESS_P384_CA_CERT_HEX: &str = "308201d63082015ca00302010202146c181cb2892a0a84e608bff702cbe7e2d59ce05a300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301a3118301606035504030c0f5265677265737320503338342043413076301006072a8648ce3d020106052b810400220362000440ee267a2b6e518f68fbfbbe45e91c675797f4e72c79ea826f01caffbf9d98e273e969d38ecd320acb309673db74c73719760d9c9e093c04e2ec7fae2c42bd53d93769fa0d15ba899bbf95b938e902f807d14b930468b672676ff2984c47d195a3633061301d0603551d0e04160414c1ea03e27d7ff202f16c14e1a2dcef28709457f2301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030368003065023100abbeb04cc89759e093d7897a6864b9d3103223c945674359ae761224d60c2adf4129467a79211155e68436c6925a31080230658fcf962f4ba4f4d40781e6a2e263731aacee8a6f13625a30ddd2dbc229dbf75ebe3cc8b232014d41bdc45d83ecab78";

/// P-384 signer, message signature ecdsa-with-SHA256; leaf issued with ecdsa-with-SHA256.
const SIG_P384_LEAF256_MD256_HEX: &str = "308203bc06092a864886f70d010702a08203ad308203a9020101310d300b0609608648016503040201300b06092a864886f70d010701a08201df308201db30820161a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e176d300a06082a8648ce3d040302301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301b3119301706035504030c1052656772657373206c333834733235363076301006072a8648ce3d020106052b81040022036200042a99a09bbd22ab0da44ac463b91c3f50545f8f4dbcf558314e8d109b5a654a78cf4926cb573bdabd699846c1e798efd9aa9c450985f474af428b8f85f43406c23077b301400dc21d872210e128fbfbd6561e90ae8f7794bc3aa14894f513e44aa3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070304301d0603551d0e04160414670e577afcf873886a8925f872710da318c00ec0301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d040302036800306502306ad81f5e7e7811e548b5ea91da0a85294666cf56a19291ee2a49b72fc45d564d737a3a7476f6a852abc313561ad152380231009a477be37494faa32917de9e36c0f665043ce8e53bc3e00d9c89b1355c4211c9425129b6d3f78dbc521941022f04a0e2318201a33082019f0201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e176d300b0609608648016503040201a081e4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a302f06092a864886f70d01090431220420a30bc77910364a1f240bd2a04e8f46cd621f984bf1e5679360444184548575e2307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d0403020466306402303727597f745096b94a5be3b2590f342195b54f5002bc08c9c59acc357e241c6cf08eebcdd1f5057f6f3e7b4827d5c9d102303090ab8796a98fe0ab8ed3f5c6651743a8c1fbc4249e0a516ff6b4a331ab8527c8c632bb5bd37f91a3e4420d1576ba06";

/// P-384 signer, message signature ecdsa-with-SHA256; leaf issued with ecdsa-with-SHA384.
const SIG_P384_LEAF384_MD256_HEX: &str = "308203bc06092a864886f70d010702a08203ad308203a9020101310d300b0609608648016503040201300b06092a864886f70d010701a08201df308201db30820161a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e176e300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301b3119301706035504030c1052656772657373206c333834733338343076301006072a8648ce3d020106052b81040022036200048515e3f91d4c235a28c237187a30212403fa882fc5eb0132342d1b87473438a8aeeaffb8ba7d4abcf40d5bcf5179090ce1a67439ee805f71628a2baac3fcde8c92b6d98277d6974058486ebecdd0b23db5796a09fea39e999b557f8f103490bea3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070304301d0603551d0e0416041412f97ec6254fa4c09292d9a8ea8cd3011ee0e649301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030368003065023100ab9a64d87392024b47051d9790168a847ad4a08126d8d06898ac9e831ad04f607f30e0b063cc8236407179cda65d4c09023037fca038c175fcfa330e7c715bcb7bdaf32fb3baa5056f7714d13aa4fef093398248cf6e53a6ca80119c8b2fa9e8b25d318201a33082019f0201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e176e300b0609608648016503040201a081e4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a302f06092a864886f70d01090431220420a30bc77910364a1f240bd2a04e8f46cd621f984bf1e5679360444184548575e2307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d04030204663064023036018d6e380c5be2f1d43806838d12f972ef66bf674ad375ac0cbd3b19e927071a9bdd84e137a8965f7f7e79beb8914302306f419aa2d9a2f60b274a3d20aa0d47ebba7a01ac9f28dcc01daa15194f690f33449db1601400e11900debab07f79f499";

/// P-384 signer, message signature ecdsa-with-SHA384; leaf issued with ecdsa-with-SHA256.
const SIG_P384_LEAF256_MD384_HEX: &str = "308203cd06092a864886f70d010702a08203be308203ba020101310d300b0609608648016503040202300b06092a864886f70d010701a08201df308201db30820161a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e176d300a06082a8648ce3d040302301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301b3119301706035504030c1052656772657373206c333834733235363076301006072a8648ce3d020106052b81040022036200042a99a09bbd22ab0da44ac463b91c3f50545f8f4dbcf558314e8d109b5a654a78cf4926cb573bdabd699846c1e798efd9aa9c450985f474af428b8f85f43406c23077b301400dc21d872210e128fbfbd6561e90ae8f7794bc3aa14894f513e44aa3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070304301d0603551d0e04160414670e577afcf873886a8925f872710da318c00ec0301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d040302036800306502306ad81f5e7e7811e548b5ea91da0a85294666cf56a19291ee2a49b72fc45d564d737a3a7476f6a852abc313561ad152380231009a477be37494faa32917de9e36c0f665043ce8e53bc3e00d9c89b1355c4211c9425129b6d3f78dbc521941022f04a0e2318201b4308201b00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e176d300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d040303046730650231009ba967d6c7b8a56e681382a5436ea6fe896c9d26aa63981f04f9929ed59d591e25a222dad5e04e26ace9b8670385fc24023076f217be804a81805b1c30ab560944f52e5345dada3feb3f85f490483382596dc9239f7f32ec95f8cb22a646e9537ba4";

/// P-384 signer, message signature ecdsa-with-SHA512; leaf issued with ecdsa-with-SHA384.
const SIG_P384_LEAF384_MD512_HEX: &str = "308203dd06092a864886f70d010702a08203ce308203ca020101310d300b0609608648016503040203300b06092a864886f70d010701a08201df308201db30820161a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e176e300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301b3119301706035504030c1052656772657373206c333834733338343076301006072a8648ce3d020106052b81040022036200048515e3f91d4c235a28c237187a30212403fa882fc5eb0132342d1b87473438a8aeeaffb8ba7d4abcf40d5bcf5179090ce1a67439ee805f71628a2baac3fcde8c92b6d98277d6974058486ebecdd0b23db5796a09fea39e999b557f8f103490bea3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070304301d0603551d0e0416041412f97ec6254fa4c09292d9a8ea8cd3011ee0e649301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030368003065023100ab9a64d87392024b47051d9790168a847ad4a08126d8d06898ac9e831ad04f607f30e0b063cc8236407179cda65d4c09023037fca038c175fcfa330e7c715bcb7bdaf32fb3baa5056f7714d13aa4fef093398248cf6e53a6ca80119c8b2fa9e8b25d318201c4308201c00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e176e300b0609608648016503040203a0820104301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a304f06092a864886f70d01090431420440da8be49bfc81cb9db0efeeea17e0c032c568f41c599eee496c17afd7e79052c68333784dd4baff0c491ff96b74b2a639f5aee65d9d1fc583111d66ead4667d9e307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d040304046630640230485da81b430dc8225abcb9f04a35c220aae9ab98d98ceca3b0cdacf2e9d38543e50019aa98d72730bb0ec2872e8211bf0230122865d118d49d6e93f6fd369c25c5e9450d0e832d8fea51ea7c320aaebc798a9a1e371594b44dc038bf2c7e98812a5e";

/// P-256 signer, message signature ecdsa-with-SHA384; leaf issued by the P-384 CA with ecdsa-with-SHA384.
const SIG_P256_LEAF384_MD384_HEX: &str = "3082039106092a864886f70d010702a08203823082037e020101310d300b0609608648016503040202300b06092a864886f70d010701a08201c3308201bf30820144a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e176f300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a301b3119301706035504030c1052656772657373206c323536733338343059301306072a8648ce3d020106082a8648ce3d03010703420004d52de3e4a58d055343eb3792517b9c927bd64f6d383cf6aa215cbd174deb449f738acac57a79261db26e02fc55edadc06e3246df241e67d0b22b06015e21c5c0a3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070304301d0603551d0e04160414db198a9c893af2976b7e751fac503904a66ae1a0301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030369003066023100942d436261a6518f2226088dce1ef81375cd86f38b5d861283cd623db2c5c4c37e1dc9daa562fb0534fd00f05d2a4c8a023100b9b438e27dbda4eccca5a02d30d23c1b4208f01c2aac201140143c77bc66f53326ec29a1b00c1028584c6cccc18dcada31820194308201900201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e176f300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d0403030447304502202cd39d30a2a6bf0452440ed76dd013de27145c05ce2d572c7f0936865c734ca4022100b39138d4c45ef61992bbe12e3de702798e6b8386a638fc4c4576f2d1f9f0e5d4";

/// Signer cert: keyUsage=keyEncipherment, extKeyUsage=serverAuth, cA=FALSE.
const SIG_PURPOSE_TLS_HEX: &str = "308203d306092a864886f70d010702a08203c4308203c0020101310d300b0609608648016503040202300b06092a864886f70d010701a08201e5308201e130820167a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1770300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030385a170d3336313131373036323030385a30163114301206035504030c0b5265677265737320746c733076301006072a8648ce3d020106052b81040022036200044725aa72706baa25f3f3e4d72b487909b89561eac9d47a97de03cbef912d93bbb649e0817575eb71be24208736e32a7e294a9e5d130ac2a68e86e502c6e6cb59c84709cd72f0dcaf91e08007f11e95cf7d000d3e68f62e6a6a99efd133a3a609a3723070300e0603551d0f0101ff04040302052030130603551d25040c300a06082b0601050507030130090603551d1304023000301d0603551d0e041604149c50399d12862d0e068f423f31bdfb17d1738190301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030368003065023100e8a20ab00a1710b3f0d3ff1f6c84922bb98c57251e66b2ab7bafb50d4bbef601eb82f4d864d78b2f7a5b026a8b495d27023044588e5c7aa1674a2243f429a30e71cd6186f8312111050e257fd7145f82f3d44b09c1c0119841b559a0cd8951292fbb318201b4308201b00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e1770300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d040303046730650230360ee9b4a35173c42762d711f8516b29ca7d0ceacb350539f7513665ca7e55255372b2dfe344c6991cacd73f35d0b6f2023100bec903220a8027416963baba32ce7f1ec32b985e5200da43f52105e797abcb8d7a3b61ca7f6aa2907c0474054eb22d38";

/// Signer cert: keyUsage=digitalSignature, extKeyUsage=serverAuth.
const SIG_PURPOSE_EKU_SERVER_HEX: &str = "308203cf06092a864886f70d010702a08203c0308203bc020101310d300b0609608648016503040202300b06092a864886f70d010701a08201e0308201dc30820162a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1771300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030395a170d3336313131373036323030395a301c311a301806035504030c115265677265737320656b757365727665723076301006072a8648ce3d020106052b81040022036200047d3292fa228b6871249b677aee4bc43cefd44bb9d9ebbc342625f7641002678e55deb59ca604873c6de34f84169885a7f58ee334c7215436b8650b6df7d5ce52ef6c949674d6a8dcf3d0638a8e7e218d757d3ab8beea53d9db3c76b9f59f0cc8a3673065300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301301d0603551d0e041604142cc72b626f67538fc4e89e424da296335bc964d2301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d040303036800306502307dc8436644a15c82da171121a9d94b40c02a4ad854da75696c1562a87a2300fc04399ffc20c97f7c8149ef90b46e867f023100d656c648f9894d3b76cf10ba3393960eac59115458f0c8b2d4dba8e08fa5979f0c248fd16f43e57f1c211354d3b6c415318201b5308201b10201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e1771300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d04030304683066023100ee3b8ec10cd0f35efdd2e38caa36a9a9456f7a667adec9f611141c367cccba41fc4251d31d3774c3b62c3b5cbb9026e60231008edcb6ba9eb9c20223b1029f0ee896c003d44ea115582b181913926750fd5d473361d40d36e0647649a03cad8124adc4";

/// Signer cert: keyUsage=keyAgreement, no extKeyUsage.
const SIG_PURPOSE_KU_AGREE_HEX: &str = "308203b606092a864886f70d010702a08203a7308203a3020101310d300b0609608648016503040202300b06092a864886f70d010701a08201c8308201c430820149a00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1772300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323030395a170d3336313131373036323030395a30183116301406035504030c0d52656772657373206b75656e633076301006072a8648ce3d020106052b810400220362000447711781e388aad257d7498f8306641fd9d80ab80a9e8785bbc496a0c1dbc17f57b6d69a2fdd77f555bc15e1b9227438cae777977dfee480db7a8a746aef63f38162426d57f19813c9d2e821841417c1f012468b64d92515476098f8c839ba81a3523050300e0603551d0f0101ff040403020308301d0603551d0e041604141188671cd9d63a61119c17bab65e9314fcccf81d301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030369003066023100f9545066759ce67020ad39023b56e884db02c93c75bbe3059417781538384a7cea913bea10d1bf293d1aae17492a0f46023100867bfbb262ba754b516f7f21a1581ef5a046c19f33820e004ddc7b8a8f628a5d92fe2c1a1f2b23bec01e1e6481ae77e6318201b4308201b00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e1772300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d040303046730650231009946d40e553e79664543495edd59a6609ef00f4cae8a07dcfb3d3590048d7ddc6cebd65ca4df37c2403fd93610521fca02301fb3d6b5580bcd98756e7f5a26d9db504df34bfafeaf8819ee8d5e1ad1bb63160bbb337815c49891a70f6aa4221e2e6b";

/// Signer cert: keyUsage=nonRepudiation, extKeyUsage=emailProtection.
const SIG_PURPOSE_NR_ONLY_HEX: &str = "308203ca06092a864886f70d010702a08203bb308203b7020101310d300b0609608648016503040202300b06092a864886f70d010701a08201dc308201d83082015fa00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1774300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323032365a170d3336313131373036323032365a30193117301506035504030c0e52656772657373206e726f6e6c793076301006072a8648ce3d020106052b8104002203620004a2a0a8280fb65333cb37e3729e9c74d9199ba3bc38b3767f7970cb4cfb3767a35c624d77c2501bccb24c9086b7cdaecee91b9e728568988a43d9ef176b66691ede483e7c417eb4361d873e659999b8c18e76e6b418b12359237a69779c95aed7a3673065300e0603551d0f0101ff04040302064030130603551d25040c300a06082b06010505070304301d0603551d0e04160414928fbc8a5c1e1a0f2842b9e4ce048835fe7ae7d8301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d040303036700306402301be61ce56aaabd220677c3e3710823ab8939d237831d5cc40025e057dc92ddf29b6cd67cc1cef017dba1f1f907395ee502305f3b084840437aa9d32c78577f469683fc739b3de845f179b891e5ff37999d62af32a10163defe6b162d607dc69c0116318201b4308201b00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e1774300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323032365a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d040303046730650231009a52e8792aeb3f42d1d976a5ec01f1f2d98ddb360f36411a90f082534a2b92b33f5b445ec41eea005a5c8754e6cd2fda023056d2c7ad329b5714fccf7a6104f4d35d2de91e296c427379a414ad80e8be3953aeb30832c99c35ba54a5fda7e7537385";

/// Signer cert: keyUsage=digitalSignature, extKeyUsage=anyExtendedKeyUsage.
const SIG_PURPOSE_ANY_EKU_HEX: &str = "308203c706092a864886f70d010702a08203b8308203b4020101310d300b0609608648016503040202300b06092a864886f70d010701a08201d9308201d53082015ba00302010202147b219f40db40f21e2f4507fe59a3ff52fa6e1775300a06082a8648ce3d040303301a3118301606035504030c0f526567726573732050333834204341301e170d3236313132303036323032365a170d3336313131373036323032365a30193117301506035504030c0e5265677265737320616e79656b753076301006072a8648ce3d020106052b8104002203620004b2b9936b38496463e7b36b05436470d4909ec4b587da3f6712856d2d0f8b06996e0d12a879884130571cc8b08828c73312493bf1cbb91d5bad106f05043dbc3cae21ce4ed506769a6a8b2f5421ecf95cb8d831ae4a2873bc582c0590fc1a34f8a3633061300e0603551d0f0101ff040403020780300f0603551d25040830060604551d2500301d0603551d0e04160414321fcb5374600b1bc07bc2970ed925795458dbe3301f0603551d23041830168014c1ea03e27d7ff202f16c14e1a2dcef28709457f2300a06082a8648ce3d0403030368003065023100901dfdaa4d0ac8bc0dd6b1b58460ffe78eec116f831f1027f307bd9257808ec25c62f29541167800716d0705c9657bc0023041a3cd498366b849d72755081ea0bd233970e236c19d36f56e5d249ca219c73ad1b41c4f029543f33fa8c668e5716148318201b4308201b00201013032301a3118301606035504030c0f52656772657373205033383420434102147b219f40db40f21e2f4507fe59a3ff52fa6e1775300b0609608648016503040202a081f4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323032365a303f06092a864886f70d0109043132043041fcef076d6b8497c9c474af2dbfdb2860552d7fce94164688822fa2f7a449c507f90804e36c07f5559d692959e1e3d4307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d0403030467306502303e595a1d62ed1032b7fc10ee46e117de7c44fc848f668c9cf2f500d29c795acb29d1ec97fc4b7b9c1fd4858da334775f0231008c799554019d6963810e1976d4a1d7907d44a43575b49808c31f6438e516cd4548088a2594b8cd2991eda5c1cdd5a1ab";

/// Self-signed P-256 cert `/CN=Regress self-signed` with basicConstraints cA=TRUE (`openssl req -x509` default).
const SELF_SIGNED_CA_SIGNER_CERT_HEX: &str = "3082019230820137a003020102021458ffc62309d6849553d1b4246d297696995ecd43300a06082a8648ce3d040302301e311c301a06035504030c13526567726573732073656c662d7369676e6564301e170d3236313132303036323030395a170d3336313131373036323030395a301e311c301a06035504030c13526567726573732073656c662d7369676e65643059301306072a8648ce3d020106082a8648ce3d030107034200043c979b8c3a624c879bffca2ef331be7051ad5eebcbbeb658f0e4827d830f96d0999e544d261591a10cd6202d377b8f5a078bf0d9646be95cb8dbf3117ec01487a3533051301d0603551d0e04160414942b38be6e06db358793387b1408f1653041ccd5301f0603551d23041830168014942b38be6e06db358793387b1408f1653041ccd5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100a05863f5271a438cfed20e93dff35a405b5983e2a066489468c9ba6f649148ce02210090e974cd35d3760daa61a32900258401d539c46719fdb922373b9c31a1e5359e";

/// Signed by the self-signed cA=TRUE certificate above (SHA-256).
const SIG_SELF_SIGNED_CA_SIGNER_HEX: &str = "3082035806092a864886f70d010702a082034930820345020101310d300b0609608648016503040201300b06092a864886f70d010701a08201963082019230820137a003020102021458ffc62309d6849553d1b4246d297696995ecd43300a06082a8648ce3d040302301e311c301a06035504030c13526567726573732073656c662d7369676e6564301e170d3236313132303036323030395a170d3336313131373036323030395a301e311c301a06035504030c13526567726573732073656c662d7369676e65643059301306072a8648ce3d020106082a8648ce3d030107034200043c979b8c3a624c879bffca2ef331be7051ad5eebcbbeb658f0e4827d830f96d0999e544d261591a10cd6202d377b8f5a078bf0d9646be95cb8dbf3117ec01487a3533051301d0603551d0e04160414942b38be6e06db358793387b1408f1653041ccd5301f0603551d23041830168014942b38be6e06db358793387b1408f1653041ccd5300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100a05863f5271a438cfed20e93dff35a405b5983e2a066489468c9ba6f649148ce02210090e974cd35d3760daa61a32900258401d539c46719fdb922373b9c31a1e5359e31820188308201840201013036301e311c301a06035504030c13526567726573732073656c662d7369676e6564021458ffc62309d6849553d1b4246d297696995ecd43300b0609608648016503040201a081e4301806092a864886f70d010903310b06092a864886f70d010701301c06092a864886f70d010905310f170d3236313132303036323030395a302f06092a864886f70d01090431220420a30bc77910364a1f240bd2a04e8f46cd621f984bf1e5679360444184548575e2307906092a864886f70d01090f316c306a300b060960864801650304012a300b0609608648016503040116300b0609608648016503040102300a06082a864886f70d0307300e06082a864886f70d030202020080300d06082a864886f70d0302020140300706052b0e030207300d06082a864886f70d0302020128300a06082a8648ce3d0403020447304502200b7d588a72ee2443ad136f3d7fd5ddda373189220a64c0b27095d741a836912e022100995b1f0f3bb9700c75000eca4e861e278cf10939aee31f63cbe15a5d51d4b024";

/// OpenSSL KARI EnvelopedData to EC256_CERT (originator id-ecPublicKey parameters absent).
const KARI_OPENSSL_P256_DER_HEX: &str = "3082014006092a864886f70d010703a08201313082012d0201023181d9a181d6020103a051a14f300906072a8648ce3d0201034200041602582029538b65df65e19302e4acd97d0879ff416a5214c2778f97539449112fec6c07693868dee0e940256a9f199b60712be2561d500f38f4e9d64e5a59c5301506062b8104010b01300b060960864801650304010530673065304930313113301106035504030c0a45432054657374204341310d300b060355040a0c0454657374310b3009060355040613025553021470f5150810906a5ae45ce460932b47d1e33dab3a0418712407cd92f222c43d5b2b9630933bf1a206ea76ed5f9601304c06092a864886f70d010701301d060960864801650304010204106e5e4fab2a0dcbaf2996ce020d9ac1d680209e798a1271b2f82dc96c162e1819c6a951fd0c13dfdef2015282f366f1e8d1d8";

/// OpenSSL AuthEnvelopedData (AES-128-GCM) to RSA_CERT via KTRI.
const ENCRYPTED_RSA_GCM_DER_HEX: &str = "308201d3060b2a864886f70d0109100117a08201c2308201be020100318201623082015e0201003046302e3110300e06035504030c0754657374204341310d300b060355040a0c0454657374310b30090603550406130255530214583180b4a0db0f23bf5f2cbc7cae324024ee0c8d300d06092a864886f70d010101050004820100b77e13c4ef0ec9488b7017ccf904695f03ba56b4ef9d69e7d5bda2273d5a1b67ef088c08548919bfff489bcaef85384e75719fc0d43187dab3b482e4e4d8b8b6926d3010f144f8cfaf3ab25a6afda60e3e71a86c913be1fc1b426f1728066055e5726ea2de7c84092bf5dbf8311b23bbcbdf9f75adf5352c7d8cf8dbafafe61ea0fdc66ca28aec626b771d3ddf580960c554c0acce495abd0155367b1dc1fb5c0cf4d1a25153ecdc6632606de063c6745ce225385df552e11fb49c4011029a83f008e1ec68b8ad0458aa51ef10f22cafaaf5c4d8ea6924f42b8ad44c18f0755e060b3c80e9a9efcce271d059637d250574a6ed41e139408aa11ae1bc02d2b333304106092a864886f70d010701301e06096086480165030401063011040cc461c5dc10ad12cb65edddb00201108014fdeee85a3302e11382faa55bf29a4a85681b014f0410fa623107bfc9610a6813831b94814447";

/// PKCS#1 v1.5 encryption under RSA_CERT of 15 bytes of 0x41.
const RSA_PKCS1_CEK15_HEX: &str = "6f819d12080803d163079697aacc4f508945868cf7256025ef01488f40d2c485d5edde9f2593f43e0bbb74421819c90019acd35e9dcbbc699ad20ac0e66451c24e00524770f1b9a5cd1eeaa1bf61a4c83bd6786bc21857fc29fb032b3b869a393d648cf76042e1dd0a900ea369b1ef1f9e58e28a6a846ce727520873f36e5c1eac7215ab19e6aa43c934786e6821595a6603d4c497ba5809085ea05177538854b99c41642e35c5c3ad559001ba660525e5ae223d2cc524024fe8bf8bb92c43a49757fd331732749553ce3a9268ef819093d5a2dc3e5c2300e62c538afa67460b5ced3c1a1694228db2a49072ea6407b63906a6a8df00616f1824305e596cce31";

/// PKCS#1 v1.5 encryption under RSA_CERT of 16 bytes of 0x41.
const RSA_PKCS1_CEK16_HEX: &str = "196a677aa6c60d4ac9ba0a6a27b7a491df892c1fb26a565082eeb42965da3def08f07f2a9a0c6bcfd3850380232cb1a52271f132a05a77626e7654be4aef8cb1fa9c46ea70543df96972640398029669bb69c9015959b591ac3e094fbf7a311c3d2ffada1cba27c5f7cc4634aa9e84912509d574eb555f7f3042be186d90a479dc6b6d007a2f8553dfb2270c71dddfb071e8fcf682c7189d4c0ea83adddfe00f57eb783d565eb0a9ef29e95ae816d2fed79c305b733b2d5d133d94ed21b258226bd24c0eac8d7d083ceb38c9325210d017871721c8f313e2ecf4b3eaade9e2285c957a2f119c45fff2cdff1e7591de36edf64e97a75473c12f3137037c365db2";

/// Regression message content signed by every `SIG_*` fixture in this section.
const REGRESS_MSG: &[u8] = b"Content-Type: text/plain\r\n\r\nsmime-tree regression\r\n";

/// 2030-01-01T00:00:00Z — inside every regression fixture's validity period.
fn regress_now() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000)
}

fn regress_ca() -> Certificate {
    Certificate::from_der(&from_hex(REGRESS_P384_CA_CERT_HEX)).expect("parse regression CA")
}

/// Verify a regression fixture against the P-384 CA and return the single
/// signer's error string (`None` if it verified).
fn regress_verify_error(sig_hex: &str) -> Option<String> {
    match verify(
        REGRESS_MSG,
        &from_hex(sig_hex),
        &[regress_ca()],
        regress_now(),
        &NoRevocationCheck,
    ) {
        Ok(r) => {
            assert!(r.all_verified(), "Ok result must mean verified: {r:?}");
            None
        }
        Err(SmimeError::AllSignersFailed(signers)) => {
            assert_eq!(signers.len(), 1);
            Some(signers[0].error.clone().unwrap_or_default())
        }
        Err(e) => panic!("unexpected top-level error: {e}"),
    }
}

// --- ECDSA curve is taken from the key, not the signature OID ---------------

/// P-384 signer with OpenSSL's default `ecdsa-with-SHA256`, on a leaf that the
/// P-384 CA also issued with `ecdsa-with-SHA256`.  OpenSSL: verifies.
#[test]
fn test_regress_p384_key_sha256_message_and_chain() {
    assert_eq!(regress_verify_error(SIG_P384_LEAF256_MD256_HEX), None);
}

/// Message signature: P-384 key, `ecdsa-with-SHA256`; chain uses SHA-384.
/// Isolates the SignerInfo signature path.  OpenSSL: verifies.
#[test]
fn test_regress_p384_key_sha256_message_signature() {
    assert_eq!(regress_verify_error(SIG_P384_LEAF384_MD256_HEX), None);
}

/// Chain: leaf issued by the P-384 CA with `ecdsa-with-SHA256`; the message
/// signature uses SHA-384.  Isolates the certificate-chain path.
/// OpenSSL: verifies.
#[test]
fn test_regress_p384_issuer_sha256_certificate_signature() {
    assert_eq!(regress_verify_error(SIG_P384_LEAF256_MD384_HEX), None);
}

/// P-384 key with `ecdsa-with-SHA512` (digest longer than the curve order).
/// OpenSSL: verifies.
#[test]
fn test_regress_p384_key_sha512_message_signature() {
    assert_eq!(regress_verify_error(SIG_P384_LEAF384_MD512_HEX), None);
}

/// P-256 key with `ecdsa-with-SHA384` (digest truncated to 256 bits).
/// OpenSSL: verifies.
#[test]
fn test_regress_p256_key_sha384_message_signature() {
    assert_eq!(regress_verify_error(SIG_P256_LEAF384_MD384_HEX), None);
}

/// A curve/hash mix-up must not turn into acceptance of a wrong signature:
/// verifying the SHA-512 fixture against different content must fail.
#[test]
fn test_regress_p384_sha512_wrong_content_rejected() {
    let r = verify(
        b"different content",
        &from_hex(SIG_P384_LEAF384_MD512_HEX),
        &[regress_ca()],
        regress_now(),
        &NoRevocationCheck,
    );
    assert!(matches!(r, Err(SmimeError::AllSignersFailed(_))), "{r:?}");
}

// --- Signer certificate purpose (RFC 8550 §4.4) ----------------------------

fn assert_unsuitable(sig_hex: &str, reason_fragment: &str) {
    let err = regress_verify_error(sig_hex).expect("OpenSSL rejects this signer; so must we");
    assert!(
        err.contains("not usable for S/MIME signing") && err.contains(reason_fragment),
        "expected UnsuitableSignerCertificate mentioning {reason_fragment:?}, got: {err}"
    );
}

/// TLS server certificate (keyEncipherment / serverAuth).  OpenSSL:
/// "unsuitable certificate purpose".
#[test]
fn test_regress_tls_server_cert_rejected_as_signer() {
    assert_unsuitable(SIG_PURPOSE_TLS_HEX, "keyUsage");
}

/// keyUsage=digitalSignature but extKeyUsage=serverAuth only.  OpenSSL:
/// "unsuitable certificate purpose".
#[test]
fn test_regress_server_auth_eku_rejected_as_signer() {
    assert_unsuitable(SIG_PURPOSE_EKU_SERVER_HEX, "extKeyUsage");
}

/// keyUsage=keyAgreement, no extKeyUsage.  OpenSSL: "unsuitable certificate
/// purpose".
#[test]
fn test_regress_key_agreement_only_ku_rejected_as_signer() {
    assert_unsuitable(SIG_PURPOSE_KU_AGREE_HEX, "keyUsage");
}

/// keyUsage=nonRepudiation alone is sufficient.  OpenSSL: verifies.
#[test]
fn test_regress_non_repudiation_only_signer_accepted() {
    assert_eq!(regress_verify_error(SIG_PURPOSE_NR_ONLY_HEX), None);
}

/// extKeyUsage=anyExtendedKeyUsage is accepted.  Oracle: RFC 8550 §4.4.4
/// ("MUST check that it contains either the id-kp-emailProtection OID or the
/// anyExtendedKeyUsage OID"); OpenSSL 3.0 is stricter here (see the section
/// header).
#[test]
fn test_regress_any_eku_signer_accepted() {
    assert_eq!(regress_verify_error(SIG_PURPOSE_ANY_EKU_HEX), None);
}

/// A self-signed signer certificate with basicConstraints cA=TRUE and no
/// keyUsage, anchored by itself, still verifies.  OpenSSL: verifies (also
/// with `-purpose smimesign`).
#[test]
fn test_regress_self_signed_ca_flag_signer_accepted() {
    let anchor = Certificate::from_der(&from_hex(SELF_SIGNED_CA_SIGNER_CERT_HEX))
        .expect("parse self-signed cert");
    let r = verify(
        REGRESS_MSG,
        &from_hex(SIG_SELF_SIGNED_CA_SIGNER_HEX),
        &[anchor],
        regress_now(),
        &NoRevocationCheck,
    )
    .expect("self-signed cA=TRUE signer must verify");
    assert!(r.all_verified());
}

// --- KARI originator key without curve parameters -------------------------

/// OpenSSL encodes the KARI originator key as id-ecPublicKey with *absent*
/// parameters (permitted by RFC 5753 §3.1.1).  decrypt() must accept it.
/// Oracle: `openssl cms -decrypt` recovers "OpenSSL KARI plaintext\r\n".
#[test]
fn test_regress_decrypt_openssl_kari_absent_curve_params() {
    let cert = Certificate::from_der(&from_hex(EC256_CERT_HEX)).expect("parse P-256 cert");
    let secret_key =
        p256::SecretKey::from_pkcs8_der(&from_hex(EC256_KEY_PKCS8_HEX)).expect("parse P-256 key");
    let key = TestEcP256DecryptionKey { secret_key, cert };
    let plaintext = decrypt(&from_hex(KARI_OPENSSL_P256_DER_HEX), &key)
        .expect("decrypt() must accept an OpenSSL KARI with absent curve parameters");
    assert_eq!(plaintext, b"OpenSSL KARI plaintext\r\n");
}

// --- KTRI: CEK-length failures are indistinguishable from wrong CEKs --------

/// Replace the KTRI `encryptedKey` of `enveloped_der` with `new_ek`.
fn replace_ktri_encrypted_key(enveloped_der: &[u8], new_ek: &[u8]) -> Vec<u8> {
    let ci = cms::content_info::ContentInfo::from_der(enveloped_der).expect("ContentInfo");
    let inner = ci.content.to_der().expect("re-encode content");
    let recip_infos = if ci.content_type == const_oid::db::rfc5911::ID_CT_AUTH_ENVELOPED_DATA {
        cms::authenveloped_data::AuthEnvelopedData::from_der(&inner)
            .expect("AuthEnvelopedData")
            .recip_infos
    } else {
        cms::enveloped_data::EnvelopedData::from_der(&inner)
            .expect("EnvelopedData")
            .recip_infos
    };
    let old_ek = recip_infos
        .0
        .iter()
        .find_map(|ri| match ri {
            cms::enveloped_data::RecipientInfo::Ktri(k) => Some(k.enc_key.as_bytes().to_vec()),
            _ => None,
        })
        .expect("fixture has a KTRI");
    assert_eq!(
        old_ek.len(),
        new_ek.len(),
        "replacement must keep the DER lengths"
    );
    let pos = enveloped_der
        .windows(old_ek.len())
        .position(|w| w == old_ek.as_slice())
        .expect("encryptedKey bytes present");
    let mut out = enveloped_der.to_vec();
    out[pos..pos + new_ek.len()].copy_from_slice(new_ek);
    out
}

fn rsa_test_key() -> TestRsaDecryptionKey {
    TestRsaDecryptionKey {
        private_key: RsaPrivateKey::from_pkcs8_der(&from_hex(RSA_KEY_PKCS8_HEX))
            .expect("parse RSA key"),
        cert: Certificate::from_der(&from_hex(RSA_CERT_HEX)).expect("parse RSA cert"),
    }
}

/// A validly padded PKCS#1 v1.5 block holding a 15-byte "CEK" must produce
/// exactly the same error as one holding a wrong 16-byte CEK and as a
/// corrupted (badly padded) block, for both the AES-128-CBC EnvelopedData and
/// the AES-128-GCM AuthEnvelopedData path.  Fixtures: OpenSSL `cms -encrypt`
/// and `pkeyutl -encrypt` (see section header).
#[test]
fn test_regress_ktri_cek_length_error_matches_wrong_key_error() {
    let key = rsa_test_key();
    for (label, fixture_hex) in [
        ("AES-128-CBC", ENCRYPTED_RSA_DER_HEX),
        ("AES-128-GCM", ENCRYPTED_RSA_GCM_DER_HEX),
    ] {
        let fixture = from_hex(fixture_hex);
        let wrong_len = replace_ktri_encrypted_key(&fixture, &from_hex(RSA_PKCS1_CEK15_HEX));
        let wrong_key = replace_ktri_encrypted_key(&fixture, &from_hex(RSA_PKCS1_CEK16_HEX));
        let mut bad_pad_ek = from_hex(RSA_PKCS1_CEK16_HEX);
        bad_pad_ek[10] ^= 0x01;
        let bad_padding = replace_ktri_encrypted_key(&fixture, &bad_pad_ek);

        let e_len = decrypt(&wrong_len, &key).expect_err("15-byte CEK must fail");
        let e_key = decrypt(&wrong_key, &key).expect_err("wrong 16-byte CEK must fail");
        let e_pad = decrypt(&bad_padding, &key).expect_err("bad PKCS#1 padding must fail");
        assert!(
            matches!(e_key, SmimeError::DecryptionFailed(_)),
            "{label}: {e_key:?}"
        );
        assert_eq!(e_len, e_key, "{label}: wrong-length vs wrong-key CEK");
        assert_eq!(e_pad, e_key, "{label}: bad padding vs wrong-key CEK");
        assert_eq!(e_len.to_string(), e_key.to_string(), "{label}: Display");
    }
}

/// `DecryptionKey` stub that returns a fixed result from `decrypt_cek` and
/// claims every recipient.
struct FixedCekKey(Result<Vec<u8>, SmimeError>);

impl DecryptionKey for FixedCekKey {
    fn decrypt_cek(&self, _: &[u8], _: &KeyEncryptionAlgorithm) -> Result<Vec<u8>, SmimeError> {
        self.0.clone()
    }
    fn matches_recipient(&self, _: &RecipientIdentifier) -> bool {
        true
    }
}

/// Every ciphertext-dependent `decrypt_cek` failure (and every CEK length)
/// collapses into one error; UnsupportedAlgorithm and RngFailure, which
/// describe the key rather than the ciphertext, pass through.
#[test]
fn test_regress_ktri_decrypt_cek_errors_are_uniform() {
    let cbc = from_hex(ENCRYPTED_RSA_DER_HEX);
    let gcm = from_hex(ENCRYPTED_RSA_GCM_DER_HEX);
    let reference = decrypt(&cbc, &FixedCekKey(Ok(vec![0x41; 16]))).expect_err("wrong CEK");
    assert!(matches!(reference, SmimeError::DecryptionFailed(_)));
    let uniform = [
        Ok(vec![]),
        Ok(vec![0x41; 15]),
        Ok(vec![0x41; 17]),
        Ok(vec![0x41; 32]),
        Err(SmimeError::DecryptionFailed("PKCS#1 padding error".into())),
        Err(SmimeError::Other("decryption error".into())),
        Err(SmimeError::MalformedInput("bad block".into())),
    ];
    for r in uniform {
        for (label, der) in [("CBC", &cbc), ("GCM", &gcm)] {
            let e = decrypt(der, &FixedCekKey(r.clone())).expect_err("must fail");
            assert_eq!(e, reference, "{label}: decrypt_cek -> {r:?}");
        }
    }
    for e in [
        SmimeError::UnsupportedAlgorithm("no OAEP".into()),
        SmimeError::RngFailure("rng".into()),
    ] {
        let got = decrypt(&cbc, &FixedCekKey(Err(e.clone()))).expect_err("must fail");
        assert_eq!(got, e);
    }
}
