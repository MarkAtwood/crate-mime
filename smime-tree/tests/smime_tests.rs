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
        s.len() % 2 == 0,
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
    let signed_bytes =
        sign(content_mime, &test_key, std::time::SystemTime::now()).expect("sign() must succeed");

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
    let signed_bytes =
        sign(content_mime, &test_key, std::time::SystemTime::now()).expect("sign() must succeed");

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
        encrypt(inner_mime, &[cert.clone()]).expect("encrypt() must succeed for P-256");

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
