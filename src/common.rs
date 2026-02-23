use crate::{Builder, cose_keys::CoseKey};
use minicbor::{CborLen, Decode, Encode};
use minicbor_weird::bstr_wrapper;

#[allow(dead_code)]
pub(crate) const MAX_SUPPORTED_ACCESSTOKEN_LEN: usize = 256;

/// HeaderMap as described in RCF 9052.
///
/// Refer to COSE Header [Parameters
/// registry](https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).
#[derive(Decode, Encode, CborLen, Debug)]
#[cbor(map)]
#[non_exhaustive]
pub struct HeaderMap<'a> {
    #[n(1)]
    // Might be extended as more exotic algorithms are supported
    pub alg: Option<CoseAlg>,

    #[cbor(b(4), with = "minicbor::bytes")]
    pub(crate) kid: Option<&'a [u8]>,

    #[cbor(b(5), with = "minicbor::bytes")]
    pub(crate) iv: Option<&'a [u8]>,

    #[b(-1)]
    pub(crate) ephemeral_key: Option<CoseKey<'a>>,
}

impl<'a> HeaderMap<'a> {
    /// Merge two header maps, using the latter's value in case of conflict.
    #[allow(unused)]
    pub fn updated_with(&self, other: &Self) -> Self {
        Self {
            alg: self.alg.or(other.alg),
            kid: self.kid.or(other.kid),
            iv: self.iv.or(other.iv),
            ephemeral_key: self
                .ephemeral_key
                .as_ref()
                .copied()
                .or(other.ephemeral_key.as_ref().copied()),
        }
    }

    /// Creates new empty header map
    pub fn new() -> Self {
        Self {
            alg: None,
            kid: None,
            iv: None,
            ephemeral_key: None
        }
    }

    /// Turns this map into a builder
    pub fn builder(self) -> Builder<Self> {
        self.into()
    }

    /// Gets alg
    pub fn algorithm(&self) -> Option<CoseAlg> {
        self.alg
    }

    /// Sets alg
    pub fn with_algorithm(&mut self, alg: CoseAlg) -> &mut Self {
        self.alg = Some(alg);
        self
    }

    /// Gets kid
    pub fn key_id(&self) -> Option<&'a [u8]> {
        self.kid
    }

    /// Sets kid
    pub fn with_key_id(&mut self, kid: &'a [u8]) -> &mut Self {
        self.kid = Some(kid);
        self
    }

    /// Gets kid
    pub fn iv(&self) -> Option<&'a [u8]> {
        self.iv
    }

     /// Sets IV
    pub fn with_iv(&mut self, iv: &'a [u8]) -> &mut Self {
        self.iv = Some(iv);
        self
    }

    /// Gets kid
    pub fn ephemeral_key(&self) -> &Option<CoseKey<'a>> {
        &self.ephemeral_key
    }

    /// Sets kid
    pub fn with_ephemeral_key(&mut self, key: CoseKey<'a>) -> &mut Self {
        self.ephemeral_key = Some(key);
        self
    }
}

impl<'a> Builder<HeaderMap<'a>> {
    /// Sets alg
    pub fn algorithm(mut self, alg: CoseAlg) -> Self {
        self.with_algorithm(alg);
        self
    }

    /// Sets kid
    pub fn key_id(mut self, kid: &'a [u8]) -> Self {
        self.with_key_id(kid);
        self
    }

     /// Sets IV
    pub fn iv(mut self, iv: &'a [u8]) -> Self {
        self.with_iv(iv);
        self
    }

    /// Sets kid
    pub fn ephemeral_key(mut self, key: CoseKey<'a>) -> Self {
        self.with_ephemeral_key(key);
        self
    }
}

/// COSE Algorithm and Curve identifiers as defined by IANA.
/// Used as Key Type Parameters in COSE Keys:
/// <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
#[derive(Decode, Debug, Encode, CborLen, PartialEq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum CoseAlg {

    /// RSASSA-PKCS1-v1_5 using SHA-1
    /// [RFC8812](https://www.iana.org/go/rfc8812)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-65535)]
    RS1 = -65535,

    /// AES-CTR w/ 128-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65534)]
    A128CTR = -65534,

    /// AES-CTR w/ 192-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65533)]
    A192CTR = -65533,

    /// AES-CTR w/ 256-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65532)]
    A256CTR = -65532,

    /// AES-CBC w/ 128-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65531)]
    A128CBC = -65531,

    /// AES-CBC w/ 192-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65530)]
    A192CBC = -65530,

    /// AES-CBC w/ 256-bit key
    /// [RFC9459](https://www.iana.org/go/rfc9459)
    #[n(-65529)]
    A256CBC = -65529,

    /// ECDSA using BrainpoolP512r1 curve and SHA-512
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-268)]
    ESB512 = -268,

    /// ECDSA using BrainpoolP384r1 curve and SHA-384
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-267)]
    ESB384 = -267,

    /// ECDSA using BrainpoolP320r1 curve and SHA-384
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-266)]
    ESB320 = -266,

    /// ECDSA using BrainpoolP256r1 curve and SHA-256
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-265)]
    ESB256 = -265,

    /// KT256 XOF
    /// [RFC9861](https://www.iana.org/go/rfc9861)
    #[n(-264)]
    KT256 = -264,

    /// KT128 XOF
    /// [RFC9861](https://www.iana.org/go/rfc9861)
    #[n(-263)]
    KT128 = -263,

    /// TurboSHAKE256 XOF
    /// [RFC9861](https://www.iana.org/go/rfc9861)
    #[n(-262)]
    TurboSHAKE256 = -262,

    /// TurboSHAKE128 XOF
    /// [RFC9861](https://www.iana.org/go/rfc9861)
    #[n(-261)]
    TurboSHAKE128 = -261,

    /// WalnutDSA signature
    /// [RFC9021](https://www.iana.org/go/rfc9021)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-260)]
    WalnutDSA = -260,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    /// [RFC8812](https://www.iana.org/go/rfc8812)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-259)]
    RS512 = -259,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    /// [RFC8812](https://www.iana.org/go/rfc8812)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-258)]
    RS384 = -258,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// [RFC8812](https://www.iana.org/go/rfc8812)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-257)]
    RS256 = -257,

    /// EdDSA using the Ed448 parameter set in Section 5.2 of [RFC8032]
    /// [RFC9864, Section 2.2](https://www.iana.org/go/rfc9864#section-2.2)
    #[n(-53)]
    Ed448 = -53,

    /// ECDSA using P-521 curve and SHA-512
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-52)]
    ESP512 = -52,

    /// ECDSA using P-384 curve and SHA-384
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-51)]
    ESP384 = -51,

    /// CBOR Object Signing Algorithm for ML-DSA-87
    /// [RFC-ietf-cose-dilithium-10](https://www.iana.org/go/draft-ietf-cose-dilithium-10)
    #[n(-50)]
    MLDSA87 = -50,

    /// CBOR Object Signing Algorithm for ML-DSA-65
    /// [RFC-ietf-cose-dilithium-10](https://www.iana.org/go/draft-ietf-cose-dilithium-10)
    #[n(-49)]
    MLDSA65 = -49,

    /// CBOR Object Signing Algorithm for ML-DSA-44
    /// [RFC-ietf-cose-dilithium-10](https://www.iana.org/go/draft-ietf-cose-dilithium-10)
    #[n(-48)]
    MLDSA44 = -48,

    /// ECDSA using secp256k1 curve and SHA-256
    /// [RFC8812](https://www.iana.org/go/rfc8812)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-47)]
    ES256K = -47,

    /// HSS/LMS hash-based digital signature
    /// [RFC8778](https://www.iana.org/go/rfc8778)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-46)]
    HSSLMS = -46,

    /// SHAKE-256 512-bit Hash Value
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-45)]
    SHAKE256 = -45,

    /// SHA-2 512-bit Hash
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-44)]
    SHA512 = -44,

    /// SHA-2 384-bit Hash
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-43)]
    SHA384 = -43,

    /// RSAES-OAEP w/ SHA-512
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-42)]
    RSAESOAEPWSHA512 = -42,

    /// RSAES-OAEP w/ SHA-256
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-41)]
    RSAESOAEPWSHA256 = -41,

    /// RSAES-OAEP w/ SHA-1
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-40)]
    RSAESOAEPWRFC8017DefaultParameters = -40,

    /// RSASSA-PSS w/ SHA-512
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-39)]
    PS512 = -39,

    /// RSASSA-PSS w/ SHA-384
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-38)]
    PS384 = -38,

    /// RSASSA-PSS w/ SHA-256
    /// [RFC8230](https://www.iana.org/go/rfc8230)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-37)]
    PS256 = -37,

    /// ECDSA w/ SHA-512
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    /// [RFC9864](https://www.iana.org/go/rfc9864)
    #[n(-36)]
    ES512 = -36,

    /// ECDSA w/ SHA-384
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    /// [RFC9864](https://www.iana.org/go/rfc9864)
    #[n(-35)]
    ES384 = -35,

    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-34)]
    ECDHSSA256KW = -34,

    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-33)]
    ECDHSSA192KW = -33,

    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-32)]
    ECDHSSA128KW = -32,

    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-31)]
    ECDHESA256KW = -31,

    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-30)]
    ECDHESA192KW = -30,

    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-29)]
    ECDHESA128KW = -29,

    /// ECDH SS w/ HKDF - generate key directly
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-28)]
    ECDHSSHKDF512 = -28,

    /// ECDH SS w/ HKDF - generate key directly
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-27)]
    ECDHSSHKDF256 = -27,

    /// ECDH ES w/ HKDF - generate key directly
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-26)]
    ECDHESHKDF512 = -26,

    /// ECDH ES w/ HKDF - generate key directly
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-25)]
    ECDHESHKDF256 = -25,

    /// EdDSA using the Ed25519 parameter set in Section 5.1 of [RFC8032]
    /// [RFC9864, Section 2.2](https://www.iana.org/go/rfc9864#section-2.2)
    #[n(-19)]
    Ed25519 = -19,

    /// SHAKE-128 256-bit Hash Value
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-18)]
    SHAKE128 = -18,

    /// SHA-2 512-bit Hash truncated to 256-bits
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-17)]
    SHA512256 = -17,

    /// SHA-2 256-bit Hash
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-16)]
    SHA256 = -16,

    /// SHA-2 256-bit Hash truncated to 64-bits
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-15)]
    SHA25664 = -15,

    /// SHA-1 Hash
    /// [RFC9054](https://www.iana.org/go/rfc9054)
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-14)]
    SHA1 = -14,

    /// Shared secret w/ AES-MAC 256-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-13)]
    DirectHKDFAES256 = -13,

    /// Shared secret w/ AES-MAC 128-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-12)]
    DirectHKDFAES128 = -12,

    /// Shared secret w/ HKDF and SHA-512
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-11)]
    DirectHKDFSHA512 = -11,

    /// Shared secret w/ HKDF and SHA-256
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-10)]
    DirectHKDFSHA256 = -10,

    /// ECDSA using P-256 curve and SHA-256
    /// [RFC9864, Section 2.1](https://www.iana.org/go/rfc9864#section-2.1)
    #[n(-9)]
    ESP256 = -9,

    /// EdDSA
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    /// [RFC9864](https://www.iana.org/go/rfc9864)
    #[n(-8)]
    EdDSA = -8,

    /// ECDSA w/ SHA-256
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    /// [RFC9864](https://www.iana.org/go/rfc9864)
    #[n(-7)]
    ES256 = -7,

    /// Direct use of CEK
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-6)]
    Direct = -6,

    /// AES Key Wrap w/ 256-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-5)]
    A256KW = -5,

    /// AES Key Wrap w/ 192-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-4)]
    A192KW = -4,

    /// AES Key Wrap w/ 128-bit key
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(-3)]
    A128KW = -3,

    /// AES-GCM mode w/ 128-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(1)]
    A128GCM = 1,

    /// AES-GCM mode w/ 192-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(2)]
    A192GCM = 2,

    /// AES-GCM mode w/ 256-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(3)]
    A256GCM = 3,

    /// HMAC w/ SHA-256 truncated to 64 bits
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(4)]
    HMAC256TruncatedTo64 = 4,

    /// HMAC w/ SHA-256
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(5)]
    HMAC256 = 5,

    /// HMAC w/ SHA-384
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(6)]
    HMAC384 = 6,

    /// HMAC w/ SHA-512
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(7)]
    HMAC512 = 7,

    /// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(10)]
    AESCCM1664128 = 10,

    /// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(11)]
    AESCCM1664256 = 11,

    /// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(12)]
    AESCCM6464128 = 12,

    /// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(13)]
    AESCCM6464256 = 13,

    /// AES-MAC 128-bit key, 64-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(14)]
    AESMAC12864 = 14,

    /// AES-MAC 256-bit key, 64-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(15)]
    AESMAC25664 = 15,

    /// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(24)]
    ChaCha20Poly1305 = 24,

    /// AES-MAC 128-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(25)]
    AESMAC128128 = 25,

    /// AES-MAC 256-bit key, 128-bit tag
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(26)]
    AESMAC256128 = 26,

    /// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(30)]
    AESCCM16128128 = 30,

    /// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(31)]
    AESCCM16128256 = 31,

    /// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(32)]
    AESCCM64128128 = 32,

    /// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(33)]
    AESCCM64128256 = 33,

    /// For doing IV generation for symmetric algorithms.
    /// [RFC9053](https://www.iana.org/go/rfc9053)
    #[n(34)]
    IVGeneration = 34,
}

bstr_wrapper!(BstrHeaderMap, HeaderMap<'a>);