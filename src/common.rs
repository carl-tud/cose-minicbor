use crate::{Builder, cose_keys::CoseKey};
use minicbor::{CborLen, Decode, Encode};
use suit_cbor::bstr_wrapper;

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
    /// Key Wrap: AES-128
    #[n(-3)]
    A128KW = -3,
    /// Key Wrap: AES-256
    #[n(-5)]
    A256KW = -5,
    /// ECDH-ES + AES Key Wrap 128
    #[n(-29)]
    ECDHESA128KW = -29,
    /// ES256 / P-256 signature
    #[n(-9)]
    ES256P256 = -9,
    /// ES256 deprecated / retro-compatible
    #[n(-7)]
    ES256 = 7,
    /// Ed25519 signature
    #[n(-19)]
    ED25519 = -19,
    /// HSS/LMS signature
    #[n(-46)]
    HSSLMS = -46,
    /// HMAC truncated 64 bits
    #[n(4)]
    HMAC25664 = 4,
    /// HMAC 256 bits
    #[n(5)]
    HMAC256256 = 5,
}

bstr_wrapper!(BstrHeaderMap, HeaderMap<'a>);