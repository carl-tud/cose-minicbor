use crate::structs::recipient::IterCoseRecipient;
use super::header::{HeaderMap};
use minicbor::{CborLen, Decode, Encode};

/// A `COSE_Encrypt` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseEncrypt<'a> {
    #[cbor(b(0), with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>, // protected is a bstr .cbor header map / or a bstr .size 0
    #[b(1)]
    pub unprotected: HeaderMap<'a>, //
    #[cbor(b(2), with = "minicbor::bytes")]
    pub ciphertex: Option<&'a [u8]>,
    #[cbor(b(3))]
    pub recipients: IterCoseRecipient<'a>,
}

/// A `COSE_Encrypt0` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseEncrypt0<'a> {
    #[cbor(b(0), with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>, // protected is a bstr .cbor header map / or a bstr .size 0
    #[b(1)]
    pub unprotected: HeaderMap<'a>, //
    #[cbor(b(2), with = "minicbor::bytes")]
    pub ciphertex: Option<&'a [u8]>,
}

/// This structure will be used for Encrypting process on [`CoseEncrypt`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(Encode, CborLen)]
pub struct EncryptStructure<'a> {
    #[n(0)]
    pub context: &'static str,
    #[cbor(b(1), with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
}

pub const CONTEXT_ENCRYPT: &'static str = "Encrypt";
pub const CONTEXT_ENCRYPT0: &'static str = "Encrypt0";