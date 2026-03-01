use minicbor::{CborLen, Decode, Encode, bytes::{CborLenBytes, DecodeBytes, EncodeBytes}};
use minicbor_weird::iter_wrapper;
use crate::structs::header::HeaderMap;

/// A `COSE_Sign1` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseSign1<'a, T = &'a [u8]> {
    #[cbor(b(0), with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>, // protected is a bstr .cbor header map / or a bstr .size 0
    #[b(1)]
    pub unprotected: HeaderMap<'a>, //
    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: Option<T>,
    #[cbor(b(3), with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseSign1`]
/// to feed the AAD during the cryptographic process.
#[derive(minicbor::Encode, CborLen)]
#[cbor(array)]
pub struct Sig1Structure<'a, T = &'a [u8]> {
    #[n(0)]
    pub context: &'static str, // "Signature1"
    #[cbor(b(1), with = "minicbor_weird::cbor_bytes")]
    pub body_protected: HeaderMap<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    #[cbor(b(3),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: T,
}

pub const CONTEXT_SIGNATURE1: &'static str = "Signature1";

iter_wrapper!(IterCoseSignature, CoseSignature<'a>);

/// A `COSE_Sign` structure to handle multiple signature as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseSign<'a, T = &'a [u8]> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,
    #[b(1)]
    pub unprotected: HeaderMap<'a>,
    // Payload could also be nil, but we don't support detached signatures here right now.
    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: Option<T>,
    #[b(3)]
    pub signature: IterCoseSignature<'a>,
}

/// A `CoseSignature` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseSignature<'a> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,
    #[b(1)]
    pub unprotected: HeaderMap<'a>,
    #[cbor(b(3), with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseSign`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode, CborLen)]
pub struct SigStructure<'a, T = &'a [u8]> {
    #[n(0)]
    pub context: &'static str, // "Signature"
    #[cbor(b(1), with = "minicbor::bytes")]
    pub body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    pub sign_protected: &'a [u8],
    #[cbor(b(3), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    #[cbor(b(4),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: T,
}

pub const CONTEXT_SIGNATURE: &'static str = "Signature";