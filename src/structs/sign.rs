use minicbor::{CborLen, Decode, Encode, bytes::{CborLenBytes, DecodeBytes, EncodeBytes}};
use minicbor_weird::{cbor_bytes::CborBytes, iter_wrapper};
use crate::structs::header::HeaderMap;

/// A `COSE_Sign1` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseSign1<'a, Header = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header, // protected is a bstr .cbor header map / or a bstr .size 0
    #[b(1)]
    pub unprotected: HeaderMap<'a>, //
    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Option<Payload>,
    #[cbor(b(3), with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseSign1`]
/// to feed the AAD during the cryptographic process.
#[derive(minicbor::Encode, CborLen)]
#[cbor(array)]
pub struct Sig1Structure<'a, Body = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[n(0)]
    pub context: &'static str, // "Signature1"
    #[cbor(b(1),
        with = "minicbor::bytes",
        encode_bound = "Body: EncodeBytes<Ctx>", 
        decode_bound = "Body: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Body: CborLenBytes<Ctx>",
    )]
    pub body_protected: Body, // protected is a bstr .cbor header map / or a bstr .size 0
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    #[cbor(b(3),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Payload,
}

pub const CONTEXT_SIGNATURE1: &'static str = "Signature1";

iter_wrapper!(IterCoseSignature, CoseSignature<'a>);

/// A `COSE_Sign` structure to handle multiple signature as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseSign<'a, Header = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header,
    #[b(1)]
    pub unprotected: HeaderMap<'a>,
    // Payload could also be nil, but we don't support detached signatures here right now.
    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Option<Payload>,
    #[b(3)]
    pub signature: IterCoseSignature<'a>,
}

/// A `CoseSignature` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseSignature<'a, Header = CborBytes<HeaderMap<'a>>> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header,
    #[b(1)]
    pub unprotected: HeaderMap<'a>,
    #[cbor(b(3), with = "minicbor::bytes")]
    pub signature: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseSign`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode, CborLen)]
pub struct SigStructure<'a, Body = CborBytes<HeaderMap<'a>>, Sign = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[n(0)]
    pub context: &'static str, // "Signature"
    #[cbor(b(1),
        with = "minicbor::bytes",
        encode_bound = "Body: EncodeBytes<Ctx>", 
        decode_bound = "Body: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Body: CborLenBytes<Ctx>",
    )]
    pub body_protected: Body,
    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "Sign: EncodeBytes<Ctx>", 
        decode_bound = "Sign: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Sign: CborLenBytes<Ctx>",
    )]
    pub sign_protected: Sign,
    #[cbor(b(3), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    #[cbor(b(4),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Payload,
}

pub const CONTEXT_SIGNATURE: &'static str = "Signature";