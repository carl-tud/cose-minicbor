use crate::structs::recipient::IterCoseRecipient;
use super::header::{HeaderMap};
use minicbor::bytes::{CborLenBytes, DecodeBytes, EncodeBytes};
use minicbor::{CborLen, Decode, Encode};
use minicbor_weird::cbor_bytes::CborBytes;

#[allow(dead_code)]
const MAX_CEK_KEY_LEN: usize = 64;

/// `Cose_MAC0` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with implicit key.
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseMac0<'a, Header = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Option<Payload>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseMac`] and [`CoseMac0`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode, CborLen)]
pub struct MacStructure<'a, Header = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[n(0)]
    pub context: &'static str, // "MAC" / "MAC0"
    #[cbor(b(1),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub body_protected: Header,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    // The full payload is used here
    #[cbor(b(3),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Option<Payload>,
}

pub const CONTEXT_MAC: &'static str = "MAC";
pub const CONTEXT_MAC0: &'static str = "MAC0";

/// `Cose_MAC` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with recipients.
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseMac<'a, Header = CborBytes<HeaderMap<'a>>, Payload = &'a [u8]> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(n(2),
        with = "minicbor::bytes",
        encode_bound = "Payload: EncodeBytes<Ctx>", 
        decode_bound = "Payload: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Payload: CborLenBytes<Ctx>",
    )]
    pub payload: Option<Payload>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],

    #[n(4)]
    pub recipients: IterCoseRecipient<'a>, // at least 1
}