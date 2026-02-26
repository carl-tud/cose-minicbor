use crate::structs::recipient::IterCoseRecipient;
use super::header::{HeaderMap};
use minicbor::bytes::{CborLenBytes, DecodeBytes, EncodeBytes};
use minicbor::{CborLen, Decode, Encode};

#[allow(dead_code)]
const MAX_CEK_KEY_LEN: usize = 64;

/// `Cose_MAC0` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with implicit key.
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
pub struct CoseMac0<'a, T> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(b(2),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: Option<T>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],
}

pub type CoseMac0BytesPayload<'a> = CoseMac0<'a, &'a [u8]>;


/// This structure will be used for Encrypting process on [`CoseMac`] and [`CoseMac0`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode, CborLen)]
pub struct MacStructure<'a, T> {
    #[n(0)]
    pub context: &'static str, // "MAC" / "MAC0"
    #[cbor(b(1), with = "minicbor_weird::cbor_bytes")]
    pub body_protected: HeaderMap<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    // The full payload is used here
    #[cbor(b(3),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: Option<T>,
}

pub const CONTEXT_MAC: &'static str = "MAC";
pub const CONTEXT_MAC0: &'static str = "MAC0";

pub type MacStructureBytesPayload<'a> = MacStructure<'a, &'a [u8]>;


/// `Cose_MAC` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with recipients.
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseMac<'a, T> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(n(2),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub payload: Option<T>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],

    #[n(4)]
    pub recipients: IterCoseRecipient<'a>, // at least 1
}

pub type CoseMacBytesPayload<'a> = CoseMac<'a, &'a [u8]>;
