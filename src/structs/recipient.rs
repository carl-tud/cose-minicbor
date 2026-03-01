use minicbor::{Decode, Encode, CborLen};
use minicbor::bytes::{CborLenBytes, DecodeBytes, EncodeBytes};
use minicbor_weird::cbor_bytes::CborBytes;
use minicbor_weird::iter_wrapper;
use crate::{multitypes::NulOrBytes, structs::CoseAlg};
use super::header::HeaderMap;

#[allow(dead_code)]
const MAX_SHARED_SECRET_LEN: usize = 66;

iter_wrapper!(IterCoseRecipient, CoseRecipient<'a>);

/// Cose Recipient for key exchanges in HMAC process as described in RCF 9052.
#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(array)]
#[non_exhaustive]
pub struct CoseRecipient<'a, Header = CborBytes<HeaderMap<'a>>> {
    #[cbor(b(0),
        with = "minicbor::bytes",
        encode_bound = "Header: EncodeBytes<Ctx>", 
        decode_bound = "Header: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "Header: CborLenBytes<Ctx>",
    )]
    pub protected: Header,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    pub ciphertext: Option<&'a [u8]>,
    // could have been recipients field (not supported)
}

pub const CONTEXT_RECIPIENT_IN_ENCRYPT: &'static str = "Enc_Recipient";
pub const CONTEXT_RECIPIENT_IN_MAC: &'static str = "Mac_Recipient";
pub const CONTEXT_RECIPIENT_IN_RECIPIENT: &'static str = "Rec_Recipient";

/// Context information structure for KDF process.
/// As decrypted in [RFC 9053 5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2)
#[allow(dead_code)]
#[derive(Encode)]
pub struct CoseKdfContext<'a, T = &'a [u8]> {
    #[n(0)]
    pub alg_id: CoseAlg,
    #[n(1)]
    pub party_u_info: PartyInfo<'a>,
    #[n(2)]
    pub party_v_info: PartyInfo<'a>,
    #[cbor(b(3),
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub sup_pub_info: SuppPubInfo<T>,
}

/// Context field structure to wrap PartyUInfo and PartyVInfo.
#[allow(dead_code)]
#[derive(Encode)]
pub struct PartyInfo<'a> {
    #[cbor(b(0))]
    pub identity: NulOrBytes<'a>,
    #[cbor(b(1))]
    pub nonce: NulOrBytes<'a>,
    #[cbor(b(2))]
    pub other: NulOrBytes<'a>,
}

/// Context field structure that contains information that is mutually known to both parties
#[allow(dead_code)]
#[derive(Encode, Decode, CborLen)]
pub struct SuppPubInfo<T> {
    #[n(0)]
    pub key_length: u32,
    #[cbor(b(1),
        with = "minicbor::bytes",
        encode_bound = "T: EncodeBytes<Ctx>", 
        decode_bound = "T: DecodeBytes<'bytes, Ctx>",
        cbor_len_bound = "T: CborLenBytes<Ctx>",
    )]
    pub protected: T,
}