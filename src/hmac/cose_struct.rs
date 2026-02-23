use crate::common::{BstrHeaderMap, HeaderMap, MAX_SUPPORTED_ACCESSTOKEN_LEN};
use crate::cose_recipient::IterCoseRecipient;
use crate::errors::{CoseError, ErrorImpl};
use crate::hmac::verify_mac;
use minicbor::{Decode, Encode};

#[allow(dead_code)]
const MAX_CEK_KEY_LEN: usize = 64;

/// `Cose_MAC0` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with implicit key.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac0<'a> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    pub payload: Option<&'a [u8]>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseMac`] and [`CoseMac0`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode)]
pub struct MacStructure<'a> {
    #[n(0)]
    pub context: &'static str, // "MAC" / "MAC0"
    #[cbor(b(1), with = "minicbor_weird::cbor_bytes")]
    pub body_protected: HeaderMap<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub external_aad: &'a [u8],
    // The full payload is used here
    #[cbor(b(3), with = "minicbor::bytes")]
    pub payload: &'a [u8],
}

/// `Cose_MAC` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with recipients.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseMac<'a> {
    #[b(0)]
    #[cbor(with = "minicbor_weird::cbor_bytes")]
    pub protected: HeaderMap<'a>,

    #[b(1)]
    pub unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    pub payload: Option<&'a [u8]>,

    #[cbor(b(3), with = "minicbor::bytes")]
    pub tag: &'a [u8],

    #[n(4)]
    pub recipients: IterCoseRecipient<'a>, // at least 1
}