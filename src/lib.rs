//! No std CBOR Object Signing and Encryption, Cose [RFC 9052 ](https://datatracker.ietf.org/doc/html/rfc9052)/ [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).
//! 
#![no_std]

pub mod structs;

mod multitypes;
mod builder;
mod error;


pub use error::*;
pub use builder::*;