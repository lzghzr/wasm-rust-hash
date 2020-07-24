#![no_std]
extern crate alloc;
use alloc::string::String;

use wasm_bindgen::prelude::*;

use blake2::{Blake2b, Blake2s, Digest};
use hex::encode;
use md4::Md4;
use md5::Md5;
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use whirlpool::Whirlpool;

fn digest<D: Digest>(data: &str) -> String {
    let hash_digest = &D::digest(data.as_bytes());
    return encode(hash_digest);
}

#[wasm_bindgen]
pub fn hash(algorithm: &str, data: &str) -> String {
    match algorithm {
        "BLAKE2b512" => digest::<Blake2b>(data),
        "BLAKE2s256" => digest::<Blake2s>(data),
        "MD4" => digest::<Md4>(data),
        "MD5" => digest::<Md5>(data),
        "RIPEMD160" => digest::<Ripemd160>(data),
        "SHA1" => digest::<Sha1>(data),
        "SHA224" => digest::<Sha224>(data),
        "SHA256" => digest::<Sha256>(data),
        "SHA384" => digest::<Sha384>(data),
        "SHA512" => digest::<Sha512>(data),
        "SHA3-224" => digest::<Sha3_224>(data),
        "SHA3-256" => digest::<Sha3_256>(data),
        "SHA3-384" => digest::<Sha3_384>(data),
        "SHA3-512" => digest::<Sha3_512>(data),
        "whirlpool" => digest::<Whirlpool>(data),
        _ => encode(data),
    }
}
