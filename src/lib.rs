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
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use whirlpool::Whirlpool;

const BLAKE2B512: [&str; 1] = ["BLAKE2B512"]; // "BLAKE2b512"
const BLAKE2S256: [&str; 1] = ["BLAKE2S256"]; // "BLAKE2s256"
const MD4: [&str; 3] = ["MD4", "RSA-MD4", "MD4WITHRSAENCRYPTION"]; // "MD4", "RSA-MD4", "md4WithRSAEncryption"
const MD5: [&str; 5] = ["MD5", "RSA-MD5", "MD5WITHRSAENCRYPTION", "MD5-SHA1","SSL3-MD5"]; // "MD5", "RSA-MD5", "md5WithRSAEncryption", "MD5-SHA1","ssl3-md5"
const RIPEMD160: [&str; 5] = [ "RIPEMD160", "RSA-RIPEMD160", "RIPEMD160WITHRSA", "RIPEMD", "RMD160"]; // "RIPEMD160", "RSA-RIPEMD160", "ripemd160WithRSA", "ripemd", "rmd160"
const SHA1: [&str; 5] = ["SHA1", "RSA-SHA1", "SHA1WITHRSAENCRYPTION", "RSA-SHA1-2", "SSL3-SHA1"]; // "SHA1", "RSA-SHA1", "sha1WithRSAEncryption", "RSA-SHA1-2", "ssl3-sha1"
const SHA224: [&str; 3] = ["SHA224", "RSA-SHA224", "SHA224WITHRSAENCRYPTION"]; // "SHA224", "RSA-SHA224", "sha224WithRSAEncryption"
const SHA256: [&str; 3] = ["SHA256", "RSA-SHA256", "SHA256WITHRSAENCRYPTION"]; // "SHA256", "RSA-SHA256", "sha256WithRSAEncryption"
const SHA384: [&str; 3] = ["SHA384", "RSA-SHA384", "SHA384WITHRSAENCRYPTION"]; // "SHA384", "RSA-SHA384", "sha384WithRSAEncryption"
const SHA512: [&str; 3] = ["SHA512", "RSA-SHA512", "SHA512WITHRSAENCRYPTION"]; // "SHA512", "RSA-SHA512", "sha512WithRSAEncryption"
const SHA512_224: [&str; 3] = ["SHA512-224", "RSA-SHA512/224", "SHA512-224WITHRSAENCRYPTION"]; // "SHA512-224", "RSA-SHA512/224", "sha512-224WithRSAEncryption"
const SHA512_256: [&str; 3] = ["SHA512-256", "RSA-SHA512/256", "SHA512-256WITHRSAENCRYPTION"]; // "SHA512-256", "RSA-SHA512/256", "sha512-256WithRSAEncryption"
const SHA3_224: [&str; 3] = ["SHA3-224", "RSA-SHA3-224", "ID-RSASSA-PKCS1-V1_5-WITH-SHA3-224"]; // "SHA3-224", "RSA-SHA3-224", "id-rsassa-pkcs1-v1_5-with-sha3-224"
const SHA3_256: [&str; 3] = ["SHA3-256", "RSA-SHA3-256", "ID-RSASSA-PKCS1-V1_5-WITH-SHA3-256"]; // "SHA3-256", "RSA-SHA3-256", "id-rsassa-pkcs1-v1_5-with-sha3-256"
const SHA3_384: [&str; 3] = ["SHA3-384", "RSA-SHA3-384", "ID-RSASSA-PKCS1-V1_5-WITH-SHA3-384"]; // "SHA3-384", "RSA-SHA3-384", "id-rsassa-pkcs1-v1_5-with-sha3-384"
const SHA3_512: [&str; 3] = ["SHA3-512", "RSA-SHA3-512", "ID-RSASSA-PKCS1-V1_5-WITH-SHA3-512"]; // "SHA3-512", "RSA-SHA3-512", "id-rsassa-pkcs1-v1_5-with-sha3-512"
const WHIRLPOOL: [&str; 1] = ["WHIRLPOOL"]; // "whirlpool"

fn digest<D: Digest>(data: &str) -> String {
    let hash_digest = D::digest(data.as_bytes());
    encode(hash_digest)
}

fn get_digest(algorithm: &str, data: &str) -> String {
    let algorithm = algorithm.to_ascii_uppercase();
    let algorithm = algorithm.as_str();
    if BLAKE2B512.contains(&algorithm) {
        digest::<Blake2b>(data)
    } else if BLAKE2S256.contains(&algorithm) {
        digest::<Blake2s>(data)
    } else if MD4.contains(&algorithm) {
        digest::<Md4>(data)
    } else if MD5.contains(&algorithm) {
        digest::<Md5>(data)
    } else if RIPEMD160.contains(&algorithm) {
        digest::<Ripemd160>(data)
    } else if SHA1.contains(&algorithm) {
        digest::<Sha1>(data)
    } else if SHA224.contains(&algorithm) {
        digest::<Sha224>(data)
    } else if SHA256.contains(&algorithm) {
        digest::<Sha256>(data)
    } else if SHA384.contains(&algorithm) {
        digest::<Sha384>(data)
    } else if SHA512.contains(&algorithm) {
        digest::<Sha512>(data)
    } else if SHA512_224.contains(&algorithm) {
        digest::<Sha512Trunc224>(data)
    } else if SHA512_256.contains(&algorithm) {
        digest::<Sha512Trunc256>(data)
    } else if SHA3_224.contains(&algorithm) {
        digest::<Sha3_224>(data)
    } else if SHA3_256.contains(&algorithm) {
        digest::<Sha3_256>(data)
    } else if SHA3_384.contains(&algorithm) {
        digest::<Sha3_384>(data)
    } else if SHA3_512.contains(&algorithm) {
        digest::<Sha3_512>(data)
    } else if WHIRLPOOL.contains(&algorithm) {
        digest::<Whirlpool>(data)
    } else {
        encode(data)
    }
}

#[wasm_bindgen]
pub fn hash(algorithm: &str, data: &str) -> String {
    get_digest(&algorithm, &data)
}
