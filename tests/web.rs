//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use wasm_rust_hash::hash;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(hash("BLAKE2b512", ""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    assert_eq!(hash("BLAKE2s256", ""), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    assert_eq!(hash("MD4", ""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(hash("MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hash("RIPEMD160", ""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    assert_eq!(hash("SHA1", ""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hash("SHA224", ""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    assert_eq!(hash("SHA256", ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash("SHA384", ""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert_eq!(hash("SHA512", ""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert_eq!(hash("SHA512-224", ""), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    assert_eq!(hash("SHA512-256", ""), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    assert_eq!(hash("SHA3-224", ""), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    assert_eq!(hash("SHA3-256", ""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(hash("SHA3-384", ""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert_eq!(hash("SHA3-512", ""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    assert_eq!(hash("whirlpool", ""), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    assert_eq!(hash("", ""), "");
}
