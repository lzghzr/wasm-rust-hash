use digest::{Digest, DynDigest, FixedOutput, Reset, Update};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FixedHash {
    inner: Box<dyn DynDigest>,
}
#[wasm_bindgen]
impl FixedHash {
    #[wasm_bindgen]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    #[wasm_bindgen(js_name = finalizeReset)]
    pub fn finalize_reset(&mut self) -> Box<[u8]> {
        self.inner.finalize_reset()
    }
    #[wasm_bindgen]
    pub fn finalize(self) -> Box<[u8]> {
        self.inner.finalize()
    }
    #[wasm_bindgen]
    pub fn reset(&mut self) {
        self.inner.reset();
    }
    #[wasm_bindgen(js_name = outputSize)]
    pub fn output_size(&self) -> usize {
        self.inner.output_size()
    }
    #[wasm_bindgen]
    pub fn clone(&mut self) -> FixedHash {
        FixedHash {
            inner: self.inner.box_clone(),
        }
    }
}
#[wasm_bindgen(js_name = createHash)]
pub fn create_hash(algorithm: &str) -> Result<FixedHash, JsValue> {
    let algorithm = algorithm
        .replace("-", "")
        .replace("/", "")
        .to_ascii_uppercase();
    let algorithm = algorithm.as_str();
    let hasher: Option<Box<dyn DynDigest>> = match algorithm {
        "BLAKE2B512" => get_some::<blake2::Blake2b>(),
        "BLAKE2S256" => get_some::<blake2::Blake2s>(),
        "FSB160" => get_some::<fsb::Fsb160>(),
        "FSB224" => get_some::<fsb::Fsb224>(),
        "FSB256" => get_some::<fsb::Fsb256>(),
        "FSB384" => get_some::<fsb::Fsb384>(),
        "FSB512" => get_some::<fsb::Fsb512>(),
        "GOST94CRYPTOPRO" => get_some::<gost94::Gost94CryptoPro>(),
        "GOST94TEST" => get_some::<gost94::Gost94Test>(),
        "GOST94S2015" => get_some::<gost94::Gost94s2015>(),
        "GROESTL224" => get_some::<groestl::Groestl224>(),
        "GROESTL256" => get_some::<groestl::Groestl256>(),
        "GROESTL384" => get_some::<groestl::Groestl384>(),
        "GROESTL512" => get_some::<groestl::Groestl512>(),
        "MD2" => get_some::<md2::Md2>(),
        "MD4" => get_some::<md4::Md4>(),
        "MD5" => get_some::<md5::Md5>(),
        "RIPEMD160" => get_some::<ripemd160::Ripemd160>(),
        "RIPEMD256" => get_some::<ripemd256::Ripemd256>(),
        "RIPEMD320" => get_some::<ripemd320::Ripemd320>(),
        "SHA1" => get_some::<sha1::Sha1>(),
        "SHA224" => get_some::<sha2::Sha224>(),
        "SHA256" => get_some::<sha2::Sha256>(),
        "SHA384" => get_some::<sha2::Sha384>(),
        "SHA512" => get_some::<sha2::Sha512>(),
        "SHA512224" => get_some::<sha2::Sha512Trunc224>(),
        "SHA512256" => get_some::<sha2::Sha512Trunc256>(),
        "KECCAK224" => get_some::<sha3::Keccak224>(),
        "KECCAK256" => get_some::<sha3::Keccak256>(),
        "KECCAK256FULL" => get_some::<sha3::Keccak256Full>(),
        "KECCAK384" => get_some::<sha3::Keccak384>(),
        "KECCAK512" => get_some::<sha3::Keccak512>(),
        "SHA3224" => get_some::<sha3::Sha3_224>(),
        "SHA3256" => get_some::<sha3::Sha3_256>(),
        "SHA3384" => get_some::<sha3::Sha3_384>(),
        "SHA3512" => get_some::<sha3::Sha3_512>(),
        "SHABAL192" => get_some::<shabal::Shabal192>(),
        "SHABAL224" => get_some::<shabal::Shabal224>(),
        "SHABAL256" => get_some::<shabal::Shabal256>(),
        "SHABAL384" => get_some::<shabal::Shabal384>(),
        "SHABAL512" => get_some::<shabal::Shabal512>(),
        "SM3" => get_some::<sm3::Sm3>(),
        "STREEBOG256" => get_some::<streebog::Streebog256>(),
        "STREEBOG512" => get_some::<streebog::Streebog512>(),
        "TIGER" => get_some::<tiger::Tiger>(),
        "WHIRLPOOL" => get_some::<whirlpool::Whirlpool>(),
        _ => None,
    };
    if let Some(h) = hasher {
        Ok(FixedHash { inner: h })
    } else {
        let err_msg = format!("unsupported hash algorithm: {}", algorithm);
        Err(JsValue::from_str(&err_msg))
    }
}

fn get_some<D: Digest + Update + FixedOutput + Reset + Clone + 'static>(
) -> Option<Box<dyn DynDigest>> {
    Some(Box::new(D::new()))
}
