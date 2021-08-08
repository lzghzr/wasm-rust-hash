use digest::generic_array::typenum::Unsigned;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use hmac::{Hmac, Mac, NewMac};
use wasm_bindgen::prelude::*;

trait DynHmac {
    /// Update MAC state with the given data.
    fn update(&mut self, data: &[u8]);

    /// Obtain the result of a [`Mac`] computation as a [`Output`] and reset
    /// [`Mac`] instance.
    fn finalize_reset(&mut self) -> Box<[u8]>;

    /// Obtain the result of a [`Mac`] computation as a [`Output`] and consume
    /// [`Mac`] instance.
    fn box_finalize(self: Box<Self>) -> Box<[u8]>;

    /// Reset [`Mac`] instance.
    fn reset(&mut self);

    /// Get output size of the [`Mac`].
    fn output_size(&self) -> usize;

    /// Clone  [`Mac`] state into a boxed trait object
    fn box_clone(&self) -> Box<dyn DynHmac>;

    /// Check if tag/code value is correct for the processed input.
    fn box_verify(self: Box<Self>, tag: &[u8]) -> bool;
}

impl<D: Mac + 'static> DynHmac for D {
    fn update(&mut self, data: &[u8]) {
        Mac::update(self, data);
    }

    fn finalize_reset(&mut self) -> Box<[u8]> {
        let res = self
            .clone()
            .finalize()
            .into_bytes()
            .to_vec()
            .into_boxed_slice();
        self.reset();
        res
    }

    fn box_finalize(self: Box<Self>) -> Box<[u8]> {
        self.finalize().into_bytes().to_vec().into_boxed_slice()
    }

    fn reset(&mut self) {
        Mac::reset(self);
    }

    fn output_size(&self) -> usize {
        <Self as Mac>::OutputSize::to_usize()
    }

    fn box_clone(&self) -> Box<dyn DynHmac> {
        Box::new(self.clone())
    }

    fn box_verify(self: Box<Self>, tag: &[u8]) -> bool {
        match self.verify(tag) {
            Ok(_) => true,
            _ => false,
        }
    }
}

#[wasm_bindgen]
pub struct FixedHmac {
    inner: Box<dyn DynHmac>,
}
#[wasm_bindgen]
impl FixedHmac {
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
        self.inner.box_finalize()
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
    pub fn clone(&mut self) -> FixedHmac {
        FixedHmac {
            inner: self.inner.box_clone(),
        }
    }
    #[wasm_bindgen]
    pub fn verify(self, tag: &[u8]) -> bool {
        self.inner.box_verify(tag)
    }
}
#[wasm_bindgen(js_name = createHmac)]
pub fn create_hmac(algorithm: &str, key: &str) -> Result<FixedHmac, JsValue> {
    let algorithm = algorithm.replace("-", "").to_ascii_uppercase();
    let algorithm = algorithm.as_str();
    let hasher: Option<Box<dyn DynHmac>> = match algorithm {
        "BLAKE2B512" => get_some::<blake2::Blake2b>(key),
        "BLAKE2S256" => get_some::<blake2::Blake2s>(key),
        "FSB160" => get_some::<fsb::Fsb160>(key),
        "FSB224" => get_some::<fsb::Fsb224>(key),
        "FSB256" => get_some::<fsb::Fsb256>(key),
        "FSB384" => get_some::<fsb::Fsb384>(key),
        "FSB512" => get_some::<fsb::Fsb512>(key),
        "GOST94CRYPTOPRO" => get_some::<gost94::Gost94CryptoPro>(key),
        "GOST94TEST" => get_some::<gost94::Gost94Test>(key),
        "GOST94S2015" => get_some::<gost94::Gost94s2015>(key),
        "GROESTL224" => get_some::<groestl::Groestl224>(key),
        "GROESTL256" => get_some::<groestl::Groestl256>(key),
        "GROESTL384" => get_some::<groestl::Groestl384>(key),
        "GROESTL512" => get_some::<groestl::Groestl512>(key),
        "MD2" => get_some::<md2::Md2>(key),
        "MD4" => get_some::<md4::Md4>(key),
        "MD5" => get_some::<md5::Md5>(key),
        "RIPEMD160" => get_some::<ripemd160::Ripemd160>(key),
        "RIPEMD256" => get_some::<ripemd256::Ripemd256>(key),
        "RIPEMD320" => get_some::<ripemd320::Ripemd320>(key),
        "SHA1" => get_some::<sha1::Sha1>(key),
        "SHA224" => get_some::<sha2::Sha224>(key),
        "SHA256" => get_some::<sha2::Sha256>(key),
        "SHA384" => get_some::<sha2::Sha384>(key),
        "SHA512" => get_some::<sha2::Sha512>(key),
        "SHA512224" => get_some::<sha2::Sha512Trunc224>(key),
        "SHA512256" => get_some::<sha2::Sha512Trunc256>(key),
        "KECCAK224" => get_some::<sha3::Keccak224>(key),
        "KECCAK256" => get_some::<sha3::Keccak256>(key),
        "KECCAK256FULL" => get_some::<sha3::Keccak256Full>(key),
        "KECCAK384" => get_some::<sha3::Keccak384>(key),
        "KECCAK512" => get_some::<sha3::Keccak512>(key),
        "SHA3224" => get_some::<sha3::Sha3_224>(key),
        "SHA3256" => get_some::<sha3::Sha3_256>(key),
        "SHA3384" => get_some::<sha3::Sha3_384>(key),
        "SHA3512" => get_some::<sha3::Sha3_512>(key),
        "SHABAL192" => get_some::<shabal::Shabal192>(key),
        "SHABAL224" => get_some::<shabal::Shabal224>(key),
        "SHABAL256" => get_some::<shabal::Shabal256>(key),
        "SHABAL384" => get_some::<shabal::Shabal384>(key),
        "SHABAL512" => get_some::<shabal::Shabal512>(key),
        "SM3" => get_some::<sm3::Sm3>(key),
        "STREEBOG256" => get_some::<streebog::Streebog256>(key),
        "STREEBOG512" => get_some::<streebog::Streebog512>(key),
        "TIGER" => get_some::<tiger::Tiger>(key),
        "WHIRLPOOL" => get_some::<whirlpool::Whirlpool>(key),
        _ => None,
    };

    if let Some(h) = hasher {
        Ok(FixedHmac { inner: h })
    } else {
        let err_msg = format!("unsupported hash algorithm: {}", algorithm);
        Err(JsValue::from_str(&err_msg))
    }
}

fn get_some<
    D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone + 'static,
>(
    key: &str,
) -> Option<Box<dyn DynHmac>> {
    Some(Box::new(
        Hmac::<D>::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size"),
    ))
}
