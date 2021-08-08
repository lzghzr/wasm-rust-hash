use wasm_bindgen::prelude::*;

pub struct JShex {}

#[wasm_bindgen(js_name = hex)]
impl JShex {
    #[wasm_bindgen]
    pub fn decode(hex: &str) -> Result<Vec<u8>, JsValue> {
        match hex::decode(hex) {
            Ok(data) => Ok(data),
            _ => {
                let err_msg = format!("cannot decode: {}", hex);
                Err(JsValue::from_str(&err_msg))
            }
        }
    }
    #[wasm_bindgen]
    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }
}
