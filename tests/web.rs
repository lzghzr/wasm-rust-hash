//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use hex::encode;
use wasm_bindgen_test::*;
use wasm_rust_hash::create_hash;

wasm_bindgen_test_configure!(run_in_browser);

fn hash(algorithm: &str, data: &str) -> String {
    let mut hasher = create_hash(algorithm).unwrap();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    encode(hash)
}

#[wasm_bindgen_test]
fn blacke2_test(){
    assert_eq!(hash("BLAKE2b512", ""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    assert_eq!(hash("BLAKE2b512", "\n"), "ca6914d2e33b83f2b2c66e4e625bc1d08674fae605008a215165d3c3a997d7d92945905207a539a7327be0f2728fa9aee005da9641407e5f3e4ef55b446b470a");
    assert_eq!(hash("BLAKE2b512", "🐛"), "af8267e87cd7ec5fc3b49a8a5d1bed90e48d34cc4df38d6a1129c2396a0a74a6f86c7cee9b0d18f3281b38568726718e6ddd4cd4595bfb2226a30eac81f4248a");

    assert_eq!(hash("BLAKE2s256", ""), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    assert_eq!(hash("BLAKE2s256", "\n"), "6fa16ac015c6513f6b98ee9e3f771ca8324a0ce77fbb9337fe3f8f549643dc73");
    assert_eq!(hash("BLAKE2s256", "🐛"), "8d3319f1d277fb040f0628c47f6c2a315c489ce51e00df7b71fa7ded93db5fb8");
}
#[wasm_bindgen_test]
fn fsb_test(){
    assert_eq!(hash("FSB-160", ""), "bd874daa024be58a7bb2725914132819f9c64c2e");
    assert_eq!(hash("FSB-160", "\n"), "e64dcb9b93851baf45a0b22bcd28867737a29476");
    assert_eq!(hash("FSB-160", "🐛"), "8a2a36b8828ec0265cbc9bda6e11379de7936017");

    assert_eq!(hash("FSB-224", ""), "c66ded00ab44a5d29b16133a7078cdb431e8d089ec6fdef7d265b554");
    assert_eq!(hash("FSB-224", "\n"), "e6965c81679a1d64f471a35002d96a4141efec932f1cbb0e5d863928");
    assert_eq!(hash("FSB-224", "🐛"), "20fda426bf1b5a5f2c87933ad080a50a05265d9915026b010b96c3f8");

    assert_eq!(hash("FSB-256", ""), "344eaf42ab2a9716a07cfd61d6e717a341b701162cbabc71673f9599167bb0b0");
    assert_eq!(hash("FSB-256", "\n"), "e5f96e799bb3e509de194911d5bc2daebd3c509f6ca1af75913d360b845ab17a");
    assert_eq!(hash("FSB-256", "🐛"), "81e189e4587ebc7e425c09c9b42a354eb359ac8cd911f17ca9bf8d50fead3942");

    assert_eq!(hash("FSB-384", ""), "ed1f3e8d9c5f9af16d82a80043b227e3cd942453d5bd55222d62270c3aca8cc608ed16aba4202b59c194d5e783d80cca");
    assert_eq!(hash("FSB-384", "\n"), "09472d120cbba7c4f413df470b1c3a5cd7aad108957eb669b1f70456ab8c063199f395a527d5e416ed5d31ca637684fb");
    assert_eq!(hash("FSB-384", "🐛"), "36ef1cbd45a92a3f5b7ea696056644fabf4cf7bbc9f090a934224e213e3c700a00a03ab38524ea3c4b3f22e55309406f");

    assert_eq!(hash("FSB-512", ""), "a60c6ba0e439d4a2137252e34623e1b1a0a35bff1d3893c11b0a31db8d9063990bee6c3084b24aea384c3ea08866d643fadeb679959778636a950b95da5c93f9");
    assert_eq!(hash("FSB-512", "\n"), "0d652529baa1254b234df8d4441f5a9e60ae5380528c388ba3ebde3a15a67d7e29590bf600bd90271ceac3a396d32a272ccb3977df4e99b043a7a616868ee2ed");
    assert_eq!(hash("FSB-512", "🐛"), "9877e7e27cfd435819772f8fee21f91a300909cf1a1d0012c21df981a0c8238447369f3e2fd00611a5966b29848dc9543d29a56ef8268ed79b00a1669e76dc40");
}
#[wasm_bindgen_test]
fn gost94_test(){
    assert_eq!(hash("GOST94CRYPTOPRO", ""), "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0");
    assert_eq!(hash("GOST94CRYPTOPRO", "\n"), "104dcb6704d80e35e88be1ff83a78232508c8dbfda9d054360a4cd8ecc91f6bb");
    assert_eq!(hash("GOST94CRYPTOPRO", "🐛"), "1b9d9a1dcecfefadfc07da991ac98647d7652e7c9b01a94e6f6db07d18bd24cc");

    assert_eq!(hash("GOST94TEST", ""), "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d");
    assert_eq!(hash("GOST94TEST", "\n"), "befe094bd7074192bbf81f6b795d641c26b744ebe24e02b0f114aacf9db095db");
    assert_eq!(hash("GOST94TEST", "🐛"), "4ae0544e86e005a8fa9a290b5696c7622146f0e81e70d09f12036bc2c1c0c600");

    assert_eq!(hash("GOST94S2015", ""), "d47819718a633fa42ff02a4d1c7180da02178067aeb4b1490388c84f88538d80");
    assert_eq!(hash("GOST94S2015", "\n"), "2118cc65f2cd98dac7b18a03bebdca7cb9ade940fdce1cbd201c3536b5f28195");
    assert_eq!(hash("GOST94S2015", "🐛"), "487b70309812babc9eaece7639d50ac765cf0d468d197d3e99a0c381804cd7a8");
}
#[wasm_bindgen_test]
fn groestl_test(){
    assert_eq!(hash("GROESTL224", ""), "f2e180fb5947be964cd584e22e496242c6a329c577fc4ce8c36d34c3");
    assert_eq!(hash("GROESTL224", "\n"), "78e377050faac1ea86591fe54ff711f839d2fad50dae60c106d37e54");
    assert_eq!(hash("GROESTL224", "🐛"), "9a373f7cf8bbfba19b10c0ff6620e67cf295ffb9cc5718425623fbd5");

    assert_eq!(hash("GROESTL256", ""), "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467");
    assert_eq!(hash("GROESTL256", "\n"), "bbd753a876f29b5530a8c2cf1a48af75d1951cade85ba1eaf358d352a23f71cc");
    assert_eq!(hash("GROESTL256", "🐛"), "746bdfa1ca8b21b2a32d8180d687a62ccdc266439919ce0bd2c3b20ac7340f5d");

    assert_eq!(hash("GROESTL384", ""), "ac353c1095ace21439251007862d6c62f829ddbe6de4f78e68d310a9205a736d8b11d99bffe448f57a1cfa2934f044a5");
    assert_eq!(hash("GROESTL384", "\n"), "72acaea4f625e8e44919a03dd3607571bb1228c4080b3a9222e2a7afe68545844df0e9b16fc3825444f3c73f733c86bd");
    assert_eq!(hash("GROESTL384", "🐛"), "086f25cbe8a575e808fc47c1b0f2942f6317259e7aae4c92818f8b6f03ff03331f7c50c9e2752adfab42d75a93e17f79");

    assert_eq!(hash("GROESTL512", ""), "6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8");
    assert_eq!(hash("GROESTL512", "\n"), "80c241c83def5f3288f15db231c90aaea09168a8a0dae432d106fd059a20fb89ec409e82c14f285faf0c0d62044e19c3a0d4081b31502e60b948365905f345a0");
    assert_eq!(hash("GROESTL512", "🐛"), "33958919db9603d6675510565fe237b01a1483bd24331cdbed92b4041b31122d048273ad209354c3572231634a22ab24144d598eb866bd0309d084acffaa0c7c");
}
#[wasm_bindgen_test]
fn md_test(){
    assert_eq!(hash("MD2", ""), "8350e5a3e24c153df2275c9f80692773");
    assert_eq!(hash("MD2", "\n"), "69ff599f4876487a24a0cea9543f44c8");
    assert_eq!(hash("MD2", "🐛"), "89ff1eaee426e655e35bc94e3a658341");

    assert_eq!(hash("MD4", ""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(hash("MD4", "\n"), "8c5b220bf6f482881a90287a64aea150");
    assert_eq!(hash("MD4", "🐛"), "a368384372098ea866ce59714724037d");

    assert_eq!(hash("MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hash("MD5", "\n"), "68b329da9893e34099c7d8ad5cb9c940");
    assert_eq!(hash("MD5", "🐛"), "af5bfd1a04de935ff26b33d06bd21aa9");
}
#[wasm_bindgen_test]
fn ripemd_test(){
    assert_eq!(hash("RIPEMD160", ""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    assert_eq!(hash("RIPEMD160", "\n"), "c0da025038ed83c687ddc430da9846ecb97f3998");
    assert_eq!(hash("RIPEMD160", "🐛"), "14d7c1266e8b1cc6d481f37a97855a7c48b227ed");

    assert_eq!(hash("RIPEMD256", ""), "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d");
    assert_eq!(hash("RIPEMD256", "\n"), "57ed62c899ff2df59a080fa913c6775e6f8e149d180d7ec73ba6c5fced3dc060");
    assert_eq!(hash("RIPEMD256", "🐛"), "895ba1b9755df1c5de0e0a1b884d4e5190dd0ee6328fb609694fc287646a2f7b");

    assert_eq!(hash("RIPEMD320", ""), "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8");
    assert_eq!(hash("RIPEMD320", "\n"), "ed2e1f34b135b34b9ca9fe2a31719307761334951ea1a649db8cd4c3857ef23521d821427d2698c4");
    assert_eq!(hash("RIPEMD320", "🐛"), "9cb6b58fe87b87e0d92eebe6e60dad718f6c2cf716f6acdcec62e4020b76eaff5e3e1d06f3606669");
}
#[wasm_bindgen_test]
fn sha1_test(){
    assert_eq!(hash("SHA1", ""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hash("SHA1", "\n"), "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc");
    assert_eq!(hash("SHA1", "🐛"), "007a4b2695258a38d1aed63006cfa67274a709bf");
}
#[wasm_bindgen_test]
fn sha2_test(){
    assert_eq!(hash("SHA224", ""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    assert_eq!(hash("SHA224", "\n"), "48837a787f07673545d9c610bcbcd8d46a2691a71966d856c197e69e");
    assert_eq!(hash("SHA224", "🐛"), "f43a9f71d3ebc0609d1436e48d8464b04b2c77fba3386aa63a61e729");

    assert_eq!(hash("SHA256", ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash("SHA256", "\n"), "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b");
    assert_eq!(hash("SHA256", "🐛"), "e41b4d360aa797e3e78da2e8d3e0d7c6d1449dd1d04359ea38fa10461d1037d6");

    assert_eq!(hash("SHA384", ""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert_eq!(hash("SHA384", "\n"), "ec664e889ed6c1b2763cacf7899d95b7f347373eb982e523419feea3aa362d891b3bf025f292267a5854049091789c3e");
    assert_eq!(hash("SHA384", "🐛"), "6b3b3abf96cceb8757386800b2c511fddf6aec2e7a7161a32f45543f38b49a6682e97b005803ebd18e859583a0867d55");

    assert_eq!(hash("SHA512", ""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert_eq!(hash("SHA512", "\n"), "be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09");
    assert_eq!(hash("SHA512", "🐛"), "2f74e2b5aa6d091c9362ee23f88280a059255533e8bc3b11de6aa2e37c871865a0aa6953f43b33fb55bfe8b31a435648260c48532db7940c388ae637ec5a111c");

    assert_eq!(hash("SHA512/224", ""), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    assert_eq!(hash("SHA512/224", "\n"), "bba8292cc455595f768816333c6eb3099d9c712885159cc004a9f73f");
    assert_eq!(hash("SHA512/224", "🐛"), "25af788ee6aef1340fd08f75d331bed006991b961ba3f4b850987877");

    assert_eq!(hash("SHA512/256", ""), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    assert_eq!(hash("SHA512/256", "\n"), "03fe1ceaa32b17bff9a713f0693ac8f75c568be3cf50d90199cc436ab1bfde74");
    assert_eq!(hash("SHA512/256", "🐛"), "6ed1fd223d2fc47988dc6955ad998207de0639115443c570d5b1f20de9bb43cf");
}
#[wasm_bindgen_test]
fn keccak_test(){
    assert_eq!(hash("KECCAK224", ""), "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd");
    assert_eq!(hash("KECCAK224", "\n"), "5a57ddc617f614573bec720bfd36e45d86bf64a0062afee7bb67c049");
    assert_eq!(hash("KECCAK224", "🐛"), "b3df43cc0a22f5036a132be4200a8d721ded4ad08224430eb6f54a84");

    assert_eq!(hash("KECCAK256", ""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    assert_eq!(hash("KECCAK256", "\n"), "0ef9d8f8804d174666011a394cab7901679a8944d24249fd148a6a36071151f8");
    assert_eq!(hash("KECCAK256", "🐛"), "1538e0a9b0cfe8064b97a97e15d21945248e520f261f318d1a20fec4e9bfd0f0");

    assert_eq!(hash("KECCAK256FULL", ""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4703dbb9a2cd87ca974b9a2b0ec61119bcb5cedf9c0c411221f6141a25f17c60d82d24680abbcbfba815b762b24b751d5b1e85325ba5e6df23c10725bfe986ace3ba2d24535a79f7dbabb153bb0d33c0dfa09cec712ebd7fe3b49a9194e859c82ebff11a645651a5d1b726be100f44641069fab7164e13487fe3609bbeebd88309cbaacb2a7ecb8e8de2145cf1db7623b16916d7210991b576bbe182362cf22fab7d7af9f77f71afea3");
    assert_eq!(hash("KECCAK256FULL", "\n"), "0ef9d8f8804d174666011a394cab7901679a8944d24249fd148a6a36071151f834ec64ce0a7d6b7416d5ef840f7a74510d76c263815bf7077e6e25a138dab82a97c7521631fb82576292b7fbd06e091c582523d6ba71e3bff0c3e40622659f47975843a69e33cc79bd6b4efe4c7d62f80cb00076e9592ab70709fa2ee1ab8c0e41ae57668cc9113bdf2311a09c30ff6cfea68913ef89f01b5ccc944ba2a082f948bd70d3dc475ae3b902ed14c9c06ba43f740d0cfe408239417c57390b6b46ab9fcbeaaa2299111a");
    assert_eq!(hash("KECCAK256FULL", "🐛"), "1538e0a9b0cfe8064b97a97e15d21945248e520f261f318d1a20fec4e9bfd0f07f0232494ad6d2395aa37bb70f9b8be59d4d34d4f13c2ba1f6324c5735bf8c06981d5ba4b4064fc6f28c7c10372de344611fb757456ffc01551ef747c971ffd61ecf11e8621c2d0b6be0f0e0155ba53009009ef11431b8ba81bde5b599dd6a71f42e8d8a0a0a74fad24c0df19cb2d68bf8402e3d4de8da06e5a3ce0b664a0a13d5c757e76c8aab530afb7f9acb9c77801e3a33e18f3d68eb22e16ecab14b92fd6c03b2086c142bbe");

    assert_eq!(hash("KECCAK384", ""), "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
    assert_eq!(hash("KECCAK384", "\n"), "7c5693398d443087ad2558a6cb2dcf3a9c502ef4f4121cc4292e0764befd629124e8c5e982c58925ed585979629e9f43");
    assert_eq!(hash("KECCAK384", "🐛"), "7c222a1b03df28d807657cf12077ab0ccfb6b8dc936b0f44a00316219a4a8dc102396ac44a798993bf2b81d52c3c34e6");

    assert_eq!(hash("KECCAK512", ""), "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
    assert_eq!(hash("KECCAK512", "\n"), "e0a651904afe783ec83eeb586a2e602a09c43a3c6d795549ed7a58caae661074beaccd16d470ce4eac3ba98feee94bead3916ef4a75c15011f07df348ce7a9e7");
    assert_eq!(hash("KECCAK512", "🐛"), "9a0a0a67332efda8f8d116d7c469ec631c4b8b7c20e4f44833b22efc713be41b65eeec744dad67ac72eb44eb6eef503904d72aa65d094f72ac5d44e8c2799a8f");
}
#[wasm_bindgen_test]
fn sha3_test(){
    assert_eq!(hash("SHA3-224", ""), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    assert_eq!(hash("SHA3-224", "\n"), "789273e7012d1d3a08818f0c301f6def0d27db7afb36933813b2c60d");
    assert_eq!(hash("SHA3-224", "🐛"), "12ea9a5cb0536a4ef33c8704ee7f985ba12fcf62aa54cffd5e824bb9");

    assert_eq!(hash("SHA3-256", ""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(hash("SHA3-256", "\n"), "a78f2c566b2439463a2e7ca515bbfa3f92948506583cbadaebdd507f277542bd");
    assert_eq!(hash("SHA3-256", "🐛"), "9cee5c5b569fcec4283722f307fb2113e316617ea9a772de00d5ca45467f1db6");

    assert_eq!(hash("SHA3-384", ""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert_eq!(hash("SHA3-384", "\n"), "50b02220a63bff173fe3943243ad4036f49572e97b4be4f71593bb05e342eb220e7b2a286488cf479bef039c1ab53326");
    assert_eq!(hash("SHA3-384", "🐛"), "58b8a93d4f6003f9db9ebb3c1d68422ea27eaaf6c3c3facf640044ad2d77f08e1aeb67e55e30b0740ac39b7bdf34095c");

    assert_eq!(hash("SHA3-512", ""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    assert_eq!(hash("SHA3-512", "\n"), "7186d65cda74aa1f4263638c0da5444614b8186935508a1d6d2b3afc53e9523ecb0f269590a7eb4d15dd60331359934f78c41a007807f6b394d3f7d059fb6638");
    assert_eq!(hash("SHA3-512", "🐛"), "9199ab1fc8eb43f1449010584f4876563f7f15990f98ded535c589c50f849ec0ce7c1f11bb538cb64c524fc0392109258f2339dc6ad67e65517aa630f1078e45");
}
#[wasm_bindgen_test]
fn shabal_test(){
    assert_eq!(hash("SHABAL192", ""), "e10dc32232f98b039dbbcfa41269b9cdf67a73c841214c81");
    assert_eq!(hash("SHABAL192", "\n"), "ccb8d79ed33093f17cd2810cb957bb14093a3a975989d4c7");
    assert_eq!(hash("SHABAL192", "🐛"), "60f336db9c47793a63452db8b21d0165fccf526e088a99ca");

    assert_eq!(hash("SHABAL224", ""), "562b4fdbe1706247552927f814b66a3d74b465a090af23e277bf8029");
    assert_eq!(hash("SHABAL224", "\n"), "433080d5508b96420add0e7406149934e745eb1890355301de44bb37");
    assert_eq!(hash("SHABAL224", "🐛"), "51f602bb57898c45699776e7a0dfe9b428270724669744ce69769d85");

    assert_eq!(hash("SHABAL256", ""), "aec750d11feee9f16271922fbaf5a9be142f62019ef8d720f858940070889014");
    assert_eq!(hash("SHABAL256", "\n"), "a99cdd7dde346fefd831724d9abc791977eda30b9d42115792b14cf3eacb6711");
    assert_eq!(hash("SHABAL256", "🐛"), "ed7e22aa3e87a987e701cd1a5057d1fc2c6b9cdcdf9972e08212f2c53a35c401");

    assert_eq!(hash("SHABAL384", ""), "ff093d67d22b06a674b5f384719150d617e0ff9c8923569a2ab60cda886df63c91a25f33cd71cc22c9eebc5cd6aee52a");
    assert_eq!(hash("SHABAL384", "\n"), "0615d4b9404b5a68703adbc8181f4e6e33b7455280b7e681bb74c825e43a0d0252b2fc6ab5408420a281847908e739e6");
    assert_eq!(hash("SHABAL384", "🐛"), "d84c3223e220caf3817449259377d66fd0670b3869029491adddca8548dd7f0a364e6426babfe9fb15bec7ff8c1ef467");

    assert_eq!(hash("SHABAL512", ""), "fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19ccffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6");
    assert_eq!(hash("SHABAL512", "\n"), "dfb9a9ee9d55b33f2daffe125a71b8fecb065daed5ac0a7089f79dd78c16e238ac021f7cc2b8d4d165998dcd591335d0fb72f1556ea7de42664d61872c8bde87");
    assert_eq!(hash("SHABAL512", "🐛"), "cbe02652d7fe05e73447a4caf000f30de867c1a6756dfb4c1e69f81f2b750c1e5b4b6c40ae969c42907cccc475bb93c0ec15c1503b6a5c39504780decd6c83eb");
}
#[wasm_bindgen_test]
fn sm3_test(){
    assert_eq!(hash("SM3", ""), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
    assert_eq!(hash("SM3", "\n"), "f4051d239b766c4111e92979aa31af0b35def053646e347bc41e8b73cfd080bc");
    assert_eq!(hash("SM3", "🐛"), "4bde381b4bbf440783813bc90bee5d61d79b53850739ba74ea2b647586b25910");
}
#[wasm_bindgen_test]
fn streebog_test(){
    assert_eq!(hash("STREEBOG256", ""), "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb");
    assert_eq!(hash("STREEBOG256", "\n"), "dc58a5f63ae427332cc98d50b3bec203690cbed2b3a02729ae76fc98a6c3c4dd");
    assert_eq!(hash("STREEBOG256", "🐛"), "1c1cfa91bcfdd69227eaffae8d8ebfd71e9ea5be7a3b1fe5601e013b3f7e6334");

    assert_eq!(hash("STREEBOG512", ""), "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a");
    assert_eq!(hash("STREEBOG512", "\n"), "cf66c744ed58fdc5fbdf8b5c00bb819a967ebbca140f115456da01b25c08baa5228def0ad37622737e435eeaf5d8b1876220a2a13b38afd5768c2b2df8f47199");
    assert_eq!(hash("STREEBOG512", "🐛"), "83fa8a27ff3a03f005323000b9e51e979b2bda107ac4c2d5c2edefb0a6c39530515b8d5396038376918d2bfd10c0ebf4aea1870a44647cb8018d8c408c723390");
}
#[wasm_bindgen_test]
fn tiger_test(){
    assert_eq!(hash("TIGER", ""), "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
    assert_eq!(hash("TIGER", "\n"), "3684a70e5a8487f995490109dbe4f97b3417899cc9270f81");
    assert_eq!(hash("TIGER", "🐛"), "75285f71d1c79c5aedaa1c91a05badae122e5a29bd3369c3");
}
#[wasm_bindgen_test]
fn whirlpool_test(){
    assert_eq!(hash("WHIRLPOOL", ""), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    assert_eq!(hash("WHIRLPOOL", "\n"), "898126aab982feb2e4b99fee1e4b1cfb4208c76f35945119d24de8744016b56666dabeed478e3a9a36032bc9b8da05db7e79156dc76a7447ad0d39067745de1e");
    assert_eq!(hash("WHIRLPOOL", "🐛"), "1cfc4006913483e3968318459778fb93b1b9cba2695885326f277d0050e4d7b8bda80f3649350d40111aee9e17c32cafd09f5e0601825132430c9d7dd6e4a1b3");
}