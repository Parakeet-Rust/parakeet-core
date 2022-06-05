use std::ops::Mul;

fn simple_make_key(seed: u8, size: usize) -> Box<[u8]> {
    let seed = seed as f32;
    let mut result = vec![0u8; size].into_boxed_slice();

    for (i, v) in result.iter_mut().enumerate() {
        let i = i as f32;
        let angle = seed + i * 0.1;
        *v = angle.tan().abs().mul(100.0) as u8;
    }

    result
}

fn derive_tea_key(ekey_header: &[u8]) -> Box<[u8]> {
    let simple_key_buf = simple_make_key(106, 8);

    let mut tea_key = [0u8; 16];
    for i in (0..16).step_by(2) {
        tea_key[i] = simple_key_buf[i / 2];
        tea_key[i + 1] = ekey_header[i / 2];
    }

    Box::from(tea_key)
}

pub fn parse_ekey(ekey: &str) -> Option<Box<[u8]>> {
    let ekey_decoded = base64::decode(ekey).ok()?;

    if ekey_decoded.len() < 8 {
        return None;
    }

    let (header, body) = ekey_decoded.split_at(8);
    let tea_key = derive_tea_key(header);
    let decrypted = tc_tea::decrypt(body, &tea_key)?;

    Some([header, &*decrypted].concat().into())
}

pub fn generate_ekey<T: AsRef<[u8]>>(key: T) -> String {
    // Generate encrypted version of the key...
    let (key_header, key_body) = key.as_ref().split_at(8);
    debug_assert_eq!(key_header.len(), 8);

    let tea_key = derive_tea_key(key_header);
    debug_assert_eq!(tea_key.len(), 16);

    let encrypted_body = tc_tea::encrypt(key_body, tea_key).unwrap();
    let ekey_encoded = [key_header, &*encrypted_body].concat();

    base64::encode(ekey_encoded)
}
