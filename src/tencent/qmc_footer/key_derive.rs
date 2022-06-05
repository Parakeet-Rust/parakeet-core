use std::ops::Mul;

#[inline]
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

#[inline]
fn derive_tea_key(ekey_header: &[u8]) -> Box<[u8]> {
    let simple_key_buf = simple_make_key(106, 8);

    let mut tea_key = [0u8; 16];
    for i in (0..16).step_by(2) {
        tea_key[i] = simple_key_buf[i / 2];
        tea_key[i + 1] = ekey_header[i / 2];
    }

    Box::from(tea_key)
}

#[inline]
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

#[cfg(test)]
mod test {
    use crate::utils::test_util::test::generate_test_data;

    #[test]
    fn test_ekey_generation() {
        let mut test_key = generate_test_data(512, "qmcv2 rc4 cipher key");
        test_key[0..8].fill(b'4');

        let pre_generated_key = concat!(
            "NDQ0NDQ0NDQeUefW/SNkzbCL/cLZx5vkzk/fVdAN3tJaTQt6ES1bX3qHHwYFJKiFcQBYf1bU1Ywf",
            "jzpJxGa1tmLwuLL648K5zYEzPDQzigPQyi55pfR9MZxTC5LoCwWj5LK6kaLoWs3yzQ0rDkMEpfbp",
            "s1hl+0Xo341OI9uTrJ8MFK3OiihEXItE74RCDB5fLpuGB1M+WMdETNR6F2Yd+QdKZcIrXiJXOmCu",
            "5zvxFPxSq6ofpg23K4NM26Z/nGgeWIHQqVqCXaXmKiKTSYSpdtbqNsITUa0PqEbLF0h0ZjQba2+N",
            "3udJPQJRUMJKbhpIvlJWoHDQzy5D4fmgf49aPYwx5daPRCnA9t7MfbExXguDHKtRHGyUbNJD5OZ3",
            "CHOe5sa+7AxQ+64qhyzaXTi4wM4mNn/EZxIwFzTIGGqzv11qOZFaWhgNBUPorMiMZe0BpF4OdCZG",
            "AXh/MBFp79Ruoiwp/nhp9AodEyEC8ni2rjaJGe33wjNpjzL5HUq4qiax1t6o+KcUdmZvQdx+wfo5",
            "gSkavob1Bwm5Nyq93YnPnXEttR2pp+c04fmpdIPu0OQgaX0WPsTYRO7i4xAab2s77UiVP4IXxsY8",
            "aHzDG3IRMalr7fHFLLVSX9bqlk8kigao5gho2/oZD6eT1Uct59WesYQ/q3yST0PCSMCCefwONYgI",
            "8IcRDCzOgguq/P3uZpO9"
        );

        match super::parse_ekey(pre_generated_key) {
            Some(key) => {
                assert_eq!(key.as_ref(), test_key);
            }

            None => {
                panic!("should generate key")
            }
        }
    }
}
