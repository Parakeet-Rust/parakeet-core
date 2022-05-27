#[cfg(test)]
pub mod test {

    use crate::decryptor::Decryptor;
    use ring::digest::{Context, SHA256};

    pub const TEST_SIZE_1MB: usize = 1 * 1024 * 1024;
    pub const TEST_SIZE_2MB: usize = TEST_SIZE_1MB * 2;
    pub const TEST_SIZE_3MB: usize = TEST_SIZE_1MB * 3;
    pub const TEST_SIZE_4MB: usize = TEST_SIZE_1MB * 4;
    pub const TEST_SIZE_8MB: usize = TEST_SIZE_1MB * 8;

    pub fn generate_test_data(len: usize, name: &str) -> Vec<u8> {
        let mut result = vec![0u8; len];

        let mut s = [0u8; 256];
        let key = name.as_bytes();
        let key_len = key.len();

        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key_len]);
            s.swap(i, usize::from(j));
        }

        let mut x = 0u8;
        let mut y = 0u8;
        for out in result.iter_mut() {
            x = x.wrapping_add(1);
            y = y.wrapping_add(s[usize::from(x)]);
            s.swap(usize::from(x), usize::from(y));

            let xx = s[usize::from(x)];
            let yy = s[usize::from(y)];
            *out = s[usize::from(xx.wrapping_add(yy))];
        }

        result
    }

    pub fn sha256(data: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let result = context.finish();
        return data_encoding::HEXLOWER.encode(result.as_ref());
    }

    pub fn decrypt_test_content(decryptor: &mut impl Decryptor, data: &[u8]) -> String {
        decryptor.init_footer(&data[..]);
        decryptor.write(&data[..]);
        decryptor.end();
        sha256(decryptor.read_all_output().as_ref())
    }

    #[test]
    fn hash_check() {
        let result = sha256(b"Parakeet");
        assert_eq!(
            result,
            "e6d539d8f612fe194b15aabb195a896b9dbe3eb4fd49dc0ae08d9740ef215a7b"
        );
    }

    #[test]
    fn generate_data_check() {
        let data = generate_test_data(256, "test_data_stable");
        let result = sha256(data.as_slice());
        assert_eq!(
            result,
            "cdffdcbb64563d64c7d56cf02dfe8f2642d9075ff6215aa61378541617ab6cb3"
        );
    }
}
