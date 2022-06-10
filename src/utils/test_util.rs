#[cfg(test)]
pub mod test {

    use crate::{
        decryptor::Decryptor,
        utils::rc4::{RC4Derive, RC4Standard},
    };
    use ring::digest::{Context, SHA256};

    #[allow(unused)]
    pub const TEST_SIZE_1MB: usize = 1024 * 1024;
    #[allow(unused)]
    pub const TEST_SIZE_2MB: usize = TEST_SIZE_1MB * 2;
    #[allow(unused)]
    pub const TEST_SIZE_3MB: usize = TEST_SIZE_1MB * 3;
    #[allow(unused)]
    pub const TEST_SIZE_4MB: usize = TEST_SIZE_1MB * 4;
    #[allow(unused)]
    pub const TEST_SIZE_8MB: usize = TEST_SIZE_1MB * 8;

    pub fn generate_test_data(len: usize, name: &str) -> Vec<u8> {
        let mut result = vec![0u8; len];

        let mut rc4 = RC4Standard::new(name.as_bytes());
        for v in result.iter_mut() {
            *v = rc4.next();
        }

        result
    }

    pub fn sha256(data: &[u8]) -> String {
        let mut context = Context::new(&SHA256);
        context.update(data);
        let result = context.finish();
        return data_encoding::HEXLOWER.encode(result.as_ref());
    }

    pub fn decrypt_test_content<T: AsRef<[u8]>>(decryptor: &mut impl Decryptor, data: T) -> String {
        let data = data.as_ref();
        decryptor.write(data).unwrap();
        decryptor.end().unwrap();
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
