const KUWO_DECRYPTION_KEY_SIZE: usize = 0x20;
type KuwoKey = [u8; KUWO_DECRYPTION_KEY_SIZE];

mod detail {
    use super::KuwoKey;
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, DecryptErrorCode, Decryptor},
        utils::array_ext::ByteSliceExt,
    };
    use std::cmp::Ordering;

    const FILE_KEY_OFFSET: usize = 0x18;
    const FULL_HEADER_SIZE: usize = 0x400;
    const KUWO_MAGIC_HEADER: [u8; 0x10] = [
        0x79u8, 0x65, 0x65, 0x6c, 0x69, 0x6f, 0x6e, 0x2d, //
        0x6bu8, 0x75, 0x77, 0x6f, 0x2d, 0x74, 0x6d, 0x65, //
    ];

    enum State {
        WaitForHeader,
        Decrypt,
    }

    struct KuwoDecryptor {
        data: BaseDecryptorData,
        key: KuwoKey,
        state: State,
    }

    impl KuwoDecryptor {
        fn new(key: &KuwoKey) -> Self {
            Self {
                data: BaseDecryptorData::new("Kuwo"),
                key: *key,
                state: State::WaitForHeader,
            }
        }

        fn init_key(&mut self) {
            let resource_id = self.data.buf_in.read_le::<u64>(FILE_KEY_OFFSET);
            let resource_id = resource_id.to_string();
            self.key.xor_key(resource_id.as_bytes());
        }
    }

    impl Decryptor for KuwoDecryptor {
        #[inline(always)]
        fn get_data(&self) -> &BaseDecryptorData {
            &self.data
        }

        #[inline(always)]
        fn get_data_mut(&mut self) -> &mut BaseDecryptorData {
            &mut self.data
        }

        fn write(&mut self, data: &[u8]) -> Result<(), DecryptError> {
            let mut p = data;

            while !p.is_empty() {
                match self.state {
                    State::WaitForHeader => {
                        if self.data.read_until_offset(&mut p, FULL_HEADER_SIZE) {
                            if self.data.buf_in[..KUWO_MAGIC_HEADER.len()].cmp(&KUWO_MAGIC_HEADER)
                                != Ordering::Equal
                            {
                                return Err(DecryptError::new(
                                    DecryptErrorCode::UnknownMagicHeader,
                                    "unknown magic header",
                                ));
                            }

                            self.init_key();
                            self.data.consume_bytes(FULL_HEADER_SIZE);
                            self.state = State::Decrypt;
                        }
                    }

                    State::Decrypt => {
                        let size = p.len();
                        let mut out = Vec::from(p);
                        out.xor_key_with_key_offset(self.key, self.data.offset);
                        self.data.buf_out.append(&mut out);
                        self.data.offset += size;
                        return Ok(());
                    }
                }
            }

            Ok(())
        }
    }

    pub fn new_kwm(key: &KuwoKey) -> impl Decryptor {
        KuwoDecryptor::new(key)
    }
}

pub use detail::new_kwm;

#[cfg(test)]
mod test {
    use crate::utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_4MB};

    #[test]
    fn test_kwm() {
        let test_key = generate_test_data(super::KUWO_DECRYPTION_KEY_SIZE, "kuwo-test-key");
        let mut test_data = generate_test_data(TEST_SIZE_4MB, "kuwo-data-1");
        test_data[..32].copy_from_slice(&[
            0x79, 0x65, 0x65, 0x6c, 0x69, 0x6f, 0x6e, 0x2d, //
            0x6b, 0x75, 0x77, 0x6f, 0x2d, 0x74, 0x6d, 0x65, //
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0xFF, 0xEE, 0xDD, 0x11, 0x22, 0x33, 0x00, 0x00, //
        ]);

        let mut decryptor = super::new_kwm(test_key[..].try_into().unwrap());
        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "aefad6b6f75ecb915fd0211f02eeacbd9c28e51b22c06c6d1bb3c61c963feaae"
        );
    }
}
