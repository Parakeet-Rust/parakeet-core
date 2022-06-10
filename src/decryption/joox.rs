mod detail {
    use std::num::NonZeroU32;

    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, DecryptErrorCode, Decryptor},
        utils::array_ext::ByteSliceExt,
    };
    use aes::Aes128;
    use cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecrypt, KeyInit};
    use ring::{digest, pbkdf2};

    enum State {
        ReadFileMagic,
        SeekToBody(usize),
        DecryptOtherBlock,
        DecryptPaddingBlock,
    }

    struct JooxDecryptor {
        data: BaseDecryptorData,
        state: State,

        aes: Aes128,
        block_count: usize,
    }

    const JOOX_V04_MAGIC: u32 = u32::from_be_bytes(*b"E!04");
    const JOOX_V04_HEADER_SIZE: usize = 12; // 'E!04' + u64_be(file size)

    const JOOX_V04_AES_BLOCK_SIZE: usize = 128 / 8;
    const JOOX_V04_ENCRYPTION_BLOCK_SIZE: usize = 0x100000; // 1MiB
    #[allow(dead_code)]
    const JOOX_V04_DECRYPTION_BLOCK_SIZE: usize = JOOX_V04_ENCRYPTION_BLOCK_SIZE + 0x10;
    const JOOX_V04_BLOCK_COUNT_PER_ITERATION: usize =
        JOOX_V04_ENCRYPTION_BLOCK_SIZE / JOOX_V04_AES_BLOCK_SIZE;

    const JOOX_UUID_SALT: &[u8; 16] = &[
        0xa4, 0x0b, 0xc8, 0x34, 0xd6, 0x95, 0xf3, 0x13, //
        0x23, 0x23, 0x43, 0x23, 0x54, 0x63, 0x83, 0xf3, //
    ];

    impl JooxDecryptor {
        fn new(uuid: &str) -> Self {
            let mut pbkdf2_output = [0u8; digest::SHA1_OUTPUT_LEN];
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA1,
                unsafe { NonZeroU32::new_unchecked(1000) },
                JOOX_UUID_SALT,
                uuid.as_bytes(),
                &mut pbkdf2_output,
            );
            let aes_key = &pbkdf2_output[..16];

            Self {
                data: BaseDecryptorData::new("Joox"),
                state: State::ReadFileMagic,
                aes: Aes128::new_from_slice(aes_key).ok().unwrap(),
                block_count: 0,
            }
        }

        #[inline(always)]
        fn decrypt_aes_block(&mut self) {
            let mut data = [0u8; JOOX_V04_AES_BLOCK_SIZE];
            data.copy_from_slice(&self.data.buf_in[0..JOOX_V04_AES_BLOCK_SIZE]);
            self.data.seek_input(JOOX_V04_AES_BLOCK_SIZE);
            self.data.offset += JOOX_V04_AES_BLOCK_SIZE;
            let mut block = GenericArray::from(data);
            self.aes.decrypt_block(&mut block);
            self.data.buf_out.extend_from_slice(block.as_slice());
        }

        #[inline]
        fn decrypt_aes_padding_block(&mut self) -> Result<(), DecryptError> {
            let mut data = [0u8; JOOX_V04_AES_BLOCK_SIZE];
            data.copy_from_slice(&self.data.buf_in[0..JOOX_V04_AES_BLOCK_SIZE]);
            self.data.offset += JOOX_V04_AES_BLOCK_SIZE;
            let data_input = data;
            self.data.seek_input(JOOX_V04_AES_BLOCK_SIZE);
            let mut block = GenericArray::from(data);

            self.aes
                .decrypt_padded::<Pkcs7>(&mut block)
                .map_err(|_| {
                    let _a = data_input;
                    let _b = self.data.offset;
                    DecryptError::new(DecryptErrorCode::AESParamError, "un-pad error")
                })
                .map(|result| {
                    self.data.buf_out.extend_from_slice(result);
                })
        }
    }

    impl Decryptor for JooxDecryptor {
        crate::impl_decryptor_inner_helper! {}

        fn end(&mut self) -> Result<(), DecryptError> {
            self.decrypt_aes_padding_block()
        }

        fn write(&mut self, data: &[u8]) -> Result<(), DecryptError> {
            let mut p = data;

            while !p.is_empty() {
                match self.state {
                    State::ReadFileMagic => {
                        if self.data.read_until_offset(&mut p, 4) {
                            let magic = self.data.buf_in.read_be::<u32>(0);
                            if magic != JOOX_V04_MAGIC {
                                return Err(DecryptError::new(
                                    DecryptErrorCode::UnknownMagicHeader,
                                    "unsupported joox version",
                                ));
                            }
                            self.state = State::SeekToBody(JOOX_V04_HEADER_SIZE);
                        }
                    }
                    State::SeekToBody(n) => {
                        if self.data.read_until_offset(&mut p, n) {
                            self.data.seek_input(n);
                            self.state = State::DecryptOtherBlock;
                        }
                    }
                    State::DecryptOtherBlock => {
                        while self.data.read_block(&mut p, JOOX_V04_AES_BLOCK_SIZE * 2) {
                            self.decrypt_aes_block();
                            self.block_count += 1;
                            if self.block_count == JOOX_V04_BLOCK_COUNT_PER_ITERATION {
                                self.state = State::DecryptPaddingBlock;
                                self.block_count = 0;
                                break;
                            }
                        }
                    }
                    State::DecryptPaddingBlock => {
                        if self.data.read_block(&mut p, JOOX_V04_AES_BLOCK_SIZE) {
                            self.decrypt_aes_padding_block()?;
                            self.state = State::DecryptOtherBlock;
                        }
                    }
                }
            }
            Ok(())
        }
    }

    pub fn new_joox(uuid: String) -> impl Decryptor {
        JooxDecryptor::new(uuid.as_str())
    }
}

pub use detail::new_joox;

#[cfg(test)]
pub mod test {
    use crate::utils::test_util::test::{
        decrypt_test_content, generate_test_data, TEST_SIZE_1MB, TEST_SIZE_4MB,
    };

    #[test]
    fn test_joox() {
        let mut test_data = generate_test_data(TEST_SIZE_4MB + 12, "joox test data");
        let uuid = generate_test_data(32, "joox uuid");
        test_data[0..4].copy_from_slice(b"E!04");
        let padding_data = &[
            0xadu8, 0x15, 0xd5, 0xb0, 0x14, 0xc6, 0xd0, 0x40, //
            0xc5u8, 0x0f, 0x9a, 0xaf, 0xf9, 0xc0, 0xfe, 0xe2, //
        ];
        for i in 1..4 {
            let i = 12 + TEST_SIZE_1MB * i + 16 * i - 16;
            test_data[i..i + 16].copy_from_slice(padding_data);
        }
        let n = test_data.len();
        test_data[n - 16..].copy_from_slice(padding_data);

        let mut decryptor =
            super::new_joox(unsafe { std::str::from_utf8_unchecked(uuid.as_slice()) }.to_string());
        let result = decrypt_test_content(&mut decryptor, test_data);
        assert_eq!(
            result,
            "68feeeb99b826608032811a14dcb8d3f712a5a984a884c1fe487b50220da862c"
        );
    }
}
