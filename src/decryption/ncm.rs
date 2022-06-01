// AES-128
const NCM_DECRYPTION_KEY_SIZE: usize = 128 / 8;
type NCMAudioKey = [u8; NCM_DECRYPTION_KEY_SIZE];

mod detail {
    use super::NCMAudioKey;
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, DecryptErrorCode, Decryptor},
        utils::{aes_ecb::Aes128EcbDec, array_ext::ByteSliceExt},
    };
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyInit};
    use std::{cmp::Ordering, mem::size_of};

    // cspell:disable-next-line
    const MAGIC: &[u8; 8] = b"CTENFDAM";
    const INITIAL_HEADER_LEN: usize = 10;

    // cspell:disable-next-line
    const CONTENT_KEY_PREFIX: &[u8; 17] = b"neteasecloudmusic";
    const CONTENT_KEY_PREFIX_LEN: usize = CONTENT_KEY_PREFIX.len();

    enum State {
        ReadFileHeader,
        ParseFileKey,
        ReadMetaBlock,
        ReadCoverFrameSize,
        ReadCoverBlock,
        SkipCoverPadding(usize),
        DecryptAudio,
    }

    struct NeteaseDecryptor {
        data: BaseDecryptorData,
        master_decryption_key: NCMAudioKey,
        state: State,

        audio_key_size: usize,
        content_key: Vec<u8>,
    }

    impl Decryptor for NeteaseDecryptor {
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
                    State::ReadFileHeader => {
                        if self.data.read_until_offset(&mut p, INITIAL_HEADER_LEN) {
                            if self.data.buf_in[..MAGIC.len()].cmp(MAGIC) != Ordering::Equal {
                                return Err(DecryptError::new(
                                    DecryptErrorCode::UnknownMagicHeader,
                                    "unknown magic header",
                                ));
                            }

                            self.data.seek_input(INITIAL_HEADER_LEN);
                            self.state = State::ParseFileKey;
                        }
                    }

                    State::ParseFileKey => {
                        let mut size = self.audio_key_size;
                        let ok = self.read_next_sized_block(&mut p, &mut size, 0)?;
                        self.audio_key_size = size;
                        if ok {
                            self.parse_key()?;
                            self.state = State::ReadMetaBlock;
                        }
                    }

                    _ => {
                        // bad
                    }
                }
            }

            Ok(())
        }
    }

    impl NeteaseDecryptor {
        fn new(master_audio_key: &NCMAudioKey) -> Self {
            Self {
                data: BaseDecryptorData::new("Netease"),
                master_decryption_key: *master_audio_key,
                state: State::ReadFileHeader,
                audio_key_size: 0,
                content_key: vec![],
            }
        }

        fn read_next_sized_block(
            &mut self,
            data: &mut &[u8],
            next_block_size: &mut usize,
            padding: usize,
        ) -> Result<bool, DecryptError> {
            if *next_block_size == 0 && self.data.read_block(data, size_of::<u32>()) {
                *next_block_size = (self.data.buf_in.read_le::<u32>(0) as usize) + padding;
                self.data.seek_input(size_of::<u32>());

                if *next_block_size == 0 {
                    return Err(DecryptError::new(
                        DecryptErrorCode::InvalidBlockSize,
                        "block size is ZERO",
                    ));
                }
            }

            Ok(*next_block_size > 0 && self.data.read_block(data, *next_block_size))
        }

        fn parse_key(&mut self) -> Result<(), DecryptError> {
            let mut encrypted_content_key = self.data.consume_input(self.audio_key_size);
            for v in encrypted_content_key.iter_mut() {
                *v ^= 0x64;
            }
            let mut content_key_out_vec = encrypted_content_key.clone();

            let content_key = Aes128EcbDec::new_from_slice(&self.master_decryption_key)
                .map_err(|_| {
                    DecryptError::new(DecryptErrorCode::AESParamError, "invalid key size")
                })?
                .decrypt_padded_b2b_mut::<Pkcs7>(
                    encrypted_content_key.as_slice(),
                    &mut content_key_out_vec,
                )
                .map_err(|_| {
                    DecryptError::new(DecryptErrorCode::AESParamError, "decrypt NCM key failed")
                })?;

            if content_key[..CONTENT_KEY_PREFIX_LEN].cmp(CONTENT_KEY_PREFIX) != Ordering::Equal {
                return Err(DecryptError::new(
                    DecryptErrorCode::InvalidNCMContentKey,
                    "unexpected key header",
                ));
            }

            self.content_key = Vec::from(&content_key[CONTENT_KEY_PREFIX_LEN..]);

            Ok(())
        }
    }

    pub fn new_ncm(key: &NCMAudioKey) -> impl Decryptor {
        NeteaseDecryptor::new(key)
    }
}

pub use detail::new_ncm;

#[cfg(test)]
mod test {
    #[test]
    fn test_ncm() {
        todo!("test ncm")
    }
}
