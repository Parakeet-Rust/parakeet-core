// AES-128
const NCM_DECRYPTION_KEY_SIZE: usize = 128 / 8;
type NCMAudioKey = [u8; NCM_DECRYPTION_KEY_SIZE];

mod detail {
    /**
     * @brief NCM file format
     *
     * File header: Hardcoded 8 char + 2 padding (hardcoded?)
     * 0000h: 43 54 45 4E 46 44 41 4D 01 69  CTENFDAM.i
     *
     * Followed by 3 blocks:
     *   - Content Key (Encrypted using `NCMAudioKey`)
     *   - Metadata; (AES-128 Encrypted, ignored by this library)
     *   - Album Cover (prefixed with 5 bytes padding? ignored by this library);
     *   - Audio Data (Encrypted with Content Key);
     */
    use super::NCMAudioKey;
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, DecryptErrorCode, Decryptor},
        utils::{
            aes_ecb::Aes128EcbDec,
            array_ext::ByteSliceExt,
            rc4::{RC4Derive, RC4Netease},
        },
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
        state: State,
        master_decryption_key: NCMAudioKey,
        audio_decryption_key: [u8; 0x100],

        content_key_size: usize,
        metadata_size: usize,
        cover_frame_size: usize,
        cover_size: usize,
        audio_offset: usize,
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
                        let ok: bool;
                        (ok, self.content_key_size) =
                            self.read_next_sized_block(&mut p, self.content_key_size, 0)?;
                        if ok {
                            self.parse_key()?;
                            self.state = State::ReadMetaBlock;
                        }
                    }

                    State::ReadMetaBlock => {
                        let ok: bool;
                        (ok, self.metadata_size) =
                            self.read_next_sized_block(&mut p, self.metadata_size, 5)?;
                        if ok {
                            self.data.seek_input(self.metadata_size);
                            self.state = State::ReadCoverFrameSize;
                        }
                    }

                    State::ReadCoverFrameSize => {
                        if self.data.read_block(&mut p, size_of::<u32>()) {
                            self.cover_frame_size =
                                self.data.consume_input(size_of::<u32>()).read_le::<u32>(0)
                                    as usize;
                            self.state = State::ReadCoverBlock;
                        }
                    }

                    State::ReadCoverBlock => {
                        let ok: bool;
                        (ok, self.cover_size) =
                            self.read_next_sized_block(&mut p, self.cover_size, 0)?;
                        if ok {
                            if self.cover_frame_size < self.cover_size {
                                return Err(DecryptError::new(
                                    DecryptErrorCode::NCMCoverFrameTooSmall,
                                    "cover_frame too small",
                                ));
                            }

                            self.data.seek_input(self.cover_size);

                            self.state =
                                State::SkipCoverPadding(self.cover_frame_size - self.cover_size);
                        }
                    }

                    State::SkipCoverPadding(0) => {
                        self.state = State::DecryptAudio;
                    }

                    State::SkipCoverPadding(n) => {
                        if self.data.read_block(&mut p, n) {
                            self.data.seek_input(n);
                            self.state = State::DecryptAudio;
                        }
                    }

                    State::DecryptAudio => {
                        let size = p.len();
                        let mut out = Vec::from(p);
                        out.xor_key_with_key_offset(self.audio_decryption_key, self.audio_offset);
                        self.data.buf_out.append(&mut out);
                        self.data.offset += size;
                        self.audio_offset += size;
                        return Ok(());
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
                audio_decryption_key: [0u8; 0x100],
                content_key_size: 0,
                metadata_size: 0,
                cover_frame_size: 0,
                cover_size: 0,
                audio_offset: 0,
            }
        }

        fn read_next_sized_block(
            &mut self,
            data: &mut &[u8],
            next_block_size: usize,
            padding: usize,
        ) -> Result<(bool, usize), DecryptError> {
            let mut next_block_size = next_block_size;
            if next_block_size == 0 && self.data.read_block(data, size_of::<u32>()) {
                next_block_size = (self.data.buf_in.read_le::<u32>(0) as usize) + padding;
                self.data.seek_input(size_of::<u32>());

                if next_block_size == 0 {
                    return Err(DecryptError::new(
                        DecryptErrorCode::InvalidBlockSize,
                        "block size is ZERO",
                    ));
                }
            }

            let ok = next_block_size > 0 && self.data.read_block(data, next_block_size);
            Ok((ok, next_block_size))
        }

        fn parse_key(&mut self) -> Result<(), DecryptError> {
            let mut encrypted_content_key = self.data.consume_input(self.content_key_size);
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
                    DecryptErrorCode::NCMInvalidContentKey,
                    "unexpected key header",
                ));
            }

            let content_key = &content_key[CONTENT_KEY_PREFIX_LEN..];

            // Init decryption key
            self.audio_offset = 0;
            let mut rc4 = RC4Netease::new(content_key);
            for v in self.audio_decryption_key.iter_mut() {
                *v = rc4.next();
            }

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
    use crate::{
        decryption::ncm::NCM_DECRYPTION_KEY_SIZE,
        utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_4MB},
    };

    #[test]
    fn test_ncm() {
        let test_key = generate_test_data(NCM_DECRYPTION_KEY_SIZE, "ncm-test-key");

        let mut test_data = generate_test_data(TEST_SIZE_4MB, "ncm-test-data");
        let header_override: &[u8] = &[
            0x43, 0x54, 0x45, 0x4E, 0x46, 0x44, 0x41, 0x4D, // header
            0xff, 0xff, // padding
            0x90, 0x00, 0x00, 0x00, // key size
            // key:
            //    neteasecloudmusic625064132972419780152239073outTde996wZqM
            //    k9R2NAS0zMZ9fHd4z37ei2drOBpNEYWFiN0jMiujKyv7pXPkxtj8eTck0
            //    0Jixun0Parakeet
            0x4D, 0x3C, 0x5A, 0x96, 0x74, 0x42, 0x64, 0xD3, 0x14, 0x4F, 0x77, 0xBB, //
            0x3C, 0x7B, 0x60, 0x56, 0x96, 0xA0, 0xD0, 0x12, 0xCB, 0xB8, 0xB6, 0x86, //
            0x13, 0xE6, 0xEF, 0x51, 0x00, 0x7E, 0xED, 0x02, 0xDF, 0xFE, 0xD2, 0xED, //
            0x6C, 0x4A, 0xA1, 0x33, 0x0C, 0xEA, 0x8E, 0x00, 0x3A, 0xBC, 0xAA, 0xFB, //
            0x47, 0xAC, 0xE3, 0x0B, 0xBA, 0xEA, 0xA4, 0x88, 0x6D, 0x84, 0x74, 0xBE, //
            0x28, 0x86, 0x1B, 0x43, 0xF7, 0x2F, 0x2A, 0xFD, 0x85, 0x44, 0xA0, 0xFC, //
            0xCD, 0xE0, 0xD7, 0xEC, 0x8F, 0xDB, 0xB0, 0xB5, 0x39, 0xFD, 0x94, 0x27, //
            0xD5, 0x24, 0x98, 0xCE, 0x2E, 0x6B, 0x7C, 0xBB, 0x16, 0x55, 0x0B, 0x63, //
            0x63, 0x3E, 0x8E, 0x26, 0x91, 0xF9, 0x32, 0x37, 0x38, 0xC0, 0x93, 0xD9, //
            0xCF, 0x40, 0x44, 0x5A, 0x6E, 0xDE, 0xEA, 0xCA, 0x27, 0xCB, 0x50, 0x54, //
            0x12, 0xFE, 0x12, 0x89, 0x59, 0x06, 0x72, 0xA9, 0x81, 0x33, 0x1F, 0xBE, //
            0xCB, 0xC9, 0x38, 0xFA, 0xE8, 0x94, 0xEB, 0xD7, 0x04, 0xF2, 0x58, 0xB4, //
            // Image metadata Block
            0x03, 0x00, 0x00, 0x00, //
            0x01, 0x02, 0x03, //
            0xff, 0xff, 0xff, 0xff, 0xff, // Unknown padding
            //
            0x03, 0x00, 0x00, 0x00, // Image Cover Frame
            0x03, 0x00, 0x00, 0x00, // Image Cover Size
            0xff, 0xff, 0xff, // Image Cover data
        ];
        test_data[..header_override.len()].copy_from_slice(header_override);

        let mut decryptor = super::new_ncm(test_key[..].try_into().unwrap());
        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "dae77d29821092561702e3cde97add3558f21a1607c9aab0599983632ce0d54b"
        );
    }
}
