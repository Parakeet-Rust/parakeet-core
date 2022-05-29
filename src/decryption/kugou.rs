pub const KUGOU_INTERNAL_TABLE_SIZE: usize = 17 * 16;
pub const KUGOU_VPR_KEY_SIZE: usize = 17;
pub const KUGOU_FILE_KEY_SIZE: usize = 17;

pub type KugouInternalTable = [u8; KUGOU_INTERNAL_TABLE_SIZE];
pub type KugouVPRKey = [u8; KUGOU_VPR_KEY_SIZE];
pub type KugouFileKey = [u8; KUGOU_FILE_KEY_SIZE];

mod detail {
    use std::cmp::Ordering;

    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, DecryptErrorCode, Decryptor},
        utils::array_ext::{ArrayExtension, ByteSliceExt},
    };

    use super::{KugouFileKey, KugouInternalTable, KugouVPRKey, KUGOU_FILE_KEY_SIZE};

    const KUGOU_MAGIC_HEADER_SIZE: usize = 16;
    const MINIMAL_HEADER_SIZE: usize = 0x2c;

    type KugouMagicHeader = [u8; KUGOU_MAGIC_HEADER_SIZE];

    enum State {
        ReadFileMagic,
        SeekToBody(usize),
        Decrypt,
    }

    trait KugouAlgo {
        fn get_magic_header(&self) -> &'static KugouMagicHeader;
        fn get_vpr_key_at_offset(&self, offset: usize) -> u8;
    }

    struct KugouKGM {}

    impl KugouKGM {
        #[inline]
        fn new() -> Self {
            Self {}
        }
    }

    impl KugouAlgo for KugouKGM {
        #[inline]
        fn get_magic_header(&self) -> &'static KugouMagicHeader {
            &[
                0x7c, 0xd5, 0x32, 0xeb, 0x86, 0x02, 0x7f, 0x4b, //
                0xa8, 0xaf, 0xa6, 0x8e, 0x0f, 0xff, 0x99, 0x14, //
            ]
        }

        #[inline]
        fn get_vpr_key_at_offset(&self, _: usize) -> u8 {
            0
        }
    }

    struct KugouVPR {
        vpr_key: KugouVPRKey,
    }

    impl KugouVPR {
        #[inline]
        fn new(vpr_key: &KugouVPRKey) -> Self {
            Self { vpr_key: *vpr_key }
        }
    }

    impl KugouAlgo for KugouVPR {
        #[inline]
        fn get_magic_header(&self) -> &'static KugouMagicHeader {
            &[
                0x05, 0x28, 0xbc, 0x96, 0xe9, 0xe4, 0x5a, 0x43, //
                0x91, 0xaa, 0xbd, 0xd0, 0x7a, 0xf5, 0x36, 0x31, //
            ]
        }

        #[inline]
        fn get_vpr_key_at_offset(&self, offset: usize) -> u8 {
            self.vpr_key.get_mod_n(offset)
        }
    }

    struct Kugou<T>
    where
        T: KugouAlgo,
    {
        data: BaseDecryptorData,
        state: State,

        t1: KugouInternalTable,
        t2: KugouInternalTable,
        v2: KugouInternalTable,
        file_key: KugouFileKey,
        detail: T,
    }

    impl<T> Kugou<T>
    where
        T: KugouAlgo,
    {
        pub fn new(
            t1: &KugouInternalTable,
            t2: &KugouInternalTable,
            v2: &KugouInternalTable,
            detail: T,
        ) -> Kugou<T> {
            Kugou {
                data: BaseDecryptorData::new(),
                state: State::ReadFileMagic,
                t1: *t1,
                t2: *t2,
                v2: *v2,
                file_key: [0u8; KUGOU_FILE_KEY_SIZE],
                detail,
            }
        }

        fn get_mask_v2(&self, offset: usize) -> u8 {
            let mut value = 0u8;
            let mut offset = offset;
            while offset > 0 {
                value ^= self.t1.get_mod_n(offset);
                offset >>= 4;
                value ^= self.t2.get_mod_n(offset);
                offset >>= 4;
            }
            value
        }

        fn decrypt_byte(&self, byte: u8, offset: usize) -> u8 {
            let mut value = byte;
            value ^= self.v2.get_mod_n(offset);
            value ^= self.file_key.get_mod_n(offset);
            value ^= self.get_mask_v2(offset >> 4);
            value = value ^ (value << 4);
            value ^= self.detail.get_vpr_key_at_offset(offset);

            value
        }

        #[inline]
        fn decrypt(&mut self, data: &[u8]) -> Result<(), DecryptError> {
            let size = data.len();
            let mut out = vec![0u8; size];

            let offset = self.data.offset;
            for i in 0..size {
                out[i] = self.decrypt_byte(data[i], offset + i);
            }

            self.data.buf_out.append(&mut out);
            self.data.offset += size;

            Ok(())
        }
    }

    impl<T> Decryptor for Kugou<T>
    where
        T: KugouAlgo,
    {
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
                    State::ReadFileMagic => {
                        if self.data.read_until_offset(&mut p, MINIMAL_HEADER_SIZE) {
                            let expected_header = self.detail.get_magic_header();

                            if self.data.buf_in[..KUGOU_MAGIC_HEADER_SIZE].cmp(&expected_header[..])
                                != Ordering::Equal
                            {
                                return Err(DecryptError::new(
                                    DecryptErrorCode::UnknownMagicHeader,
                                    "unknown magic header",
                                ));
                            }

                            let header_size = self.data.buf_in.read_le::<u32>(0x10) as usize;
                            self.file_key[0..16].copy_from_slice(&self.data.buf_in[0x1c..0x2c]);
                            self.file_key[16] = 0;

                            self.state = State::SeekToBody(header_size);
                        }
                    }

                    State::SeekToBody(n) => {
                        if self.data.read_until_offset(&mut p, n) {
                            self.state = State::Decrypt;
                            self.data.offset = 0;
                            self.data.consume_bytes(n);
                        }
                    }

                    State::Decrypt => {
                        return self.decrypt(p);
                    }
                }
            }

            Ok(())
        }
    }

    pub fn new_kgm(
        t1: &KugouInternalTable,
        t2: &KugouInternalTable,
        v2: &KugouInternalTable,
    ) -> impl Decryptor {
        Kugou::new(t1, t2, v2, KugouKGM::new())
    }

    pub fn new_vpr(
        t1: &KugouInternalTable,
        t2: &KugouInternalTable,
        v2: &KugouInternalTable,
        vpr_key: &KugouVPRKey,
    ) -> impl Decryptor {
        Kugou::new(t1, t2, v2, KugouVPR::new(vpr_key))
    }
}

pub use detail::new_kgm;
pub use detail::new_vpr;

#[cfg(test)]
pub mod test {
    use crate::{
        decryption::kugou::KUGOU_VPR_KEY_SIZE,
        utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_4MB},
    };

    use super::KUGOU_INTERNAL_TABLE_SIZE;

    #[test]
    fn test_kgm() {
        let mut t1 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "kgm_test1_t1");
        let mut t2 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "kgm_test1_t2");
        let v2 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "kgm_test1_v2");

        t1[..16].fill(0);
        t2[..16].fill(0);

        let mut test_data = generate_test_data(TEST_SIZE_4MB, "kgm_test1_data");
        test_data[..20].copy_from_slice(&[
            0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B, 0xA8, 0xAF, //
            0xA6, 0x8E, 0x0F, 0xFF, 0x99, 0x14, 0x00, 0x04, 0x00, 0x00, //
        ]);

        let mut decryptor = super::new_kgm(
            t1[..].try_into().unwrap(),
            t2[..].try_into().unwrap(),
            v2[..].try_into().unwrap(),
        );

        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "7260037c367e8782c9ea4727d12e9d1f53d30b25d262531ef9170e9adbafb3c3"
        );
    }

    #[test]
    fn test_vpr() {
        let mut t1 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "vpr_test1_t1");
        let mut t2 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "vpr_test1_t2");
        let v2 = generate_test_data(KUGOU_INTERNAL_TABLE_SIZE, "vpr_test1_v2");
        let vpr_key = generate_test_data(KUGOU_VPR_KEY_SIZE, "vpr_test1_key");

        t1[..16].fill(0);
        t2[..16].fill(0);

        let mut test_data = generate_test_data(TEST_SIZE_4MB, "vpr_test1_data");
        test_data[..20].copy_from_slice(&[
            0x05, 0x28, 0xbc, 0x96, 0xe9, 0xe4, 0x5a, 0x43, 0x91, 0xaa, //
            0xbd, 0xd0, 0x7a, 0xf5, 0x36, 0x31, 0x00, 0x04, 0x00, 0x00, //
        ]);

        let mut decryptor = super::new_vpr(
            t1[..].try_into().unwrap(),
            t2[..].try_into().unwrap(),
            v2[..].try_into().unwrap(),
            vpr_key[..].try_into().unwrap(),
        );

        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "9f8786693b334d074b0ef5c573672c9cf290fae204b285240c18f93cd7ebaca5"
        );
    }
}
