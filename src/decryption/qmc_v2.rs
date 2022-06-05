mod detail {
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, Decryptor},
        impl_decryptor_inner_helper,
        utils::{
            array_ext::ArrayExtension,
            rc4::{rc4::RC4Derive, RC4TencentQmcV2},
        },
    };
    use std::ops::Div;

    const FIRST_SEGMENT_SIZE: usize = 0x0080;
    const OTHER_SEGMENT_SIZE: usize = 0x1400;

    enum State {
        DecryptFirstSegment,
        DecryptOtherSegment,
    }

    struct QMCv2 {
        data: BaseDecryptorData,
        state: State,

        key: Vec<u8>,
        key_hash: u32,
        rc4: RC4TencentQmcV2,

        segment_id: usize,
        segment_bytes_left: usize,
    }

    impl QMCv2 {
        pub fn new<T: AsRef<[u8]>>(key: T, reserved_eof: usize) -> Self {
            Self {
                data: BaseDecryptorData::new_with_eof_reserve("QMCv2(RC4)", reserved_eof),
                state: State::DecryptFirstSegment,
                key: Vec::from(key.as_ref()),
                key_hash: Self::calculate_key_hash(key.as_ref()),
                rc4: RC4TencentQmcV2::new(key.as_ref()),

                segment_bytes_left: 0,
                segment_id: 0,
            }
        }

        #[inline(always)]
        fn calculate_key_hash(key: &[u8]) -> u32 {
            let mut hash: u32 = 1;
            for v in key.iter() {
                let v = *v as u32;
                if v == 0 {
                    continue;
                }

                let next_hash = hash.wrapping_mul(v);
                if next_hash == 0 || next_hash <= hash {
                    break;
                }

                hash = next_hash;
            }

            hash
        }

        #[inline(always)]
        fn get_segment_key(&self, id: u64, seed: u64) -> usize {
            if seed == 0 {
                0
            } else {
                100u64
                    .wrapping_mul(self.key_hash as u64)
                    .div(seed.wrapping_mul(id + 1)) as usize
            }
        }

        #[inline(always)]
        fn decrypt_first_segment(&mut self) {
            let mut output = self.data.consume_input(FIRST_SEGMENT_SIZE);

            for (i, v) in output.iter_mut().enumerate() {
                let seed = self.key.get_mod_n(i) as u64;
                let key_idx = self.get_segment_key(i as u64, seed);
                *v ^= self.key.get_mod_n(key_idx);
            }
            self.data.buf_out.append(&mut output);
            self.reset_other_segment_rc4(FIRST_SEGMENT_SIZE);
        }

        #[inline(always)]
        fn decrypt_other_segment_data(&mut self, p: &[u8]) {
            let mut output = Vec::from(p);
            let mut len = p.len();

            let mut i = 0usize;
            while len > 0 {
                if self.segment_bytes_left == 0 {
                    self.reset_other_segment_rc4(0);
                }

                let process_len = usize::min(self.segment_bytes_left, len);
                for v in output[i..i + process_len].iter_mut() {
                    *v ^= self.rc4.next();
                }

                i += process_len;
                len -= process_len;
                self.segment_bytes_left -= process_len;
            }

            self.data.offset += p.len();
            self.data.buf_out.append(&mut output);
        }

        #[inline(always)]
        fn reset_other_segment_rc4(&mut self, skip: usize) {
            self.segment_bytes_left = OTHER_SEGMENT_SIZE - skip;

            let seed = self.key[self.segment_id & 0x1FF] as u64;
            let discards = self.get_segment_key(self.segment_id as u64, seed) & 0x1FF;
            self.segment_id += 1;

            self.rc4.reset();
            self.rc4.skip(skip + discards);
        }
    }

    impl Decryptor for QMCv2 {
        impl_decryptor_inner_helper! {}

        fn write(&mut self, data: &[u8]) -> Result<(), DecryptError> {
            let mut p = data;

            while !p.is_empty() {
                match self.state {
                    State::DecryptFirstSegment => {
                        if self.data.read_until_offset(&mut p, FIRST_SEGMENT_SIZE) {
                            self.decrypt_first_segment();
                            self.state = State::DecryptOtherSegment;
                        }
                    }
                    State::DecryptOtherSegment => {
                        self.decrypt_other_segment_data(p);
                        return Ok(());
                    }
                }
            }

            Ok(())
        }
    }

    pub fn new_qmc_v2_rc4<T: AsRef<[u8]>>(key: T, reserved_eof: usize) -> impl Decryptor {
        QMCv2::new(key, reserved_eof)
    }
}

pub use detail::new_qmc_v2_rc4;

#[cfg(test)]
mod test {
    use crate::utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_4MB};

    #[test]
    fn test_qmc_v2_rc4() {
        let mut test_key = generate_test_data(512, "qmcv2 rc4 cipher key");
        let test_data = generate_test_data(TEST_SIZE_4MB, "qmcv2 rc4 cipher data");
        test_key[0..8].fill(b'4');

        let mut decryptor = super::new_qmc_v2_rc4(test_key, 0);
        let result = decrypt_test_content(&mut decryptor, test_data);
        assert_eq!(
            result,
            "757fc9aa94ab48295b106a16452b7da7b90395be8e3132a077b6d2a9ea216838"
        );
    }
}
