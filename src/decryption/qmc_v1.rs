mod detail {
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, Decryptor},
        utils::array_ext::{ArrayExtension, ByteSliceExt, VecExtension},
    };

    const STATIC_CIPHER_PAGE_SIZE: usize = 0x7fff;

    trait QmcV1Algo {
        fn new() -> Self;
        fn get_mask(key: &[u8], i: usize) -> u8;
    }

    struct QmcV1StaticAlgo<const C: usize> {}
    impl<const C: usize> QmcV1Algo for QmcV1StaticAlgo<C> {
        #[inline(always)]
        fn new() -> Self {
            Self {}
        }

        #[inline(always)]
        fn get_mask(key: &[u8], i: usize) -> u8 {
            key.get_mod_n(i * i + C)
        }
    }
    struct QmcV2MapAlgo<const C: usize> {}
    impl<const C: usize> QmcV1Algo for QmcV2MapAlgo<C> {
        #[inline(always)]
        fn new() -> Self {
            Self {}
        }

        #[inline(always)]
        fn get_mask(key: &[u8], i: usize) -> u8 {
            let i = (i * i + C) % key.len();
            let v = key.get_value_unchecked(i);
            let shift = (i + 4) & 0b0111;
            (v << shift) | (v >> shift)
        }
    }

    struct QMCv1<T: QmcV1Algo> {
        data: BaseDecryptorData,
        extra_cache_value: u8,
        cache: [u8; STATIC_CIPHER_PAGE_SIZE],

        #[allow(dead_code)]
        algo: T,
    }

    impl<T: QmcV1Algo> QMCv1<T> {
        #[inline(always)]
        pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
            let mut result = Self {
                data: BaseDecryptorData::new("QMCv1"),
                extra_cache_value: 0,
                cache: [0u8; STATIC_CIPHER_PAGE_SIZE],
                algo: T::new(),
            };

            result.init_cache(key.as_ref());
            result
        }

        #[inline(always)]
        fn init_cache(&mut self, key: &[u8]) {
            for (i, v) in self.cache.iter_mut().enumerate() {
                *v = T::get_mask(key, i);
            }
            self.extra_cache_value = self.cache[0] ^ T::get_mask(key, STATIC_CIPHER_PAGE_SIZE);
        }
    }

    impl<T: QmcV1Algo> Decryptor for QMCv1<T> {
        #[inline(always)]
        fn get_data(&self) -> &BaseDecryptorData {
            &self.data
        }

        #[inline(always)]
        fn get_data_mut(&mut self) -> &mut BaseDecryptorData {
            &mut self.data
        }

        fn write(&mut self, data: &[u8]) -> Result<(), DecryptError> {
            let n = data.len();
            let offset = self.data.offset;
            let new_offset = offset + n;

            let buf = self.data.buf_out.append_data(data);
            buf.xor_key_with_key_offset(&self.cache, offset);

            if offset <= STATIC_CIPHER_PAGE_SIZE && STATIC_CIPHER_PAGE_SIZE < new_offset {
                buf[STATIC_CIPHER_PAGE_SIZE - offset] ^= self.extra_cache_value;
            }
            self.data.offset = new_offset;
            Ok(())
        }
    }

    pub fn new_qmc_v1_static(key: &[u8]) -> impl Decryptor {
        QMCv1::<QmcV1StaticAlgo<80923>>::new(key)
    }

    pub fn new_qmc_v2_map(key: &[u8]) -> impl Decryptor {
        QMCv1::<QmcV2MapAlgo<71214>>::new(key)
    }
}

pub use detail::new_qmc_v1_static;
pub use detail::new_qmc_v2_map;

#[cfg(test)]
mod test {
    use crate::utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_4MB};

    #[test]
    fn test_qmc_v1_static() {
        let test_key = generate_test_data(256, "qmcv1 static key");
        let test_data = generate_test_data(TEST_SIZE_4MB, "qmcv1 static data");

        let mut decryptor = super::new_qmc_v1_static(test_key.as_slice());
        let result = decrypt_test_content(&mut decryptor, test_data.as_slice());
        assert_eq!(
            result,
            "2f9c936ed130a654911e0e2bc872fec33c90288e78df2a0aa41d352164c3b4e3"
        );
    }

    #[test]
    fn test_qmc_v2_map() {
        let test_key = generate_test_data(256, "qmcv1 map cipher derived key");
        let test_data = generate_test_data(TEST_SIZE_4MB, "qmcv1 map cipher data");

        let mut decryptor = super::new_qmc_v2_map(test_key.as_slice());
        let result = decrypt_test_content(&mut decryptor, test_data.as_slice());
        assert_eq!(
            result,
            "ce84e9ac24ef5b2f02a11f74ffa8eb7008fe2898855617596c5ee217139fc214"
        );
    }
}
