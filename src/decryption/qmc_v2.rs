mod detail {
    use crate::{
        decryptor::{BaseDecryptorData, DecryptError, Decryptor},
        utils::{
            array_ext::{ArrayExtension, ByteSliceExt, VecExtension},
            rc4::RC4TencentQmcV2,
        },
    };

    enum State {
        DecryptFirstSegment,
        DecryptOtherSegment,
    }

    struct QMCv2 {
        data: BaseDecryptorData,
        state: State,

        key: Vec<u8>,
        rc4: RC4TencentQmcV2,
    }

    impl QMCv2 {
        pub fn new<T: AsRef<[u8]>>(key: T) -> Self {
            let mut result = Self {
                data: BaseDecryptorData::new("QMCv2(RC4)"),
                state: State::DecryptFirstSegment,
                key: Vec::from(key.as_ref()),
                rc4: RC4TencentQmcV2::new(key.as_ref()),
            };

            result.init_key(key.as_ref());
            result
        }

        fn init_key(&mut self, key: &[u8]) {
            self.key = key.into();
        }
    }

    impl Decryptor for QMCv2 {
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
                    State::DecryptFirstSegment => {
                        //
                    }
                    State::DecryptOtherSegment => {
                        //
                    }
                }
            }

            Ok(())
        }
    }
}
