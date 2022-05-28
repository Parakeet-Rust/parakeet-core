use crate::decryptor::{BaseDecryptorData, Decryptor};

const XMLY_SCRAMBLE_SIZE: usize = 1024;

const X2MContentKeySize: usize = 0x04;
const X3MContentKeySize: usize = 0x20;

pub type X2MContentKey = [u8; X2MContentKeySize];
pub type X3MContentKey = [u8; X3MContentKeySize];
pub type ScrambleTable = [u16; XMLY_SCRAMBLE_SIZE];

enum State {
    DecryptHeader,
    PassThrough,
}

pub struct Ximalaya<T> {
    data: BaseDecryptorData,
    state: State,
    key: T,
    scramble_table: ScrambleTable,
}

impl<const KEY_SIZE: usize> Ximalaya<[u8; KEY_SIZE]> {
    pub fn new(key: [u8; KEY_SIZE], scramble_table: ScrambleTable) -> Self {
        let data = BaseDecryptorData::new();
        Ximalaya {
            data,
            key,
            state: State::DecryptHeader,
            scramble_table,
        }
    }

    fn do_header_decryption(&mut self) {
        let mut output = vec![0u8; XMLY_SCRAMBLE_SIZE];
        for (i, v) in output.iter_mut().enumerate() {
            let idx = usize::from(self.scramble_table[i]);
            *v = self.data.buf_in[idx] ^ self.key[i % KEY_SIZE];
        }
        self.data.buf_out.append(&mut output);
        self.data.buf_in.drain(..XMLY_SCRAMBLE_SIZE);
    }
}

impl<const KEY_SIZE: usize> Decryptor for Ximalaya<[u8; KEY_SIZE]> {
    fn get_data(&self) -> &BaseDecryptorData {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut BaseDecryptorData {
        &mut self.data
    }

    fn write(&mut self, data: &[u8]) -> bool {
        let mut p = data;

        while !p.is_empty() {
            match self.state {
                State::DecryptHeader => {
                    if self.data.read_until_offset(&mut p, XMLY_SCRAMBLE_SIZE) {
                        self.do_header_decryption();
                        self.state = State::PassThrough;
                    }
                }
                State::PassThrough => {
                    self.data.buf_out.extend_from_slice(p);
                    break;
                }
            }
        }

        true
    }
}

pub type XimalayaX2M = Ximalaya<X2MContentKey>;
pub type XimalayaX3M = Ximalaya<X3MContentKey>;

#[cfg(test)]
pub mod test {
    use super::{ScrambleTable, XimalayaX2M, XimalayaX3M, XMLY_SCRAMBLE_SIZE};
    use crate::{
        decryption::ximalaya::{X2MContentKeySize, X3MContentKeySize},
        utils::test_util::test::{decrypt_test_content, generate_test_data, TEST_SIZE_1MB},
    };

    #[test]
    fn test_x2m() {
        let test_data = generate_test_data(TEST_SIZE_1MB, "x2m-test-data");
        let x2m_content_key = generate_test_data(X2MContentKeySize, "x2m content key");

        let mut x2m_scramble_table: ScrambleTable = [0u16; XMLY_SCRAMBLE_SIZE];
        for (i, v) in x2m_scramble_table.iter_mut().enumerate() {
            *v = i as u16;
        }
        let table_size = x2m_scramble_table.len();
        let x2m_scramble_seed = generate_test_data(table_size * 2, "x2m seed");
        for i in 0..table_size {
            let n = u16::from_le_bytes(
                x2m_scramble_seed[i * 2..i * 2 + 2]
                    .try_into()
                    .expect("incorrect length"),
            ) as usize;
            x2m_scramble_table.swap(i, n % table_size);
        }

        assert_eq!(x2m_content_key.len(), X2MContentKeySize);

        let mut decryptor = XimalayaX2M::new(
            x2m_content_key
                .try_into()
                .expect("could not format to array"),
            x2m_scramble_table,
        );
        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "fd1ac1c4750f48b8d3c9562013f1c3202b12e45137b344995eda32a4f6b8a61f"
        );
    }

    #[test]
    fn test_x3m() {
        let test_data = generate_test_data(TEST_SIZE_1MB, "x3m-test-data");
        let x3m_content_key = generate_test_data(X3MContentKeySize, "x3m content key");

        let mut x3m_scramble_table: ScrambleTable = [0u16; XMLY_SCRAMBLE_SIZE];
        for (i, v) in x3m_scramble_table.iter_mut().enumerate() {
            *v = i as u16;
        }
        let table_size = x3m_scramble_table.len();
        let x3m_scramble_seed = generate_test_data(table_size * 2, "x3m seed");
        for i in 0..table_size {
            let n = u16::from_le_bytes(
                x3m_scramble_seed[i * 2..i * 2 + 2]
                    .try_into()
                    .expect("incorrect length"),
            ) as usize;
            x3m_scramble_table.swap(i, n % table_size);
        }

        assert_eq!(x3m_content_key.len(), X3MContentKeySize);

        let mut decryptor = XimalayaX3M::new(
            x3m_content_key
                .try_into()
                .expect("could not format to array"),
            x3m_scramble_table,
        );
        let result = decrypt_test_content(&mut decryptor, test_data.as_ref());
        assert_eq!(
            result,
            "a10bbfdcdbd388373361da6baf35c80b725f7310c3eca29d7dcf228e397a8c5a"
        );
    }
}
