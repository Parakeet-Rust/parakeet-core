use super::super::decryptor::{BaseDecryptorData, Decryptor};

const XMLY_SCRAMBLE_SIZE: usize = 1024;

const X2MContentKeySize: usize = 0x04;
const X3MContentKeySize: usize = 0x20;

pub type X2MContentKey = [u8; X2MContentKeySize];
pub type X3MContentKey = [u8; X3MContentKeySize];
pub type ScrambleTable = [u16; XMLY_SCRAMBLE_SIZE];

enum State {
    DecryptHeader,
    Passthrough,
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
                        self.state = State::Passthrough;
                    }
                }
                State::Passthrough => {
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
