#[derive(Debug)]
#[allow(dead_code)]
pub struct BaseDecryptorData {
    pub(crate) name: String,
    pub(crate) offset: usize,
    pub(crate) buf_in: Vec<u8>,
    pub(crate) buf_out: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DecryptErrorCode {
    UnknownEncryption,
    UnknownMagicHeader,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DecryptError {
    code: DecryptErrorCode,
    str: String,
}

impl DecryptError {
    pub fn new(code: DecryptErrorCode, str: &str) -> DecryptError {
        DecryptError {
            code,
            str: str.into(),
        }
    }
}

impl BaseDecryptorData {
    pub fn new(name: &str) -> Self {
        BaseDecryptorData {
            buf_in: vec![],
            buf_out: vec![],
            offset: 0,
            name: String::from(name),
        }
    }

    pub(crate) fn read_until_offset(&mut self, data: &mut &[u8], offset: usize) -> bool {
        if self.offset < offset {
            let read_size = std::cmp::min(data.len(), offset - self.offset);
            if read_size == 0 {
                return false;
            }

            let (to_buffer, left_over) = data.split_at(read_size);
            self.buf_in.extend_from_slice(to_buffer);
            *data = left_over;

            self.offset += read_size
        }
        self.offset == offset
    }

    pub(crate) fn consume_bytes(&mut self, len: usize) {
        self.buf_in.drain(..len);
    }

    pub(crate) fn read_all_output(&mut self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.buf_out);
        result
    }
}

pub trait Decryptor {
    fn init_footer(&mut self, _footer: &[u8]) -> bool {
        true
    }
    fn end(&mut self) -> bool {
        true
    }

    fn get_name(&self) -> &str {
        &self.get_data().name
    }

    fn write(&mut self, data: &[u8]) -> Result<(), DecryptError>;
    fn read_all_output(&mut self) -> Vec<u8> {
        self.get_data_mut().read_all_output()
    }

    fn get_data(&self) -> &BaseDecryptorData;
    fn get_data_mut(&mut self) -> &mut BaseDecryptorData;
}
