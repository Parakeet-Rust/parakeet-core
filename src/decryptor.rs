#[derive(Debug)]
pub struct BaseDecryptorData {
    pub(crate) name: String,
    pub(crate) offset: usize,
    pub(crate) buf_in: Vec<u8>,
    pub(crate) buf_out: Vec<u8>,
    pub(crate) reserve_eof: usize,
}

#[derive(Debug)]
pub enum DecryptErrorCode {
    UnknownEncryption,
    UnknownMagicHeader,
    InvalidBlockSize,
    AESParamError,
    NCMInvalidContentKey,
    NCMCoverFrameTooSmall,
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
    #[inline(always)]
    pub(crate) fn new(name: &str) -> Self {
        BaseDecryptorData {
            buf_in: vec![],
            buf_out: vec![],
            offset: 0,
            name: String::from(name),
            reserve_eof: 0,
        }
    }

    #[inline(always)]
    pub(crate) fn new_with_eof_reserve(name: &str, reserve_len: usize) -> Self {
        BaseDecryptorData {
            buf_in: vec![],
            buf_out: vec![],
            offset: 0,
            name: String::from(name),
            reserve_eof: reserve_len,
        }
    }

    #[inline(always)]
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

    #[inline(always)]
    pub(crate) fn read_block(&mut self, data: &mut &[u8], size: usize) -> bool {
        if self.buf_in.len() < size {
            let read_size = std::cmp::min(data.len(), size - self.buf_in.len());
            if read_size == 0 {
                return false;
            }

            let (to_buffer, left_over) = data.split_at(read_size);
            self.buf_in.extend_from_slice(to_buffer);
            *data = left_over;
        }

        self.buf_in.len() == size
    }

    #[inline(always)]
    pub(crate) fn seek_input(&mut self, len: usize) {
        self.buf_in.drain(..len);
    }

    #[inline(always)]
    pub(crate) fn consume_input(&mut self, len: usize) -> Vec<u8> {
        let result = Vec::from(&self.buf_in[..len]);
        self.seek_input(len);
        result
    }

    #[inline(always)]
    pub(crate) fn read_all_output(&mut self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        std::mem::swap(&mut self.buf_out, &mut result);
        result
    }
}

pub trait Decryptor {
    fn write(&mut self, data: &[u8]) -> Result<(), DecryptError>;
    #[inline(always)]
    fn end(&mut self) -> bool {
        true
    }

    fn get_name(&self) -> &str;
    fn read_all_output(&mut self) -> Vec<u8>;
    fn get_eof_reserve(&self) -> usize;
}

#[macro_export]
macro_rules! impl_decryptor_inner_helper {
    () => {
        #[inline(always)]
        fn get_name(&self) -> &str {
            &self.data.name
        }

        #[inline(always)]
        fn read_all_output(&mut self) -> Vec<u8> {
            self.data.read_all_output()
        }

        #[inline(always)]
        fn get_eof_reserve(&self) -> usize {
            self.data.reserve_eof
        }
    };
}
