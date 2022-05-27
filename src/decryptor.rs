pub struct BaseDecryptorData {
    pub(crate) name: String,
    pub(crate) error: String,
    pub(crate) offset: usize,
    pub(crate) buf_in: Vec<u8>,
    pub(crate) buf_out: Vec<u8>,
}

impl BaseDecryptorData {
    pub fn new() -> Self {
        BaseDecryptorData {
            buf_in: vec![],
            buf_out: vec![],
            offset: 0,
            error: String::new(),
            name: String::new(),
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

    fn read_all_output(&mut self) -> Vec<u8> {
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

    fn is_error(&self) -> bool {
        !self.get_error().is_empty()
    }

    fn get_error(&self) -> &str {
        &self.get_data().error
    }

    fn write(&mut self, data: &[u8]) -> bool;
    fn read_all_output(&mut self) -> Vec<u8> {
        self.get_data_mut().read_all_output()
    }

    fn get_data(&self) -> &BaseDecryptorData;
    fn get_data_mut(&mut self) -> &mut BaseDecryptorData;
}
