#[derive(Debug, PartialEq)]
pub struct QMCFooterParseResult {
    pub key: Vec<u8>,
    pub eof_bytes_ignore: usize,
}

impl QMCFooterParseResult {
    pub fn new<T: AsRef<[u8]>>(key: T, eof_bytes: usize) -> Self {
        Self {
            key: Vec::from(key.as_ref()),
            eof_bytes_ignore: eof_bytes,
        }
    }
}

mod detail {
    use std::mem::size_of;

    use super::QMCFooterParseResult;
    use crate::{tencent::qmc_footer::key_derive::parse_ekey, utils::array_ext::ByteSliceExt};

    const MAGIC_QMC2_QTAG: u32 = u32::from_be_bytes(*b"QTag");
    const MAGIC_QMC2_STAG: u32 = u32::from_be_bytes(*b"STag");

    #[inline]
    fn parse_android_qtag_footer(buf: &[u8]) -> Option<QMCFooterParseResult> {
        // Legacy Android format.
        //   metadata := [ansi ekey_b64] ","
        //               [ansi songid] ","
        //               [ansi metadata_version '2']
        //   eof_mark := [(be)uint32_t meta_len] [bytes 'QTag']
        //   qmc_file := [encrypted_data] [metadata] [eof_mark]
        //
        // Where:
        //   meta_len := bytes( [metadata] [eof_mark] ).size()
        let len = buf.len();
        let required_len = buf.read_be::<u32>(len - 2 * size_of::<u32>()) as usize;
        if len < required_len {
            return None;
        }

        let line = String::from_utf8_lossy(&buf[len - required_len..len - 2 * size_of::<u32>()]);
        let csv: Vec<&str> = line.split(',').collect();

        if csv.len() != 3 || csv[2] != "2" {
            return None;
        }

        let ekey_b64 = csv[0];
        let ekey = parse_ekey(ekey_b64)?;

        Some(QMCFooterParseResult::new(ekey, required_len))
    }

    #[inline]
    fn parse_pc_footer(buf: &[u8]) -> Option<QMCFooterParseResult> {
        // Legacy PC QQMusic encoded format.
        // ekey_b64 := [ansi ekey_b64]
        // eof_mark := [(le)uint32_t ekey_size]
        // qmc_file := [encrypted_data] [ekey_b64] [eof_mark]
        let len = buf.len();
        let payload_size = buf.read_le::<u32>(len - size_of::<u32>()) as usize;
        let required_len = payload_size + size_of::<u32>();

        if required_len < len {
            return None;
        }

        const QMC_ENC_V2_KEY_HEADER: &str = "UVFNdXNpYyBFbmNWMixLZXk6";
        let ekey_b64 = String::from_utf8_lossy(&buf[len - required_len..len - size_of::<u32>()]);
        if ekey_b64.starts_with(QMC_ENC_V2_KEY_HEADER) {
            // Unsupported V2 header
            return None;
        }

        let ekey = parse_ekey(ekey_b64.as_ref())?;

        Some(QMCFooterParseResult::new(ekey, required_len))
    }

    pub fn parse<T: AsRef<[u8]>>(buf: T) -> Option<QMCFooterParseResult> {
        let buf = buf.as_ref();
        let len = buf.len();

        if len < 8 {
            return None;
        }

        let eof_magic = buf.read_be::<u32>(len - 4);

        if eof_magic == MAGIC_QMC2_QTAG {
            parse_android_qtag_footer(&buf[..len - 4])
        } else if eof_magic == MAGIC_QMC2_STAG {
            None
        } else {
            parse_pc_footer(buf)
        }
    }
}

pub use detail::parse;

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn test_parse_small_buffer_boundary_check() {
        assert_eq!(parse(&[0u8; 7]), None);
        assert_eq!(parse(&[0u8; 8]), None);
    }
}
