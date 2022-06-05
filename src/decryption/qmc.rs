use super::{qmc_v1, qmc_v2};
use crate::decryptor::Decryptor;

pub fn new_qmc_v2<T: AsRef<[u8]>>(footer: T) -> Option<Box<dyn Decryptor>> {
    let parsed = crate::tencent::qmc_footer::parse(footer)?;
    let key_len = parsed.key.len();

    if key_len == 0 {
        return None;
    }

    if parsed.key.len() < 300 {
        Some(Box::new(qmc_v1::new_qmc_v1_map(
            parsed.key,
            parsed.eof_bytes_ignore,
        )))
    } else {
        Some(Box::new(qmc_v2::new_qmc_v2_rc4(
            parsed.key,
            parsed.eof_bytes_ignore,
        )))
    }
}
