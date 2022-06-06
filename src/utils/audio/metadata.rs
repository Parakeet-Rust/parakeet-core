use crate::utils::array_ext::ByteSliceExt;

#[inline]
fn parse_id3_sync_safe_int(buf: &[u8]) -> u32 {
    let raw = buf.read_be::<u32>(0);

    ((raw & 0x7F00_0000) >> 3)
        | ((raw & 0x007F_0000) >> 2)
        | ((raw & 0x0000_7F00) >> 1)
        | (raw & 0x0000_007F)
}

#[inline]
fn get_id3_header_size(magic: u32, buf: &[u8]) -> usize {
    if buf.len() < 10 {
        return 0;
    }

    // ID3v1 and ID3v1.1: flat 128 bytes
    const ID3V1_MASKS: u32 = 0xFFFFFF00; // Select first 3 bytes
    const ID3V1_VALUE: u32 = u32::from_be_bytes(*b"TAG\x00");
    if (magic & ID3V1_MASKS) == ID3V1_VALUE {
        return 128;
    }

    const ID3V2_MASKS: u32 = 0xFFFFFF00; // Select first 3 bytes
    const ID3V2_VALUE: u32 = u32::from_be_bytes(*b"ID3\x00");
    if (magic & ID3V2_MASKS) != ID3V2_VALUE {
        return 0;
    }

    // file = 'ID3'
    //        u8(ver_major) u8(ver_minor)
    //        u8(flags)
    //        u32(inner_tag_size)
    //        byte[inner_tag_size] id3v2 data
    //        byte[*] original_file_content
    let id3v2_inner_tag_size = parse_id3_sync_safe_int(&buf[6..10]) as usize;
    if id3v2_inner_tag_size == 0 {
        return 0;
    }

    10 + id3v2_inner_tag_size
}

#[inline]
fn get_ape_v2_full_size(magic1: u32, buf: &[u8]) -> usize {
    let magic2: u32 = buf.read_be::<u32>(4);
    // cspell:disable
    const APE_V2_MAGIC1: u32 = u32::from_be_bytes(*b"APET");
    const APE_V2_MAGIC2: u32 = u32::from_be_bytes(*b"AGEX");
    // cspell:enable

    if magic1 != APE_V2_MAGIC1 || magic2 != APE_V2_MAGIC2 {
        return 0;
    }

    // Tag size in bytes including footer and all tag items excluding the header.
    const APE_V2_HEADER_SIZE: usize = 32;
    let tag_size = buf.read_le::<u32>(0x0c) as usize;

    APE_V2_HEADER_SIZE + tag_size
}

#[inline]
pub fn get_audio_header_metadata_size(buf: &[u8]) -> usize {
    // Not enough bytes to detect
    if buf.len() < 10 {
        return 0;
    }

    let magic = buf.read_be::<u32>(0);

    let id3_meta_size = get_id3_header_size(magic, buf);
    if id3_meta_size > 0 {
        return id3_meta_size;
    }

    // It's possible to have APEv2 header at the beginning of a file, though rare.
    let ape_meta_size = get_ape_v2_full_size(magic, buf);
    if ape_meta_size > 0 {
        return ape_meta_size;
    }

    0
}
