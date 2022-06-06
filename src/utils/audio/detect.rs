use crate::utils::array_ext::ByteSliceExt;

use super::{magic, metadata::get_audio_header_metadata_size, AudioType};

fn is_mp3(magic: u32) -> bool {
    // Framesync, should have first 11-bits set to 1.
    const MP3_MAGIC_AND_MASK: u32 = 0b1111_1111_1110_0000 << 16;
    const MP3_MAGIC_EXPECTED: u32 = 0b1111_1111_1110_0000 << 16;
    (magic & MP3_MAGIC_AND_MASK) == MP3_MAGIC_EXPECTED
}

fn is_aac(magic: u32) -> bool {
    // Framesync, should have first 12-bits set to 1.
    const AAC_MAGIC_AND_MASK: u32 = 0b1111_1111_1111_0110 << 16;
    const AAC_MAGIC_EXPECTED: u32 = 0b1111_1111_1111_0000 << 16;

    (magic & AAC_MAGIC_AND_MASK) == AAC_MAGIC_EXPECTED
}

pub fn detect_audio_type<T: AsRef<[u8]>>(header: T) -> AudioType {
    let mut buf = header.as_ref();

    // Seek optional id3 tag.
    let audio_header_meta_size = get_audio_header_metadata_size(buf);
    if audio_header_meta_size > buf.len() {
        return AudioType::UnknownType;
    } else if audio_header_meta_size > 0 {
        buf = &buf[audio_header_meta_size..];
    }

    if buf.len() < 16 {
        return AudioType::UnknownType;
    }

    {
        // Magic: first 4 bytes
        let magic = buf.read_be::<u32>(0);

        // 4 byte magic
        match magic {
            magic::fLaC => {
                return AudioType::FLAC;
            }
            magic::OggS => {
                return AudioType::OGG;
            }
            magic::FRM8 => {
                return AudioType::DFF;
            }
            magic::wma_u32_hdr => {
                return AudioType::WMA;
            }
            magic::RIFF => {
                return AudioType::WAV;
            }
            magic::APE_MAGIC_MAC => {
                return AudioType::APE;
            }
            _ => {}
        };

        // Detect type by its frame header
        if is_aac(magic) {
            return AudioType::AAC;
        } else if is_mp3(magic) {
            return AudioType::MP3;
        }
    }

    // ftyp
    if buf.read_be::<u32>(4) == magic::ftyp {
        let ftyp_type = buf.read_be::<u32>(8);
        match ftyp_type {
            magic::ftyp_isom | magic::ftyp_iso2 => {
                return AudioType::MP4;
            }

            magic::ftyp_MSNV | magic::ftyp_NDAS => {
                return AudioType::M4A;
            }

            _ => {}
        }

        match ftyp_type >> 8 {
            magic::ftyp_M4A => {
                return AudioType::M4A;
            }

            magic::ftyp_M4B => {
                return AudioType::M4B;
            }

            _ => {}
        }
    }

    AudioType::UnknownType
}
