#[allow(non_upper_case_globals)]
#[allow(clippy::module_inception)]
mod magic {
    pub const fLaC: u32 = u32::from_be_bytes(*b"fLaC"); // Free Lossless Audio Codec (FLAC)
    pub const OggS: u32 = u32::from_be_bytes(*b"OggS"); // Ogg
    pub const FRM8: u32 = u32::from_be_bytes(*b"FRM8"); // Direct Stream Digital (DS-DIFF)
    pub const ftyp: u32 = u32::from_be_bytes(*b"ftyp"); // MP4 Frame
    pub const wma_u32_hdr: u32 = u32::from_be_bytes(*b"\x30\x26\xB2\x75"); // Windows WMA/WMV/ASF
    pub const RIFF: u32 = u32::from_be_bytes(*b"RIFF"); // Waveform Audio File Format (WAV)
    pub const APE_MAGIC_MAC: u32 = u32::from_be_bytes(*b"MAC "); // Monkey's Audio (APE; u8 "MAC ")

    pub const ftyp_MSNV: u32 = u32::from_be_bytes(*b"MSNV"); // MPEG-4 (.MP4) for SonyPSP
    pub const ftyp_NDAS: u32 = u32::from_be_bytes(*b"NDAS"); // Nero Digital AAC Audio
    pub const ftyp_isom: u32 = u32::from_be_bytes(*b"isom"); // isom - MP4 (audio only?)
    pub const ftyp_iso2: u32 = u32::from_be_bytes(*b"iso2"); // iso2 - MP4 (audio only?)

    pub const ftyp_M4A: u32 = u32::from_be_bytes(*b"\x00M4A"); // iTunes AAC-LC (.M4A) Audio
    pub const ftyp_M4B: u32 = u32::from_be_bytes(*b"\x00M4B"); // iTunes AAC-LC (.M4B) Audio Book
}

pub use magic::*;
