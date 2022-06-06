const AUDIO_TYPE_MASK_LOSSLESS: isize = 1 << 5;

#[allow(clippy::upper_case_acronyms)]
pub enum AudioType {
    UnknownType = 0,

    // Lossy
    OGG,
    AAC,
    MP3,
    M4A,
    M4B,
    MP4,

    // Lossless
    FLAC = AUDIO_TYPE_MASK_LOSSLESS,
    DFF,
    WAV,
    WMA,
    APE,
}

pub trait AudioExtensionName {
    fn to_audio_ext(&self) -> &str;
}

impl AudioExtensionName for AudioType {
    fn to_audio_ext(&self) -> &str {
        match *self {
            AudioType::OGG => "ogg",
            AudioType::AAC => "aac",
            AudioType::MP3 => "mp3",
            AudioType::M4A => "m4a",
            AudioType::M4B => "m4b",
            AudioType::MP4 => "mp4",
            AudioType::FLAC => "flac",
            AudioType::DFF => "dff",
            AudioType::WAV => "wav",
            AudioType::WMA => "wma",
            AudioType::APE => "ape",
            _ => "bin",
        }
    }
}
