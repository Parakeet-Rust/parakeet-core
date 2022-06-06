// References:
// - General sniff code:
//   https://github.com/unlock-music/cli/blob/master/algo/common/sniff.go
// - Various magic numbers:
//   https://www.garykessler.net/library/file_sigs.html
// - DFF:
//   https://www.sonicstudio.com/pdf/dsd/DSDIFF_1.5_Spec.pdf
// - MP3:
//   http://www.mp3-tech.org/programmer/frame_header.html
// - AAC:
//   https://wiki.multimedia.cx/index.php/ADTS
// - FLAC:
//   https://xiph.org/flac/format.html
// - fytp:
//   https://www.ftyps.com/

mod audio_type;
mod detect;
mod magic;
mod metadata;

pub use audio_type::AudioExtensionName;
pub use audio_type::AudioType;
pub use detect::detect_audio_type;
