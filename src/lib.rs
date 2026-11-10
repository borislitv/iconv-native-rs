#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![cfg_attr(
    any(windows, all(target_arch = "wasm32", feature = "web-encoding"),),
    no_std
)]
#![doc = include_str!("../docs/README.md")]

extern crate alloc;

#[cfg(not(all(target_os = "linux", target_env = "gnu", feature = "libc-iconv")))]
compile_error!("the reviewed streaming adapter requires GNU libc Linux with libc-iconv");

/// Reviewed caller-buffer adapter, supported only on the qualified GNU libc
/// Linux target. This fork intentionally does not qualify other backends.
#[cfg(all(target_os = "linux", target_env = "gnu", feature = "libc-iconv"))]
pub mod stream;

/// Effective-runtime loader/module validation for the qualified deployment.
pub mod runtime;
mod runtime_files;

/// Actual qualified build libc and gconv file-closure identity. Runtime deployment
/// must preserve this closure; changing it requires rebuilding the producer.
pub const BUILD_CONTRACT: &str = env!("ICONV_BUILD_CONTRACT");

/// SHA-256 identity of this dependency's manifest, build script and Rust sources.
/// Bind this together with the locked Git revision and `BUILD_CONTRACT` in a
/// downstream producer identity; call `runtime::verify()` before serving it.
pub const CODEC_SOURCE_ID: &str = env!("ICONV_SOURCE_SHA256");

mod bom;
mod encoding;
mod error;
mod sys;
mod utf;

use core::str::FromStr;

use alloc::{string::String, vec::Vec};

pub use error::{ConvertError, ConvertLossyError};

#[doc = include_str!("../docs/convert.md")]
pub fn convert(
    input: impl AsRef<[u8]>,
    from_encoding: &str,
    to_encoding: &str,
) -> Result<Vec<u8>, ConvertError> {
    sys::convert(input.as_ref(), from_encoding, to_encoding)
}

#[doc = include_str!("../docs/convert_lossy.md")]
pub fn convert_lossy(
    input: impl AsRef<[u8]>,
    from_encoding: &str,
    to_encoding: &str,
) -> Result<Vec<u8>, ConvertLossyError> {
    sys::convert_lossy(input.as_ref(), from_encoding, to_encoding)
}

#[doc = include_str!("../docs/decode.md")]
pub fn decode(input: impl AsRef<[u8]>, encoding: &str) -> Result<String, ConvertError> {
    let mut input = input.as_ref();
    try_strip_utf8_bom(&mut input, encoding);
    sys::decode(input, encoding)
}

#[doc = include_str!("../docs/decode_lossy.md")]
pub fn decode_lossy(input: impl AsRef<[u8]>, encoding: &str) -> Result<String, ConvertLossyError> {
    let mut input = input.as_ref();
    try_strip_utf8_bom(&mut input, encoding);
    sys::decode_lossy(input, encoding)
}

fn try_strip_utf8_bom(input: &mut &[u8], encoding: &str) {
    if let Ok(utf) = utf::UtfEncoding::from_str(encoding) {
        utf.strip_bom(input);
    }
}
