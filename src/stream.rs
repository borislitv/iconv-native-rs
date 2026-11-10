//! Caller-buffer streaming conversion for the reviewed GNU libc deployment.
//!
//! No Rust allocation is performed here. The descriptor owns libc's opaque
//! conversion state. Each call consumes at most the supplied input/output slices;
//! callers retain incomplete input and choose their own cancellation boundaries.

use core::ffi::{c_char, CStr};
use core::ptr;

use crate::sys::ffi::{iconv, iconv_close, iconv_open, iconv_t};

/// Result of one native conversion call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The supplied input was consumed, or flushing finished.
    Complete,
    /// Supply output space and retry the unconsumed input.
    OutputFull,
    /// Retain the unconsumed suffix and append more input before retrying.
    Incomplete,
    /// Invalid input or another native failure. Discard the complete conversion.
    Invalid,
}

/// Progress refers only to bytes consumed/written by this call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Bytes consumed from the input slice.
    pub consumed: usize,
    /// Initialized bytes written into the output slice.
    pub written: usize,
    /// Native conversion status.
    pub status: Status,
}

/// Owned native descriptor. Access requires `&mut self`; no shared or cross-thread
/// access to the opaque state is implemented.
#[derive(Debug)]
pub struct Converter(iconv_t);

impl Converter {
    /// Open a converter without allocating encoding-name copies. Unsupported
    /// conversions return `None`, matching iconv_open failure.
    pub fn new(from: &CStr, to: &CStr) -> Option<Self> {
        // SAFETY: both pointers refer to live NUL-terminated strings. A successful
        // descriptor is exclusively owned here and closed exactly once in Drop.
        let descriptor = unsafe { iconv_open(to.as_ptr(), from.as_ptr()) };
        (descriptor as isize != -1).then_some(Self(descriptor))
    }

    /// Convert a bounded slice. An empty slice is NOT a flush: stateful input may
    /// end at a chunk boundary. Use `flush` exactly after all input is consumed.
    pub fn convert(&mut self, input: &[u8], output: &mut [u8]) -> Progress {
        self.call(Some(input), output)
    }

    /// Emit pending shift-state output and reset the descriptor. Retry OutputFull
    /// with fresh output space until Complete. Never call while input remains.
    pub fn flush(&mut self, output: &mut [u8]) -> Progress {
        self.call(None, output)
    }

    fn call(&mut self, input: Option<&[u8]>, output: &mut [u8]) -> Progress {
        let input_len = input.map_or(0, <[u8]>::len);
        let mut remaining = input_len;
        let mut input_ptr = input.map_or(ptr::null(), |bytes| bytes.as_ptr().cast::<c_char>());
        let mut output_ptr = output.as_mut_ptr().cast::<c_char>();
        let mut available = output.len();
        // SAFETY: self owns a valid descriptor; all pointer/count variables are
        // mutable, correctly typed locals. Native writes are confined to the
        // exclusive output slice. iconv only reads input. Null input requests
        // the documented flush/reset operation. No borrowed pointer is retained.
        let result = unsafe {
            iconv(
                self.0,
                &mut input_ptr,
                &mut remaining,
                &mut output_ptr,
                &mut available,
            )
        };
        // Capture errno immediately, before any further native calls.
        let error = if result == usize::MAX {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        let status = match error {
            Some(7) => Status::OutputFull,  // GNU libc E2BIG
            Some(22) => Status::Incomplete, // GNU libc EINVAL
            Some(_) => Status::Invalid,
            None if result == usize::MAX => Status::Invalid,
            None => Status::Complete,
        };
        Progress {
            consumed: input_len - remaining,
            written: output.len() - available,
            status,
        }
    }
}

impl Drop for Converter {
    fn drop(&mut self) {
        // SAFETY: this descriptor is live, uniquely owned, and never exposed.
        unsafe { iconv_close(self.0) };
    }
}
