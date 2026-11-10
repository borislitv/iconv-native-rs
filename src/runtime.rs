//! Strict validation of the effective native codec closure before serving.
//!
//! Hashing and module loading occur once per process. Every use rechecks loader
//! overrides, the actual locale, and fixed-size file/directory identity stamps.
//! Unsupported or changed runtimes fail closed; they are NOT codec failures.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::OnceLock;

use crate::runtime_files::{self, Closure, Entry, GCONV, LIBC, LIBDIR, LOADER};

/// Bounded runtime validation failure, separate from malformed/unknown codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A loader/converter override or unsupported locale is active.
    Override,
    /// The installed or mapped native files do not match the compiled closure.
    Mismatch,
    /// The process uses an unsupported loader, mapping or module dependency.
    Loader,
    /// Required protected files/proc metadata are unavailable or exceed bounds.
    Unavailable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "unverified native codec runtime: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Verify before cache lookup, cache publication and core derivation. There is
/// no successful fallback on failure. A changed deployment requires restart and
/// a build against its exact native closure, not reusing another producer key.
pub fn verify() -> Result<(), Error> {
    reject_overrides()?;
    static PROOF: OnceLock<Result<Proof, Error>> = OnceLock::new();
    let proof = PROOF
        .get_or_init(Proof::new)
        .as_ref()
        .map_err(|error| *error)?;
    proof
        .closure
        .check_unchanged()
        .map_err(|()| Error::Mismatch)?;
    check_loader_namespace(&proof.closure)
}

// GNU x86-64 ABI only; the crate rejects other deployment targets.
#[repr(C)]
struct DlInfo {
    name: *const c_char,
    base: *mut c_void,
    _symbol: *const c_char,
    _address: *mut c_void,
}
#[repr(C)]
struct LinkMapHead {
    base: usize,
}
unsafe extern "C" {
    fn dladdr(address: *const c_void, info: *mut DlInfo) -> c_int;
    fn dlopen(name: *const c_char, flags: c_int) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlinfo(handle: *mut c_void, request: c_int, info: *mut *mut LinkMapHead) -> c_int;
    fn nl_langinfo(item: c_int) -> *const c_char;
    fn gnu_dev_major(device: u64) -> u32;
    fn gnu_dev_minor(device: u64) -> u32;
}

fn reject_overrides() -> Result<(), Error> {
    for (name, _) in std::env::vars_os() {
        // Cargo supplies LD_LIBRARY_PATH when executing tests/examples. The
        // search path is not evidence of interposition: every actual executable
        // mapping and resolved codec symbol must still match the pinned closure.
        // In particular a replacement libc/module loaded from this path fails.
        if (name.as_bytes().starts_with(b"LD_") && name != "LD_LIBRARY_PATH")
            || name.as_bytes().starts_with(b"GCONV_")
            || name == "GLIBC_TUNABLES"
        {
            return Err(Error::Override);
        }
    }
    // SAFETY: GNU libc nl_langinfo(CODESET=14) returns a live NUL-terminated
    // borrowed string. It is inspected only during this call, never retained.
    let codeset = unsafe { CStr::from_ptr(nl_langinfo(14)) }.to_bytes();
    // Locale-dependent iconv aliases must not vary under one producer identity.
    // Rust/GNU startup uses the C locale; changing the actual thread codeset is
    // outside this fixed deployment contract, even if LANG names a UTF-8 locale.
    if codeset != b"ANSI_X3.4-1968" {
        return Err(Error::Override);
    }
    Ok(())
}

// Integer storage is private; it represents a uniquely owned dlopen reference.
// GNU dlopen/dlclose are thread-safe. No library code pointer is exposed. Keeping
// these owners in the once proof pins every verified module until process exit.
struct Module(usize);
impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: exactly one owned reference from successful dlopen; no Clone.
        unsafe { dlclose(self.0 as *mut c_void) };
    }
}
struct Proof {
    closure: Closure,
    _modules: Vec<Module>,
}

impl Proof {
    fn new() -> Result<Self, Error> {
        let closure = runtime_files::capture().map_err(|()| Error::Unavailable)?;
        if closure.digest != env!("ICONV_CLOSURE_SHA256") {
            return Err(Error::Mismatch);
        }
        let libc = closure
            .entries
            .iter()
            .find(|entry| entry.path == Path::new(LIBC))
            .ok_or(Error::Unavailable)?;
        for address in [
            crate::sys::ffi::iconv_open as *const () as *const c_void,
            crate::sys::ffi::iconv as *const () as *const c_void,
            crate::sys::ffi::iconv_close as *const () as *const c_void,
            dlopen as *const () as *const c_void,
            dlclose as *const () as *const c_void,
            dladdr as *const () as *const c_void,
            dlinfo as *const () as *const c_void,
            nl_langinfo as *const () as *const c_void,
            gnu_dev_major as *const () as *const c_void,
            gnu_dev_minor as *const () as *const c_void,
        ] {
            let mut info = DlInfo {
                name: std::ptr::null(),
                base: std::ptr::null_mut(),
                _symbol: std::ptr::null(),
                _address: std::ptr::null_mut(),
            };
            // SAFETY: address is a live resolved function; info is writable and
            // correctly laid out for GNU Dl_info. No native pointer is retained.
            if unsafe { dladdr(address, &mut info) } == 0
                || info.base.is_null()
                || info.name.is_null()
            {
                return Err(Error::Loader);
            }
            check_mapping(address as usize, libc)?;
        }
        let loader = closure
            .entries
            .iter()
            .find(|entry| entry.path == Path::new(LOADER))
            .ok_or(Error::Unavailable)?;
        let aux = read_bounded("/proc/self/auxv", 64 * 1024)?;
        let base = aux
            .as_chunks::<16>()
            .0
            .iter()
            .find_map(|row| {
                (u64::from_ne_bytes(row[..8].try_into().ok()?) == 7).then(|| {
                    u64::from_ne_bytes(row[8..].try_into().expect("fixed auxv row")) as usize
                })
            })
            .ok_or(Error::Loader)?;
        check_mapping(base, loader)?;
        let mut modules = Vec::new();
        for entry in &closure.entries {
            if entry.path.starts_with(GCONV)
                && entry.path.extension().is_some_and(|ext| ext == "so")
            {
                let name =
                    CString::new(entry.path.as_os_str().as_bytes()).map_err(|_| Error::Loader)?;
                // SAFETY: protected, fingerprinted ELF path; GNU RTLD_NOW=2 and
                // RTLD_LOCAL=0. The owned reference is closed on any error path.
                let handle = unsafe { dlopen(name.as_ptr(), 2) };
                if handle.is_null() {
                    return Err(Error::Loader);
                }
                let module = Module(handle as usize);
                let mut map = std::ptr::null_mut();
                // SAFETY: handle is live; GNU RTLD_DI_LINKMAP=2 writes a valid
                // link_map pointer. The first member is Elf64_Addr l_addr.
                if unsafe { dlinfo(handle, 2, &mut map) } != 0 || map.is_null() {
                    return Err(Error::Loader);
                }
                // SAFETY: the link_map remains live while module owns its handle.
                check_mapping(unsafe { (*map).base }, entry)?;
                modules.push(module);
            }
        }
        check_loader_namespace(&closure)?;
        closure.check_unchanged().map_err(|()| Error::Mismatch)?;
        Ok(Self {
            closure,
            _modules: modules,
        })
    }
}

fn read_bounded(path: &str, max: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| Error::Unavailable)?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 > max {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}

fn check_mapping(address: usize, expected: &Entry) -> Result<(), Error> {
    let maps = read_bounded("/proc/self/maps", 1024 * 1024)?;
    let maps = std::str::from_utf8(&maps).map_err(|_| Error::Loader)?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields
            .next()
            .and_then(|range| range.split_once('-'))
            .ok_or(Error::Loader)?;
        let start = usize::from_str_radix(start, 16).map_err(|_| Error::Loader)?;
        let end = usize::from_str_radix(end, 16).map_err(|_| Error::Loader)?;
        if !(start..end).contains(&address) {
            continue;
        }
        fields.next().ok_or(Error::Loader)?; // permissions
        fields.next().ok_or(Error::Loader)?; // offset
        let device = fields
            .next()
            .and_then(|value| value.split_once(':'))
            .ok_or(Error::Loader)?;
        let inode: u64 = fields
            .next()
            .ok_or(Error::Loader)?
            .parse()
            .map_err(|_| Error::Loader)?;
        let path = fields.next().ok_or(Error::Loader)?;
        if fields.next().is_some() || Path::new(path) != expected.path {
            return Err(Error::Mismatch);
        }
        let metadata = expected.file.metadata().map_err(|_| Error::Unavailable)?;
        // SAFETY: GNU dev_t helpers accept the fstat device value, no pointers.
        let major = unsafe { gnu_dev_major(metadata.dev()) };
        let minor = unsafe { gnu_dev_minor(metadata.dev()) };
        if inode != metadata.ino()
            || u32::from_str_radix(device.0, 16).map_err(|_| Error::Loader)? != major
            || u32::from_str_radix(device.1, 16).map_err(|_| Error::Loader)? != minor
        {
            return Err(Error::Mismatch);
        }
        return Ok(());
    }
    Err(Error::Loader)
}

fn check_loader_namespace(closure: &Closure) -> Result<(), Error> {
    let executable = std::fs::read_link("/proc/self/exe").map_err(|_| Error::Unavailable)?;
    let maps = read_bounded("/proc/self/maps", 1024 * 1024)?;
    let maps = std::str::from_utf8(&maps).map_err(|_| Error::Loader)?;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let permissions = fields.get(1).ok_or(Error::Loader)?;
        if !permissions.contains('x') {
            continue;
        }
        let path = fields.get(5).ok_or(Error::Loader)?;
        if *path == "[vdso]" || *path == "[vsyscall]" {
            continue;
        }
        if fields.len() != 6 {
            return Err(Error::Loader);
        }
        let path = Path::new(path);
        if path == executable {
            continue;
        }
        if path.parent() != Some(Path::new(LIBDIR)) && path.parent() != Some(Path::new(GCONV)) {
            return Err(Error::Loader);
        }
        let expected = closure
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .ok_or(Error::Loader)?;
        let metadata = expected.file.metadata().map_err(|_| Error::Unavailable)?;
        let device = fields[3].split_once(':').ok_or(Error::Loader)?;
        // SAFETY: GNU dev_t value helpers have no pointer/resource parameters.
        let major = unsafe { gnu_dev_major(metadata.dev()) };
        let minor = unsafe { gnu_dev_minor(metadata.dev()) };
        if fields[4].parse::<u64>().map_err(|_| Error::Loader)? != metadata.ino()
            || u32::from_str_radix(device.0, 16).map_err(|_| Error::Loader)? != major
            || u32::from_str_radix(device.1, 16).map_err(|_| Error::Loader)? != minor
        {
            return Err(Error::Mismatch);
        }
    }
    Ok(())
}
