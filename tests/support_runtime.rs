//! Exercise the existing serving dependency closure, not merely files on disk.
//! DT_NEEDED maps these four native libraries before the public verifier runs.

use std::ffi::{c_char, c_uint, c_ulong, c_void, CStr};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[link(name = "libssl.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn TLS_method() -> *const c_void;
}
#[link(name = "libcrypto.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn OpenSSL_version_num() -> c_ulong;
}
#[link(name = "libz.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn zlibVersion() -> *const c_char;
}
#[link(name = "libzstd.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn ZSTD_versionNumber() -> c_uint;
}

#[test]
fn existing_tls_and_compression_support_is_verified() {
    iconv_native::runtime::verify().unwrap();
    // SAFETY: these stable ABI queries require no mutable context or borrowed
    // input. TLS_method returns an opaque static descriptor; zlibVersion returns
    // a static NUL-terminated version string. Neither pointer is retained.
    unsafe {
        assert!(!TLS_method().is_null());
        assert!(OpenSSL_version_num() >= 0x3000_0000);
        assert!(CStr::from_ptr(zlibVersion()).to_bytes().starts_with(b"1."));
        assert!(ZSTD_versionNumber() >= 10_000);
    }
    iconv_native::runtime::verify().unwrap();
}

#[test]
#[ignore = "fresh-exec barrier fixture for the owned-container support mapping probe"]
fn support_mapping_child() {
    std::fs::write(std::env::var_os("ICONV_SUPPORT_READY").unwrap(), b"ready").unwrap();
    let mut signal = [0];
    std::io::stdin().read_exact(&mut signal).unwrap();
    assert_eq!(
        iconv_native::runtime::verify(),
        // The old mapped object's renamed/deleted path is no longer in the
        // captured namespace, although the current on-disk hash still matches.
        Err(iconv_native::runtime::Error::Loader)
    );
}

struct Probe(Child);
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Restore {
    path: PathBuf,
    backup: PathBuf,
    ready: PathBuf,
}
impl Drop for Restore {
    fn drop(&mut self) {
        std::fs::rename(&self.backup, &self.path).expect("restore original support inode");
        let _ = std::fs::remove_file(&self.ready);
    }
}

#[test]
#[ignore = "run alone in owned disposable root container; replaces/restores four support inodes"]
fn mapped_tls_and_compression_support_cannot_be_replaced_by_identical_bytes() {
    assert_eq!(
        std::env::var("ICONV_OWNED_RUNTIME_CONTAINER").as_deref(),
        Ok("1")
    );
    assert!(
        Path::new("/.dockerenv").is_file(),
        "never replace host native files"
    );
    for (index, name) in ["libssl.so.3", "libcrypto.so.3", "libz.so.1", "libzstd.so.1"]
        .into_iter()
        .enumerate()
    {
        // Resolve the known SONAME exactly as the native loader does. The actual
        // regular target is replaced; aliases and every hashed byte stay equal.
        let path =
            std::fs::canonicalize(Path::new("/usr/lib/x86_64-linux-gnu").join(name)).unwrap();
        let suffix = format!("{}-{index}", std::process::id());
        let backup = path.with_file_name(format!("iconv-support-backup-{suffix}"));
        let ready = std::env::temp_dir().join(format!("iconv-support-ready-{suffix}"));
        assert!(!backup.exists());
        assert!(!ready.exists());
        let mut child = Probe(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "support_mapping_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ICONV_SUPPORT_READY", &ready)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{name}: child exited before barrier"
            );
            assert!(Instant::now() < deadline, "{name}: ready barrier timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
        let bytes = std::fs::read(&path).unwrap();
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        std::fs::rename(&path, &backup).unwrap();
        let restore = Restore {
            path,
            backup,
            ready,
        };
        std::fs::write(&restore.path, bytes).unwrap();
        std::fs::set_permissions(&restore.path, permissions).unwrap();
        child.0.stdin.take().unwrap().write_all(b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "{name}: replaced mapping probe {status}");
                break;
            }
            assert!(Instant::now() < deadline, "{name}: mapping probe timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(child);
        drop(restore);
    }
}
