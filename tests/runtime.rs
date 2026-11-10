//! Fresh-process public-API probes. Mutation cases require a disposable owned
//! root container and must run alone; they never change the host's native files.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use iconv_native::{runtime, BUILD_CONTRACT, CODEC_SOURCE_ID};

#[test]
fn matching_runtime_and_source_identity() {
    assert_eq!(CODEC_SOURCE_ID.len(), 64);
    assert!(CODEC_SOURCE_ID.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(BUILD_CONTRACT.starts_with("x86_64-gnu-linux;libc+loader+gconv-sha256="));
    runtime::verify().unwrap();
    runtime::verify().unwrap();
    println!("CODEC_SOURCE_ID={CODEC_SOURCE_ID}\nBUILD_CONTRACT={BUILD_CONTRACT}");
}

#[test]
#[ignore = "fresh-process fixture invoked by the parent tests"]
fn runtime_child() {
    match std::env::var("ICONV_RUNTIME_PROBE").unwrap().as_str() {
        "override" => assert_eq!(runtime::verify(), Err(runtime::Error::Override)),
        "search-path" => runtime::verify().unwrap(),
        "relocated-library" => assert_eq!(runtime::verify(), Err(runtime::Error::Loader)),
        "changed" => assert_eq!(runtime::verify(), Err(runtime::Error::Mismatch)),
        scenario @ ("warm-changed" | "mapped-changed") => {
            if scenario == "warm-changed" {
                runtime::verify().unwrap();
            }
            std::fs::write(std::env::var_os("ICONV_RUNTIME_READY").unwrap(), b"ready").unwrap();
            let mut signal = [0];
            std::io::stdin().read_exact(&mut signal).unwrap();
            assert_eq!(runtime::verify(), Err(runtime::Error::Mismatch));
        }
        other => panic!("unknown runtime probe {other}"),
    }
}

struct Probe(Child);
impl Probe {
    fn spawn(scenario: &str, ready: Option<&Path>, variable: Option<(&str, &str)>) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "runtime_child", "--ignored", "--nocapture"])
            .env("ICONV_RUNTIME_PROBE", scenario)
            .stdin(Stdio::piped());
        if let Some(ready) = ready {
            command.env("ICONV_RUNTIME_READY", ready);
        }
        if let Some((name, value)) = variable {
            command.env(name, value);
        }
        Self(command.spawn().unwrap())
    }

    fn ready(&mut self, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.exists() {
            assert!(
                self.0.try_wait().unwrap().is_none(),
                "probe exited before barrier"
            );
            assert!(Instant::now() < deadline, "probe barrier timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn success(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "runtime probe {status}");
                return;
            }
            assert!(Instant::now() < deadline, "runtime probe timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn resume(&mut self) {
        self.0.stdin.take().unwrap().write_all(b"x").unwrap();
        self.success();
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn converter_and_loader_overrides_are_rejected() {
    for variable in [
        ("GCONV_PATH", "/nonexistent-synthetic-codec-path"),
        ("LD_PRELOAD", ""),
        ("LD_AUDIT", ""),
        ("GLIBC_TUNABLES", ""),
    ] {
        Probe::spawn("override", None, Some(variable)).success();
    }
}

#[test]
fn cargo_search_path_is_not_a_runtime_mismatch() {
    // Search-path text alone cannot change conversion. Actual mapped identities
    // are verified even when Cargo adds its dependency/toolchain search paths.
    Probe::spawn(
        "search-path",
        None,
        Some(("LD_LIBRARY_PATH", "/nonexistent-synthetic-library-path")),
    )
    .success();
}

#[test]
fn search_path_cannot_substitute_an_unverified_mapped_library() {
    let directory = std::env::temp_dir().join(format!("iconv-relocated-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let cleanup = Cleanup(directory);
    // Identical bytes at a different inode/path must not silently join the
    // verified loader closure. GNU executable startup actually loads this copy.
    std::fs::copy(
        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        cleanup.0.join("libgcc_s.so.1"),
    )
    .unwrap();
    Probe::spawn(
        "relocated-library",
        None,
        Some(("LD_LIBRARY_PATH", cleanup.0.to_str().unwrap())),
    )
    .success();
}

fn require_owned_container() {
    assert_eq!(
        std::env::var("ICONV_OWNED_RUNTIME_CONTAINER").as_deref(),
        Ok("1")
    );
    assert!(
        Path::new("/.dockerenv").is_file(),
        "never mutate host libraries"
    );
}

struct Restore {
    original: PathBuf,
    backup: PathBuf,
    ready: PathBuf,
}
impl Drop for Restore {
    fn drop(&mut self) {
        std::fs::rename(&self.backup, &self.original).expect("restore original native file");
        let _ = std::fs::remove_file(&self.ready);
    }
}

#[test]
#[ignore = "run alone in explicitly owned disposable root container; changes gconv module"]
fn changed_module_rejects_cold_and_warm_processes() {
    require_owned_container();
    let original = PathBuf::from("/usr/lib/x86_64-linux-gnu/gconv/TSCII.so");
    let ready = std::env::temp_dir().join(format!("iconv-module-ready-{}", std::process::id()));
    assert!(!ready.exists());
    let mut child = Probe::spawn("warm-changed", Some(&ready), None);
    child.ready(&ready);
    struct RestoreContents {
        path: PathBuf,
        bytes: Vec<u8>,
        ready: PathBuf,
    }
    impl Drop for RestoreContents {
        fn drop(&mut self) {
            std::fs::write(&self.path, &self.bytes).expect("restore original module contents");
            let _ = std::fs::remove_file(&self.ready);
        }
    }
    let restore = RestoreContents {
        path: original.clone(),
        bytes: std::fs::read(&original).unwrap(),
        ready,
    };
    // Leave valid ELF code and the mapped inode intact. The cold process can
    // still dlopen this module, and a warm process retains the same mapping;
    // only content identity/freshness validation detects this native-file drift.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&original)
        .unwrap()
        .write_all(b"synthetic-runtime-drift")
        .unwrap();
    Probe::spawn("changed", None, None).success();
    child.resume();
    drop(restore);
}

#[test]
#[ignore = "run alone in explicitly owned disposable root container; replaces libc inode"]
fn mapped_libc_identity_is_not_just_a_filesystem_hash() {
    require_owned_container();
    let original = PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6");
    let backup = original.with_file_name(format!("iconv-libc-backup-{}", std::process::id()));
    let ready = std::env::temp_dir().join(format!("iconv-libc-ready-{}", std::process::id()));
    assert!(!backup.exists());
    assert!(!ready.exists());
    let mut child = Probe::spawn("mapped-changed", Some(&ready), None);
    child.ready(&ready);
    let bytes = std::fs::read(&original).unwrap();
    let permissions = std::fs::metadata(&original).unwrap().permissions();
    std::fs::rename(&original, &backup).unwrap();
    let restore = Restore {
        original: original.clone(),
        backup,
        ready,
    };
    std::fs::write(&original, bytes).unwrap();
    std::fs::set_permissions(&original, permissions).unwrap();
    child.resume();
    drop(restore);
}
