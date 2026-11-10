use std::env::var;

#[path = "src/runtime_files.rs"]
mod runtime_files;

fn main() {
    fingerprint_source();
    fingerprint_qualified_libc();
    let feature_libiconv = var("CARGO_FEATURE_LIBICONV").is_ok();
    let feature_fallback_libiconv = var("CARGO_FEATURE_FALLBACK_LIBICONV").is_ok();
    let is_windows = var("CARGO_CFG_WINDOWS").is_ok();
    let is_using_win32 = var("CARGO_FEATURE_WIN32").is_ok() && is_windows;
    let is_using_web_encoding = var("CARGO_FEATURE_WEB_ENCODING").is_ok()
        && var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let is_linux = var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");
    let is_gnu = var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let is_hurd = var("CARGO_CFG_TARGET_OS").as_deref() == Ok("hurd");
    let is_apple = var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple");
    let is_using_libc_iconv =
        var("CARGO_FEATURE_LIBC_ICONV").is_ok() && ((is_gnu && is_linux) || is_hurd || is_apple);
    let is_using_fallback = !(is_using_libc_iconv || is_using_win32 || is_using_web_encoding);
    if is_windows && (feature_libiconv || (feature_fallback_libiconv && is_using_fallback)) {
        #[cfg(target_env = "msvc")]
        vcpkg::find_package("libiconv").unwrap();
    }
}

fn fingerprint_source() {
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    fn collect(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path).expect("codec source directory") {
            let entry = entry.expect("codec source entry");
            let kind = entry.file_type().expect("codec source type");
            assert!(!kind.is_symlink(), "codec source aliases are unsupported");
            if kind.is_dir() {
                collect(&entry.path(), files);
            } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
                files.push(entry.path());
            }
        }
    }
    let mut files = vec![PathBuf::from("Cargo.toml"), PathBuf::from("build.rs")];
    collect(Path::new("src"), &mut files);
    files.sort();
    let mut digest = Sha256::new();
    digest.update(b"iconv-native-source-v1\0d386e5223966bcde2654523e2b2135223a5c3602\0");
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
        let name = file.to_str().expect("UTF-8 codec source path").as_bytes();
        let bytes = std::fs::read(&file).expect("codec source bytes");
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    let source_id: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("cargo:rustc-env=ICONV_SOURCE_SHA256={source_id}");
}

// The same bounded fingerprint implementation is used by the runtime gate.
fn fingerprint_qualified_libc() {
    assert_eq!(
        var("HOST").unwrap(),
        var("TARGET").unwrap(),
        "cross builds are not qualified"
    );
    assert_eq!(var("TARGET").unwrap(), "x86_64-unknown-linux-gnu");
    let closure = runtime_files::capture().expect("protected qualified codec closure");
    for entry in &closure.entries {
        println!("cargo:rerun-if-changed={}", entry.path.display());
    }
    for (path, _) in &closure.directories {
        // Do not watch / or /usr: source/target writes are unrelated to codec
        // inputs. Runtime stamps still reject replacing protected ancestors.
        if path.starts_with(runtime_files::GCONV) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rustc-env=ICONV_CLOSURE_SHA256={}", closure.digest);
    println!(
        "cargo:rustc-env=ICONV_BUILD_CONTRACT=x86_64-gnu-linux;libc+loader+gconv-sha256={};codeset=ANSI_X3.4-1968",
        closure.digest
    );
}
