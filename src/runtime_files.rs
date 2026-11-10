// Shared by the build script and runtime verifier. No native calls here.
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const LIBDIR: &str = "/usr/lib/x86_64-linux-gnu";
pub const GCONV: &str = "/usr/lib/x86_64-linux-gnu/gconv";
pub const LIBC: &str = "/usr/lib/x86_64-linux-gnu/libc.so.6";
pub const LOADER: &str = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
// The serving executable's explicit GNU/TLS/compression support closure, not an
// inventory of unrelated installed libraries. Changes require qualification.
const SUPPORT: [&str; 6] = [
    "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/usr/lib/x86_64-linux-gnu/libm.so.6",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "/usr/lib/x86_64-linux-gnu/libz.so.1",
    "/usr/lib/x86_64-linux-gnu/libzstd.so.1",
];
const MAX_FILES: usize = 1024;
const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

pub fn stamp(metadata: &Metadata) -> Result<Stamp, ()> {
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(());
    }
    Ok(Stamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

pub struct Entry {
    pub path: PathBuf,
    pub file: File,
    pub stamp: Stamp,
}

pub struct Closure {
    pub entries: Vec<Entry>,
    pub directories: Vec<(PathBuf, Stamp)>,
    pub digest: String,
}

impl Closure {
    pub fn check_unchanged(&self) -> Result<(), ()> {
        for entry in &self.entries {
            if stamp(&entry.file.metadata().map_err(|_| ())?)? != entry.stamp
                || stamp(&std::fs::metadata(&entry.path).map_err(|_| ())?)? != entry.stamp
            {
                return Err(());
            }
        }
        for (path, expected) in &self.directories {
            if &stamp(&std::fs::metadata(path).map_err(|_| ())?)? != expected {
                return Err(());
            }
        }
        Ok(())
    }
}

pub fn capture() -> Result<Closure, ()> {
    fn collect(
        path: &Path,
        depth: usize,
        paths: &mut Vec<PathBuf>,
        directories: &mut Vec<(PathBuf, Stamp)>,
    ) -> Result<(), ()> {
        if depth > 3 || paths.len() + directories.len() >= MAX_FILES {
            return Err(());
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
        stamp(&metadata)?;
        if metadata.is_dir() {
            directories.push((path.to_owned(), stamp(&metadata)?));
            for entry in std::fs::read_dir(path).map_err(|_| ())? {
                collect(
                    &entry.map_err(|_| ())?.path(),
                    depth + 1,
                    paths,
                    directories,
                )?;
            }
        } else if metadata.is_file() {
            paths.push(path.to_owned());
        } else {
            // No symlink aliases, devices or sockets in the qualified closure.
            return Err(());
        }
        Ok(())
    }
    let mut paths = Vec::new();
    let mut directories = Vec::new();
    for directory in ["/", "/usr", "/usr/lib", LIBDIR] {
        let path = Path::new(directory);
        directories.push((
            path.to_owned(),
            stamp(&std::fs::metadata(path).map_err(|_| ())?)?,
        ));
    }
    for file in [LIBC, LOADER, GCONV] {
        collect(Path::new(file), 0, &mut paths, &mut directories)?;
    }
    for file in SUPPORT {
        let file = Path::new(file);
        let metadata = std::fs::symlink_metadata(file).map_err(|_| ())?;
        let target = if metadata.is_symlink() {
            // SONAME aliases may take exactly one hop to a regular file in the
            // same protected directory. Linux symlink mode bits are not access
            // controls; require root ownership and protect the directory instead.
            if metadata.uid() != 0 {
                return Err(());
            }
            let target = std::fs::read_link(file).map_err(|_| ())?;
            let target = if target.is_absolute() {
                target
            } else {
                Path::new(LIBDIR).join(target)
            };
            if target.parent() != Some(Path::new(LIBDIR)) {
                return Err(());
            }
            target
        } else {
            file.to_owned()
        };
        if !std::fs::symlink_metadata(&target)
            .map_err(|_| ())?
            .is_file()
        {
            return Err(());
        }
        // collect rejects a second alias or special file. The canonical path
        // and bytes are hashed; parent-directory stamps fence alias replacement.
        collect(&target, 0, &mut paths, &mut directories)?;
    }
    paths.sort();
    paths.dedup();
    let mut entries = Vec::new();
    let mut digest = Sha256::new();
    let mut total = 0u64;
    for path in paths {
        let name = path.to_str().ok_or(())?.as_bytes();
        if name.len() > 4096 {
            return Err(());
        }
        let mut file = File::open(&path).map_err(|_| ())?;
        let metadata = file.metadata().map_err(|_| ())?;
        let before = stamp(&metadata)?;
        if !metadata.is_file() {
            return Err(());
        }
        total = total.checked_add(metadata.len()).ok_or(())?;
        if total > MAX_BYTES {
            return Err(());
        }
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update(metadata.len().to_be_bytes());
        let mut bytes = 0u64;
        let mut buffer = [0u8; 32768];
        loop {
            let read = file.read(&mut buffer).map_err(|_| ())?;
            if read == 0 {
                break;
            }
            bytes += read as u64;
            if bytes > metadata.len() {
                return Err(());
            }
            digest.update(&buffer[..read]);
        }
        if bytes != metadata.len() || stamp(&file.metadata().map_err(|_| ())?)? != before {
            return Err(());
        }
        entries.push(Entry {
            path,
            file,
            stamp: before,
        });
    }
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let result = Closure {
        entries,
        directories,
        digest,
    };
    result.check_unchanged()?;
    Ok(result)
}
