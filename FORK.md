# Qualified GNU codec fork

This fork starts at upstream `bdbai/iconv-native-rs` commit
`d386e5223966bcde2654523e2b2135223a5c3602` (v0.1.0). The original package layout,
authors, features and license declaration (`MIT OR Apache-2.0`) are retained.
The original `LICENSE` file is unchanged. This is a downstream GNU/Linux profile,
not a claim that other upstream backends have been qualified with these additions.
There are no source inventories, patch-history copies or embedded source archives.

## Public additions

- `stream::Converter::{new, convert, flush}` operates on caller-owned buffers.
  `Progress` reports consumed/written bytes and `Status` distinguishes complete,
  output-full, incomplete and invalid input. The descriptor is uniquely owned,
  closed on drop, and not shared across threads. This adapter does not allocate
  growing Rust output buffers or perform application cancellation for its caller.
- `CODEC_SOURCE_ID` is a build-generated SHA-256 over the original upstream base
  identifier, manifest, build script and all Rust sources under `src/`. It does not
  depend on checkout location, timestamps, Git dirty state or generated output.
- `BUILD_CONTRACT` binds the actual build native-file bytes and the supported
  thread codeset. Downstream producer identity must include both exported IDs and
  the locked dependency Git revision. No downstream source-file copies or
  `include_bytes!` paths into an application vendor directory are needed.
- `runtime::verify() -> Result<(), runtime::Error>` verifies the effective loaded
  runtime. Errors (`Override`, `Mismatch`, `Loader`, `Unavailable`) are distinct
  from unknown encodings/malformed input and must never become raw-byte success
  or an optional-cache miss.

Applications must call the fallible verifier before accepting requests (one-time
startup work), before any RAM/durable cache lookup or completed-flight reuse,
before derivation, before publication, and at complete-response consumption/final
fences. The codec crate cannot enforce downstream cache wiring. Native Git-style
metadata conversion does not flush; `flush` exists for callers whose contract
requires it. An empty `convert` is deliberately not a flush.

## Effective-runtime contract

The supported deployment is native x86-64 GNU/Linux, Rust 1.99 or later, with
`default-features = false, features = ["libc-iconv"]`. Cross-compilation is rejected.
Build and runtime capture the same protected paths: libc, GNU loader, the complete
gconv tree, and the executable support DSOs `libgcc_s.so.1`, `libm.so.6`,
`libssl.so.3`, `libcrypto.so.3`, `libz.so.1` and `libzstd.so.1` under
`/usr/lib/x86_64-linux-gnu`. These are the existing serving executable's GNU,
TLS and compression dependencies, not a general library allowlist. Unrelated
installed DSOs are not hashed. New native dependencies require an explicit
contract change and renewed qualification.

Capture is limited to 1024 entries, 512 MiB and 32 KiB hashing reads. Files and
ancestors must be root-owned, not group/world writable; the codec tree cannot
contain symlinks or special files. Open files, device/inode/size/timestamp stamps
and protected directory stamps are retained. Hashing/module loading occurs once,
before request admission; later gates recheck freshness and executable mappings.
For the six explicit support SONAMEs only, a root-owned alias may take one hop
to a regular file in the same protected library directory. The actual target
path/bytes are fingerprinted and matched to executable mappings; directory stamps
reject alias replacement. Multi-hop, escaping or special-file targets fail closed.

Resolved native function pointers, `AT_BASE`, GNU `link_map` module bases and
kernel `/proc/self/maps` device/inode/path identities must agree with the captured
files. Every gconv DSO is loaded and held through an owned `dlopen` reference.
Unknown executable mappings, interposed libraries, deleted/replaced files and
unsupported loader namespaces fail closed. This checks actual loaded objects,
not merely a matching file found on disk after an older libc was mapped.

`GCONV_*`, `GLIBC_TUNABLES` and `LD_*` other than `LD_LIBRARY_PATH` are rejected.
Cargo's `LD_LIBRARY_PATH` is not itself a mismatch: the actual closure is still
verified, including rejection when that search path substitutes a byte-identical
library at an unverified inode/path. The actual thread codeset must remain the
GNU C-locale `ANSI_X3.4-1968`; locale-dependent aliases cannot vary under one key.
Environment and locale must not be mutated while serving. No process-global
environment or locale setting is changed by the library.

Use one immutable common OS base/package transaction for compiler, native Git
oracle, tests and final application runtime. Do not independently upgrade runtime
libc, add DSOs after compilation, copy selected gconv files from another stage, or
run a startup package upgrade. Preserve `/proc` access and the supported loader
layout. Keep the native closure immutable while serving; a changed deployment
requires restart/rebuild. The gate still runs: common ancestry is not proof of
the actual mapped runtime. Prefer a non-root application user.

The startup limits bound explicit Rust work and input sizes, not opaque libc
allocations, constructors, loader/filesystem latency or scheduler delay. Run in a
process/container resource envelope. There is no cooperative hard-stop guarantee
for a native call, nor a guarantee against a privileged actor modifying executable
memory between checks.

## Initial qualification

Qualified on 2026-11-10 in image
`sha256:4636f3f83f9672a3114b1fa3edb66eb34e39442f068d5bc24f8f16f69028de24`:
Rust/Cargo 1.99.1, Git 2.56.0, Ubuntu glibc 2.43-2ubuntu2.4. Each container was
limited to CPUs 48-49 / 1.8 CPU / 3712 MiB / no extra swap / 232 PIDs / two build
jobs. Its finite controller used CPUs 24-25 / 0.1 CPU / 128 MiB / 12 tasks, with
independent systemd `ExecStopPost` container cleanup. Shared registry input was
read-only; an owned writable Cargo cache was used for missing dependencies.

```sh
cargo fmt --all --check
cargo test --offline --locked --no-default-features --features libc-iconv --all-targets
cargo clippy --offline --locked --no-default-features --features libc-iconv --all-targets -- -D warnings
cargo test --offline --locked --release --no-default-features --features libc-iconv --test runtime matching_runtime_and_source_identity -- --exact --nocapture
cargo test --offline --locked --release --no-default-features --features libc-iconv --test stream
```

Results: the 20 existing upstream tests, six streaming tests and four regular
runtime tests passed. Release startup verification and six release streaming
tests passed; the matching release probe completed in 0.19 seconds (observation,
not a latency guarantee). Strict Clippy and formatting passed.

Two additional ignored mutation probes passed, each alone in a new disposable
owned root container, using `ICONV_OWNED_RUNTIME_CONTAINER=1` and
`--test runtime <name> -- --exact --ignored --test-threads=1`:

- `changed_module_rejects_cold_and_warm_processes`: append bytes without changing
  valid ELF code or the mapped inode; cold content equality and warm freshness
  must both reject. A restoration guard retains the original contents.
- `mapped_libc_identity_is_not_just_a_filesystem_hash`: replace libc with identical
  bytes after child exec but before proof creation; actual mapped inode must
  reject even though the filesystem digest is unchanged. Original inode restored.

These probes must never run on a host or in a container shared with other work.
Children use explicit barriers, finite 30-second waits and kill/wait cleanup.

Four real compiled RED controls failed for the intended `Ok(())` versus required
error assertion: removed override rejection; disabled closure hash comparison;
removed warm freshness check; reduced proof to filesystem validation by bypassing
mapped-object checks. All faults were restored, then the full GREEN commands and
both disposable-container probes passed again. Setup/compilation failures are not
counted as sensitivity evidence.

This qualification is for the dependency only. Application cache/publication
fences, downstream exact Git pin, native complete-porcelain equivalence and final
multi-stage application Docker integration remain the application owner's tests.

## Explicit serving support closure follow-up

The original profile correctly rejected the root serving binary's pre-existing
OpenSSL/zlib/zstd mappings. The four support SONAMEs above are now explicitly
captured, including one-hop zlib/zstd aliases to their actual regular files. The
runtime verifier, resolved native-FFI symbol validation, loader/proc mapping
checks, file hashes and freshness checks are unchanged; no arbitrary system DSO
or broad installed-library inventory was admitted.

The same pinned image/resource envelope was used for follow-up qualification:

- 32 regular tests pass in both debug and release: 20 existing, six streaming,
  five runtime and one serving-support test. Strict all-target Clippy and fmt pass.
- The support test uses DT_NEEDED to map all four real libraries before verify,
  then checks their stable TLS/version ABIs. It failed with Loader against the
  previous profile before the capture extension, then passed with the fix.
- A fresh child deliberately dlopens unlisted `libresolv.so.2` from the protected
  system directory and is rejected. The actual SSL LD_PRELOAD case is also
  rejected, as is a search-path substituted byte-identical library.
- Three separately owned disposable-root-container probes pass: cold/warm gconv
  drift; byte-identical replaced mapped libc; and identical-byte replacement of
  each of the four mapped TLS/compression objects, including alias targets.
  Every original file/inode is restored, with barriers and finite child cleanup.
- New real RED controls bypass the subsequent namespace check (unlisted DSO
  incorrectly succeeds), and bypass namespace validation during identical-byte
  support replacement (incorrect success instead of Loader). Both fail on the
  intended result assertion; all faults are restored before final GREEN.

An old mapped support object's renamed/deleted path is classified as Loader;
direct libc symbol mapping mismatch remains Mismatch. Both are fail-closed,
distinct from a codec conversion failure. The first support mutation fixture was
corrected to expect this existing public error classification, not a new fallback.
Application cache wiring and the actual release image remain separate gates.
