//! OS-SYSTEM conformance — the `FakeSystem` half of the one suite (dev-docs/contracts/os-system.md).
//! Each test maps to ≥1 REQ-SYSTEM id. The shared property fns live in `razel_os_api::conformance` and
//! are ALSO run against the real `DarwinSystem` by `razel-os-darwin/tests/conformance.rs` — that pair is
//! REQ-SYSTEM-005's `one_suite_all_impls` (Fake + Darwin today; Linux/Windows impls join the same fns).
//!
//! Row red-first mutants (tools/gate.sh runs each and requires RED):
//!   mutant_os_missing_read_as_empty       → missing_path_is_error_never_empty_value
//!   mutant_os_stat_mtime_absorbed_to_zero → metadata_exposes_dirtycheck_fields
//!
//! Static-scan properties are pinned OUTSIDE cargo (recorded, not duplicated here):
//! `no_raw_os_outside_the_os_seam` / `alias_denylist_is_exhaustive` /
//! `allowlist_burndown_gate_fails_on_unlisted_and_expired` → `tools/raw_os.py` +
//! `tools/test_raw_os.py` + `tools/wall_fixtures.py` (fixture_s3_raw_os_alias), REQ-SYSTEM-001/002/010.

use razel_os_api::conformance::{
    args_reflect_construction, list_dir_is_deterministic, lstat_does_not_follow_final_symlink,
    metadata_dirtycheck_fields_see_rewrite, missing_is_notfound, read_roundtrip, uds_stream_echo, FakeSystem,
};
use razel_os_api::{EnvName, FileKind, HostPath, OsError, OsPathFragment, OsPathPolicy, ProcessSpec, System};
use std::sync::Arc;

fn p(s: &str) -> HostPath {
    HostPath::new(s)
}

// ──────────────── test-local per-OS policies (the REQ-SYSTEM-008/014 fixtures) ────────────────
// Same reference shapes as the path-types twin suite (tests/path_types_conformance.rs): pinned by
// fixture, not inherited from the test host.

struct DarwinAliasPolicy;
impl OsPathPolicy for DarwinAliasPolicy {
    fn canonicalize_alias(&self, path: &HostPath) -> HostPath {
        let s = path.as_str();
        for alias in ["/var", "/tmp", "/etc"] {
            if s == alias || s.starts_with(&format!("{alias}/")) {
                return HostPath::new(format!("/private{s}"));
            }
        }
        path.clone()
    }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if raw.is_empty() || raw.contains('/') || raw == "." || raw == ".." {
            return Err(OsError::Invalid { what: "fragment".into(), detail: raw.into() });
        }
        Ok(OsPathFragment::new_unchecked(raw))
    }
}

struct WindowsPolicy;
impl OsPathPolicy for WindowsPolicy {
    fn canonicalize_alias(&self, path: &HostPath) -> HostPath {
        HostPath::new(path.as_str().replace('/', "\\").to_ascii_lowercase())
    }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if raw.is_empty() || raw.contains('/') || raw.contains('\\') || raw == "." || raw == ".." {
            return Err(OsError::Invalid { what: "fragment".into(), detail: raw.into() });
        }
        Ok(OsPathFragment::new_unchecked(raw.to_ascii_lowercase()))
    }
}

// ──────────────── REQ-SYSTEM-004 — missingness is typed, never an empty value ────────────────

/// REQ-SYSTEM-004: `read`/`stat`/`list_dir` of an absent path are a typed `NotFound`; `exists` is
/// `Ok(false)`. `read` is NEVER `Ok(vec![])` — the mutant `mutant_os_missing_read_as_empty` turns the
/// missing read into exactly that absorb and this test must go red.
#[test]
fn missing_path_is_error_never_empty_value() {
    let fs = FakeSystem::new().with_file("/root/present.txt", b"hi");
    missing_is_notfound(&fs, &p("/root/absent.txt"));
    missing_is_notfound(&fs, &p("/no/such/dir"));
    // The presence control: the same calls succeed on a real entry.
    read_roundtrip(&fs, &p("/root/present.txt"), b"hi");
}

// ──────────────── REQ-SYSTEM-005 — one suite, all impls ────────────────

/// REQ-SYSTEM-005 (`one_suite_all_impls`, the Fake half): the SAME parameterized property fns this file
/// runs on `FakeSystem` are run on the real `DarwinSystem` by razel-os-darwin/tests/conformance.rs.
/// A capability the Fake cannot provide is a LOUD `Unsupported` (see `unsupported_is_loud_not_silent`),
/// never a silent skip.
#[test]
fn one_suite_all_impls_fake_half() {
    let fs = FakeSystem::new().with_file("/x", b"bytes");
    read_roundtrip(&fs, &p("/x"), b"bytes");
    missing_is_notfound(&fs, &p("/nope"));
}

// ──────────────── REQ-SYSTEM-006 — deterministic listing ────────────────

/// REQ-SYSTEM-006: `list_dir` is sorted by raw byte name — scrambled insertion order and mixed case do
/// not change it ("A" (0x41) < "b" (0x62); "0" first).
#[test]
fn list_dir_is_deterministically_ordered() {
    let fs = FakeSystem::new()
        .with_file("/d/z.txt", b"1")
        .with_file("/d/A.txt", b"2")
        .with_file("/d/b.rs", b"3")
        .with_file("/d/0cfg", b"4");
    list_dir_is_deterministic(&fs, &p("/d"), &["0cfg", "A.txt", "b.rs", "z.txt"]);
}

// ──────────────── REQ-SYSTEM-007 — lstat ≠ stat; raw link targets ────────────────

/// REQ-SYSTEM-007: `lstat` reports the SYMLINK; `stat` follows to the target's kind; `read_link` returns
/// the raw (here: relative) target byte-for-byte.
#[test]
fn lstat_does_not_follow_final_symlink_on_fake() {
    let fs = FakeSystem::new().with_file("/d/real.txt", b"content").with_symlink("/d/link", "real.txt");
    lstat_does_not_follow_final_symlink(&fs, &p("/d/link"), "real.txt", FileKind::File);
    // A dangling link still lstat's and read_link's raw — `..`-relative bytes survive untouched.
    let fs2 = FakeSystem::new().with_symlink("/d/dangling", "../peer/./gone");
    assert_eq!(fs2.lstat(&p("/d/dangling")).expect("lstat").kind, FileKind::Symlink);
    assert_eq!(fs2.read_link(&p("/d/dangling")).expect("read_link").0, "../peer/./gone");
    assert!(matches!(fs2.stat(&p("/d/dangling")), Err(OsError::NotFound { .. })),
        "stat THROUGH a dangling link is NotFound (typed), never a default");
}

// ──────────────── REQ-SYSTEM-008 — Darwin aliasing on the Fake ────────────────

/// REQ-SYSTEM-008: with the Darwin policy, `canonicalize` collapses the `/var` firmlink alias — the
/// resolved form is what enters host-path comparison. (The real-impl half lives in razel-os-darwin.)
#[test]
fn darwin_var_aliases_to_private_var() {
    let fs = FakeSystem::new().with_policy(Box::new(DarwinAliasPolicy));
    assert_eq!(fs.canonicalize(&p("/var/db/x")).expect("canonicalize"), p("/private/var/db/x"));
    assert_eq!(fs.canonicalize(&p("/tmp/y")).expect("canonicalize"), p("/private/tmp/y"));
    assert_eq!(fs.canonicalize(&p("/variant/x")).expect("canonicalize"), p("/variant/x"),
        "the alias applies to the /var COMPONENT, not the /var prefix bytes");
}

// ──────────────── REQ-SYSTEM-013 — dirty-check metadata (and its mtime-absorb mutant) ────────────────

/// REQ-SYSTEM-013: `Metadata` exposes size + mtime + a stable file id, and a rewrite is VISIBLE in them
/// even when the length is unchanged. The mutant `mutant_os_stat_mtime_absorbed_to_zero` absorbs the
/// mtime to a constant and this test must go red. (No content digest lives on `Metadata` — hashing is
/// `core::Digest`, over content, F4.)
#[test]
fn metadata_exposes_dirtycheck_fields() {
    let mut fs = FakeSystem::new();
    fs.put_file("/f", b"aa");
    let before = fs.stat(&p("/f")).expect("stat before");
    assert_eq!(before.len, 2);
    fs.put_file("/f", b"bb"); // same length — only the mtime can carry the change
    let after = fs.stat(&p("/f")).expect("stat after");
    metadata_dirtycheck_fields_see_rewrite(&before, &after);
    assert!(after.mtime_nanos > before.mtime_nanos,
        "same-length rewrite MUST advance the mtime (the cheap dirty-check depends on it)");
}

// ──────────────── REQ-SYSTEM-014 — Windows semantics exercised on the Fake ────────────────

/// REQ-SYSTEM-014: the Windows policy runs on the Fake on a Unix host — `\` and case-insensitivity are
/// pinned by fixture; separator-carrying or dot fragments fail closed.
#[test]
fn windows_policy_exercised_on_fake() {
    let fs = FakeSystem::new().with_policy(Box::new(WindowsPolicy));
    assert_eq!(
        fs.canonicalize(&p("C:/Foo/Bar")).expect("canonicalize"),
        fs.canonicalize(&p("c:\\foo\\bar")).expect("canonicalize"),
        "separator and case must canonicalize identically under the Windows policy"
    );
    let pol = fs.path_policy();
    assert_eq!(pol.normalize_fragment("ReadMe.MD").unwrap(), pol.normalize_fragment("readme.md").unwrap());
    assert!(pol.normalize_fragment("a/b").is_err());
    assert!(pol.normalize_fragment("a\\b").is_err());
    assert!(pol.normalize_fragment("..").is_err());
}

// ──────────────── REQ-SYSTEM-015 — Send+Sync, no ambient state ────────────────

/// REQ-SYSTEM-015: `System` impls are `Send + Sync` (compile-time) and hold NO ambient/process-global
/// state — two instances with different env snapshots do not cross-contaminate, and neither reads the
/// ambient process env at all.
#[test]
fn system_is_send_sync_no_ambient_state() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakeSystem>();
    let a = FakeSystem::new().with_env("ONLY_A", "a-value");
    let b = FakeSystem::new().with_env("ONLY_B", "b-value");
    let only_a = EnvName("ONLY_A".into());
    let only_b = EnvName("ONLY_B".into());
    assert_eq!(a.raw_env(&only_a).map(|v| v.0), Some("a-value".to_string()));
    assert_eq!(b.raw_env(&only_b).map(|v| v.0), Some("b-value".to_string()));
    assert_eq!(a.raw_env(&only_b), None, "instance A must not see instance B's snapshot");
    assert_eq!(b.raw_env(&only_a), None, "instance B must not see instance A's snapshot");
    // PATH is set in any test-runner process; the Fake's constructed-in snapshot must NOT expose it.
    assert_eq!(a.raw_env(&EnvName("PATH".into())), None, "no ambient env reaches raw_env");
}

// ──────────────── REQ-SYSTEM-003 (shipped-surface half) — Unsupported is loud ────────────────

// ──────────────── argv + UDS capability growth (os-system trait-growth reconcile, first slice) ────────────────

/// The sanctioned argv capability (T10-flagged gap): `args()` returns the constructed-in command line
/// and the default (no `with_args`) is empty — never the ambient process argv.
#[test]
fn args_reflect_constructed_argv() {
    let fs = FakeSystem::new().with_args(&["razel-daemon", "batch", "build", "//hello:out.txt"]);
    args_reflect_construction(&fs, &["razel-daemon", "batch", "build", "//hello:out.txt"]);
    args_reflect_construction(&FakeSystem::new(), &[]);
}

/// The UDS byte-stream capability on the Fake half of the one suite (the SAME `uds_stream_echo` runs
/// on `DarwinSystem` in razel-os-darwin/tests/conformance.rs — REQ-SYSTEM-005). bind→accept→
/// connect→write→read echo→close, with the server observing a clean `Ok(0)` EOF.
#[test]
fn uds_byte_stream_echoes_on_fake() {
    let fs: Arc<dyn System> = Arc::new(FakeSystem::new());
    uds_stream_echo(fs, &p("/sock/echo"));
}

/// A closed peer is a typed error, never a silent drop: after the reader end closes, a write to it
/// fails (the disconnect-cancel mechanism the comms layer builds on).
#[test]
fn uds_write_to_closed_peer_is_typed_error() {
    let fs: Arc<dyn System> = Arc::new(FakeSystem::new());
    let sock = p("/sock/closed");
    let listener = fs.uds_bind_listen(&sock).expect("bind");
    let client = fs.uds_connect(&sock).expect("connect");
    let server = fs.uds_accept(&listener).expect("accept");
    fs.stream_close(&server).expect("server closes"); // reader end gone
    // The client's write to the now-closed peer must be a typed error (broken pipe), never Ok-and-dropped.
    assert!(matches!(fs.stream_write(&client, b"lost"), Err(OsError::Io { .. })),
        "write to a closed peer must be a typed error");
}

/// REQ-SYSTEM-003 vocabulary on the shipped surface: a capability an impl cannot provide is a typed
/// `Unsupported` naming the op — never a silent success/fallback. (The `clone_file`-specific gate
/// `unsupported_clone_is_loud_not_silent_copy` needs the not-yet-shipped `clone_file` method and is a
/// recorded remaining-to-specced item in the contract doc.)
#[test]
fn unsupported_is_loud_not_silent() {
    let fs = FakeSystem::new().with_file("/x", b"hi");
    match fs.write_atomic(&p("/x"), b"new") {
        Err(OsError::Unsupported { op, .. }) => assert_eq!(op, "write_atomic"),
        other => panic!("write_atomic on the skeleton Fake must be a LOUD Unsupported, got {other:?}"),
    }
    assert_eq!(fs.read(&p("/x")).expect("read"), b"hi", "the refused write must not have happened");
    let spec = ProcessSpec {
        program: p("/bin/true"),
        args: vec![],
        env: Default::default(),
        cwd: p("/"),
    };
    assert!(matches!(fs.spawn(&spec), Err(OsError::Unsupported { op: "spawn", .. })),
        "the Fake has no process model — spawn is a loud Unsupported, never a fabricated ExitStatus");
}
