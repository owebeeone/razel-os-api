//! `razel-os-api` — the `System` seam: the one OS/syscall surface. Hardened per DR55/DR48 (C13/C19,
//! ADR-0008): typed OS paths (no `&str`), fail-closed `OsError::NotFound` (never a silent empty), `lstat` ≠
//! `stat`, `Metadata` carries NO digest (stat-as-identity is forbidden), exact-env spawn (no host inherit),
//! `OsPathPolicy` for alias canonicalization. Per-OS impls + the in-memory `Fake` all pass ONE conformance
//! suite. Representative-complete surface (the remaining link/clone/rename/temp/lock methods extend the same
//! shape). SKELETON bodies in the Fake.

use std::collections::BTreeMap;

// ──────────────── Typed OS path/env values (no stringly-typed paths) ────────────────
/// A concrete host filesystem path. NOT a `razel-core::Key` component — host paths never enter a node key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HostPath(String);
impl HostPath {
    /// Construction is restricted to the OS seam / declared-edge policy.
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn join(&self, frag: &OsPathFragment) -> HostPath { HostPath(format!("{}/{}", self.0, frag.0)) }
}
/// A validated path fragment (no `..`, no separators-as-data). The *validated* path is
/// `OsPathPolicy::normalize_fragment`; `new_unchecked` is for impls that have already validated (e.g. a real
/// directory entry from `list_dir`). SKELETON: the real crate seals this to a crate-visible ctor.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct OsPathFragment(String);
impl OsPathFragment {
    pub fn new_unchecked(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}
/// The RAW target of a symlink — may be relative/non-canonical, so it is NOT a `HostPath`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawSymlinkTarget(pub String);
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EnvName(pub String);
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OsValue(pub String);
pub type EnvMap = BTreeMap<EnvName, OsValue>;

// ──────────────── Stat results — fail-closed; Metadata has NO digest (REQ-SYSTEM-013) ────────────────
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind { File, Dir, Symlink }
/// Cheap dirty-check identity (size + mtime + opaque file-id). Deliberately exposes NO content digest —
/// hashing happens above, over content, never over stat.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Metadata {
    pub kind: FileKind,
    pub len: u64,
    pub mtime_nanos: i128,
    pub file_id: u64, // opaque; not a content hash
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum OsError {
    NotFound { path: String },
    PermissionDenied { path: String },
    AlreadyExists { path: String },
    Unsupported { op: &'static str, detail: String }, // e.g. clone_file on non-CoW FS — LOUD, never a silent fallback
    SpawnFailed { program: String, detail: String },
    Invalid { what: String, detail: String },
    Io { detail: String },
}

/// OS-divergent path semantics (Darwin /var↔/private/var, Windows sep/case). A capability, passed in.
pub trait OsPathPolicy: Send + Sync {
    /// Resolve OS path aliasing for comparison (e.g. Darwin `/var/x` → `/private/var/x`).
    fn canonicalize_alias(&self, p: &HostPath) -> HostPath;
    /// Validate a raw fragment: reject `..`, embedded separators. Fail-closed.
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProcessSpec {
    pub program: HostPath, // resolved program, NOT host-PATH lookup of a bare name
    pub args: Vec<String>,
    pub env: EnvMap, // EXACT — never merged with the host environment
    pub cwd: HostPath,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitStatus { pub code: i32 }

/// The one OS/syscall seam. Every impl (Fake + per-OS) passes the SAME conformance suite.
pub trait System: Send + Sync {
    fn read(&self, p: &HostPath) -> Result<Vec<u8>, OsError>;
    fn write_atomic(&self, p: &HostPath, bytes: &[u8]) -> Result<(), OsError>;
    fn exists(&self, p: &HostPath) -> Result<bool, OsError>; // Ok(false), never NotFound-as-error
    fn stat(&self, p: &HostPath) -> Result<Metadata, OsError>; // follows final symlink
    fn lstat(&self, p: &HostPath) -> Result<Metadata, OsError>; // does NOT follow final symlink
    fn list_dir(&self, p: &HostPath) -> Result<Vec<OsPathFragment>, OsError>; // deterministic byte-sorted order
    fn read_link(&self, p: &HostPath) -> Result<RawSymlinkTarget, OsError>;
    fn canonicalize(&self, p: &HostPath) -> Result<HostPath, OsError>;
    fn raw_env(&self, name: &EnvName) -> Option<OsValue>;
    fn spawn(&self, spec: &ProcessSpec) -> Result<ExitStatus, OsError>;
    fn path_policy(&self) -> &dyn OsPathPolicy;
    // The remaining surface (symlink/hardlink/clone_file/rename/create_dir_all/remove_*/temp_dir(guard)/
    // file_lock(guard)/wait/signal/cwd) extends this same typed, fail-closed shape — omitted from the
    // skeleton for brevity, not by design.
}

// ──────────────── In-memory Fake + the parameterized conformance suite ────────────────
pub mod conformance {
    use super::*;
    use std::collections::BTreeMap;

    struct IdentityPolicy;
    impl OsPathPolicy for IdentityPolicy {
        fn canonicalize_alias(&self, p: &HostPath) -> HostPath { p.clone() }
        fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
            if raw.contains("..") || raw.contains('/') {
                return Err(OsError::Invalid { what: "fragment".into(), detail: raw.into() });
            }
            Ok(OsPathFragment(raw.to_string()))
        }
    }

    /// The cross-platform reference impl. Makes every layer above testable without a real OS.
    pub struct FakeSystem {
        files: BTreeMap<String, Vec<u8>>,
        policy: IdentityPolicy,
    }
    impl Default for FakeSystem {
        fn default() -> Self { Self { files: BTreeMap::new(), policy: IdentityPolicy } }
    }
    impl FakeSystem {
        pub fn new() -> Self { Self::default() }
        pub fn with_file(mut self, p: &str, bytes: &[u8]) -> Self {
            self.files.insert(p.to_string(), bytes.to_vec());
            self
        }
    }
    impl System for FakeSystem {
        fn read(&self, p: &HostPath) -> Result<Vec<u8>, OsError> {
            self.files.get(p.as_str()).cloned().ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
        }
        fn write_atomic(&self, _p: &HostPath, _b: &[u8]) -> Result<(), OsError> {
            Err(OsError::Unsupported { op: "write_atomic", detail: "skeleton Fake is read-only".into() })
        }
        fn exists(&self, p: &HostPath) -> Result<bool, OsError> { Ok(self.files.contains_key(p.as_str())) }
        fn stat(&self, p: &HostPath) -> Result<Metadata, OsError> {
            let len = self.files.get(p.as_str()).map(|b| b.len() as u64)
                .ok_or_else(|| OsError::NotFound { path: p.as_str().into() })?;
            Ok(Metadata { kind: FileKind::File, len, mtime_nanos: 0, file_id: 0 })
        }
        fn lstat(&self, p: &HostPath) -> Result<Metadata, OsError> { self.stat(p) }
        fn list_dir(&self, p: &HostPath) -> Result<Vec<OsPathFragment>, OsError> {
            let prefix = format!("{}/", p.as_str());
            let mut out: Vec<OsPathFragment> = self.files.keys()
                .filter_map(|k| k.strip_prefix(&prefix).filter(|r| !r.contains('/')))
                .map(|r| OsPathFragment(r.to_string()))
                .collect();
            out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())); // deterministic byte order
            Ok(out)
        }
        fn read_link(&self, p: &HostPath) -> Result<RawSymlinkTarget, OsError> {
            Err(OsError::NotFound { path: p.as_str().into() })
        }
        fn canonicalize(&self, p: &HostPath) -> Result<HostPath, OsError> { Ok(self.policy.canonicalize_alias(p)) }
        fn raw_env(&self, _name: &EnvName) -> Option<OsValue> { None }
        fn spawn(&self, _spec: &ProcessSpec) -> Result<ExitStatus, OsError> {
            Err(OsError::Unsupported { op: "spawn", detail: "Fake has no process model".into() })
        }
        fn path_policy(&self) -> &dyn OsPathPolicy { &self.policy }
    }

    /// Conformance harness — run against ANY `System` impl (the caller supplies the fixture).
    pub fn read_roundtrip<S: System>(sys: &S, p: &HostPath, expect: &[u8]) {
        assert_eq!(sys.read(p).expect("read must succeed"), expect, "read must return the bytes at path");
        assert_eq!(sys.stat(p).expect("stat must succeed").kind, FileKind::File, "stat kind");
    }
    pub fn missing_is_notfound<S: System>(sys: &S, absent: &HostPath) {
        assert!(matches!(sys.read(absent), Err(OsError::NotFound { .. })),
            "a missing path MUST be a typed NotFound, never an empty value");
        assert!(matches!(sys.exists(absent), Ok(false)),
            "exists() of a missing path is Ok(false), not an error");
    }

    #[cfg(test)]
    mod selftest {
        use super::*;
        #[test]
        fn fake_passes() {
            let fs = FakeSystem::new().with_file("/x", b"hi");
            read_roundtrip(&fs, &HostPath::new("/x"), b"hi");
            missing_is_notfound(&fs, &HostPath::new("/nope"));
        }
    }
}
