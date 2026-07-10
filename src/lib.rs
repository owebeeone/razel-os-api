//! `razel-os-api` — the `System` seam: the one OS/syscall surface. Hardened per DR55/DR48 (C13/C19,
//! ADR-0008): typed OS paths (no `&str`), fail-closed `OsError::NotFound` (never a silent empty), `lstat` ≠
//! `stat`, `Metadata` carries NO digest (stat-as-identity is forbidden), exact-env spawn (no host inherit),
//! `OsPathPolicy` for alias canonicalization. Per-OS impls + the in-memory `Fake` all pass ONE conformance
//! suite. Representative-complete surface (the remaining link/clone/rename/temp/lock methods extend the same
//! shape). SKELETON bodies in the Fake.

use std::collections::BTreeMap;

pub mod env;

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

// ──────────────── UDS socket capability — opaque handles (byte-stream; framing lives ABOVE) ────────────────
// The comms plane needs sockets, but the raw-OS wall bans `std::net`/`std::os` outside razel-os-darwin.
// So the socket capability grows on THIS seam (additive; the first slice of the os-system trait-growth
// reconcile). A handle carries an impl-owned payload as `Any` — the api crate never names a std socket
// type; razel-os-darwin stows a real `UnixListener`/`UnixStream`, `FakeSystem` an in-memory paired end.
// Consumers hold handles opaquely and drive them through `System`; the byte-stream framing is above.
pub struct UdsListener(Box<dyn std::any::Any + Send + Sync>);
pub struct UdsStream(Box<dyn std::any::Any + Send + Sync>);
impl UdsListener {
    pub fn new<T: std::any::Any + Send + Sync>(inner: T) -> Self { Self(Box::new(inner)) }
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> { self.0.downcast_ref::<T>() }
}
impl UdsStream {
    pub fn new<T: std::any::Any + Send + Sync>(inner: T) -> Self { Self(Box::new(inner)) }
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> { self.0.downcast_ref::<T>() }
}

/// The one OS/syscall seam. Every impl (Fake + per-OS) passes the SAME conformance suite.
///
/// The argv + UDS methods are DEFAULT-provided (loud `Unsupported` / empty) so growing the seam is
/// additive — a `System` impl that has no process/socket model keeps compiling unchanged; the shipped
/// `DarwinSystem` and the reference `FakeSystem` override them.
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
    // file_lock(guard)/wait/signal) extends this same typed, fail-closed shape — omitted from the
    // skeleton for brevity, not by design.

    // ──────────────── argv + working directory (the T10 wall-forced gap) ────────────────
    /// The process command line (argv). The sanctioned argv capability: a daemon-rooted binary reads
    /// its command line HERE, never via `std::env` (which the raw-OS wall bans outside razel-os-darwin).
    /// Default: empty (an impl with no process model exposes no argv).
    fn args(&self) -> Vec<String> {
        Vec::new()
    }
    /// The process working directory. Default: a loud `Unsupported` (an impl with no cwd notion).
    fn cwd(&self) -> Result<HostPath, OsError> {
        Err(OsError::Unsupported { op: "cwd", detail: "this System has no working-directory notion".into() })
    }

    // ──────────────── UDS byte-stream capability (blocking v1; framing lives above) ────────────────
    /// Bind a Unix-domain socket at `path` and start listening. Blocking accept (v1). Default: `Unsupported`.
    fn uds_bind_listen(&self, path: &HostPath) -> Result<UdsListener, OsError> {
        let _ = path;
        Err(OsError::Unsupported { op: "uds_bind_listen", detail: "this System has no socket capability".into() })
    }
    /// Block until a peer connects; return the accepted byte stream. Default: `Unsupported`.
    fn uds_accept(&self, listener: &UdsListener) -> Result<UdsStream, OsError> {
        let _ = listener;
        Err(OsError::Unsupported { op: "uds_accept", detail: "this System has no socket capability".into() })
    }
    /// Connect to a listening Unix-domain socket at `path`. Default: `Unsupported`.
    fn uds_connect(&self, path: &HostPath) -> Result<UdsStream, OsError> {
        let _ = path;
        Err(OsError::Unsupported { op: "uds_connect", detail: "this System has no socket capability".into() })
    }
    /// Blocking read into `buf`; `Ok(0)` == the peer closed cleanly (EOF), never a spurious empty. Default: `Unsupported`.
    fn stream_read(&self, stream: &UdsStream, buf: &mut [u8]) -> Result<usize, OsError> {
        let _ = (stream, buf);
        Err(OsError::Unsupported { op: "stream_read", detail: "this System has no socket capability".into() })
    }
    /// Write `bytes`; returns the count written. A closed peer is a typed error, never a silent drop. Default: `Unsupported`.
    fn stream_write(&self, stream: &UdsStream, bytes: &[u8]) -> Result<usize, OsError> {
        let _ = (stream, bytes);
        Err(OsError::Unsupported { op: "stream_write", detail: "this System has no socket capability".into() })
    }
    /// Close a byte stream (idempotent). The peer's next read observes EOF; its next write, a typed error. Default: `Unsupported`.
    fn stream_close(&self, stream: &UdsStream) -> Result<(), OsError> {
        let _ = stream;
        Err(OsError::Unsupported { op: "stream_close", detail: "this System has no socket capability".into() })
    }
}

// ──────────────── In-memory Fake + the parameterized conformance suite ────────────────
pub mod conformance {
    use super::*;
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::sync::{Arc, Condvar, Mutex};

    // ──────────────── the in-memory paired-stream fake (UDS capability) ────────────────
    // A blocking bidirectional byte pipe, enough to run the SAME transport logic without a real OS.
    // Two `Pipe`s per connection (client→server, server→client) crossed between the endpoints.

    struct ChanState {
        buf: VecDeque<u8>,
        closed: bool,
    }
    /// One direction of a byte pipe: a bounded-by-nothing buffer with a blocking reader (Condvar).
    #[derive(Clone)]
    struct Pipe {
        inner: Arc<(Mutex<ChanState>, Condvar)>,
    }
    impl Pipe {
        fn new() -> Self {
            Pipe { inner: Arc::new((Mutex::new(ChanState { buf: VecDeque::new(), closed: false }), Condvar::new())) }
        }
        fn write(&self, bytes: &[u8]) -> Result<usize, OsError> {
            let (m, cv) = &*self.inner;
            let mut g = m.lock().unwrap();
            if g.closed {
                // A closed peer is a TYPED error, never a silent drop (the disconnect-cancel mechanism).
                return Err(OsError::Io { detail: "broken pipe (peer closed)".into() });
            }
            g.buf.extend(bytes.iter().copied());
            cv.notify_all();
            Ok(bytes.len())
        }
        fn read(&self, buf: &mut [u8]) -> Result<usize, OsError> {
            let (m, cv) = &*self.inner;
            let mut g = m.lock().unwrap();
            loop {
                if !g.buf.is_empty() {
                    let n = buf.len().min(g.buf.len());
                    for slot in buf.iter_mut().take(n) {
                        *slot = g.buf.pop_front().unwrap();
                    }
                    return Ok(n);
                }
                if g.closed {
                    return Ok(0); // clean EOF — never a spurious empty on a LIVE pipe
                }
                g = cv.wait(g).unwrap();
            }
        }
        fn close(&self) {
            let (m, cv) = &*self.inner;
            let mut g = m.lock().unwrap();
            g.closed = true;
            cv.notify_all();
        }
    }

    /// One endpoint of a connection: read from `rd`, write to `wr`.
    struct FakeStreamEnd {
        rd: Pipe,
        wr: Pipe,
    }
    impl Drop for FakeStreamEnd {
        fn drop(&mut self) {
            // Close on drop, mirroring a real socket fd: the peer's next read then sees a clean EOF (Ok(0)).
            // Without this, dropping a stream handle (rather than calling stream_close) would leave a peer
            // blocked forever — the Fake must model the OS's close-on-drop faithfully.
            self.wr.close();
        }
    }

    struct ListenerState {
        pending: Mutex<VecDeque<FakeStreamEnd>>,
        cv: Condvar,
    }

    /// The process-local socket broker: listeners keyed by bind path. Shared (`Arc`) so a `FakeSystem`
    /// behind an `Arc<dyn System>` serves both the server thread and the client through one broker.
    pub(super) struct FakeNet {
        listeners: Mutex<HashMap<String, Arc<ListenerState>>>,
    }
    impl FakeNet {
        fn new() -> Self {
            FakeNet { listeners: Mutex::new(HashMap::new()) }
        }
        fn bind(&self, path: &str) -> Result<Arc<ListenerState>, OsError> {
            let mut ls = self.listeners.lock().unwrap();
            if ls.contains_key(path) {
                return Err(OsError::AlreadyExists { path: path.into() });
            }
            let st = Arc::new(ListenerState { pending: Mutex::new(VecDeque::new()), cv: Condvar::new() });
            ls.insert(path.into(), st.clone());
            Ok(st)
        }
        fn connect(&self, path: &str) -> Result<FakeStreamEnd, OsError> {
            let st = self.listeners.lock().unwrap().get(path).cloned()
                .ok_or_else(|| OsError::NotFound { path: path.into() })?;
            let c2s = Pipe::new();
            let s2c = Pipe::new();
            let server_end = FakeStreamEnd { rd: c2s.clone(), wr: s2c.clone() };
            let client_end = FakeStreamEnd { rd: s2c, wr: c2s };
            st.pending.lock().unwrap().push_back(server_end);
            st.cv.notify_all();
            Ok(client_end)
        }
        fn accept(st: &ListenerState) -> FakeStreamEnd {
            let mut q = st.pending.lock().unwrap();
            loop {
                if let Some(end) = q.pop_front() {
                    return end;
                }
                q = st.cv.wait(q).unwrap();
            }
        }
    }

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

    struct FakeFile {
        bytes: Vec<u8>,
        mtime_nanos: i128,
        file_id: u64,
    }
    struct FakeLink {
        target: RawSymlinkTarget,
        mtime_nanos: i128,
        file_id: u64,
    }

    /// The cross-platform reference impl. Makes every layer above testable without a real OS.
    /// Models the *shipped* `System` surface faithfully: fail-closed missingness, a fake clock so
    /// `Metadata` dirty-check fields are real (REQ-SYSTEM-013), symlink entries with RAW targets so
    /// `lstat` ≠ `stat` is observable (REQ-SYSTEM-007), a constructed-in env snapshot (no ambient state,
    /// REQ-SYSTEM-015), and a pluggable `OsPathPolicy` so per-OS path semantics run on the Fake
    /// (REQ-SYSTEM-008/014). Still a skeleton where the trait is: `write_atomic`/`spawn` are loud
    /// `Unsupported`, never a silent success (REQ-SYSTEM-003's vocabulary).
    pub struct FakeSystem {
        files: BTreeMap<String, FakeFile>,
        symlinks: BTreeMap<String, FakeLink>,
        env: EnvMap,
        policy: Box<dyn OsPathPolicy>,
        tick: i128,   // fake clock: strictly increases per write, so a rewrite is visible in mtime
        next_id: u64, // stable per-path file ids
        args: Vec<String>,     // constructed-in argv (no ambient process argv — REQ-SYSTEM-015 shape)
        net: Arc<FakeNet>,     // the process-local UDS broker (shared across an Arc<dyn System>)
    }
    impl Default for FakeSystem {
        fn default() -> Self {
            Self {
                files: BTreeMap::new(),
                symlinks: BTreeMap::new(),
                env: EnvMap::new(),
                policy: Box::new(IdentityPolicy),
                tick: 0,
                next_id: 0,
                args: Vec::new(),
                net: Arc::new(FakeNet::new()),
            }
        }
    }
    impl FakeSystem {
        pub fn new() -> Self { Self::default() }
        /// Constructed-in argv snapshot — the Fake's `args()` reads THIS, never the ambient process argv.
        pub fn with_args(mut self, args: &[&str]) -> Self {
            self.args = args.iter().map(|s| s.to_string()).collect();
            self
        }
        pub fn with_file(mut self, p: &str, bytes: &[u8]) -> Self {
            self.put_file(p, bytes);
            self
        }
        /// Rewrite-capable fixture edit: bumps the fake clock, keeps the path's `file_id` stable — the
        /// REQ-SYSTEM-013 dirty-check fields behave like a real filesystem's.
        pub fn put_file(&mut self, p: &str, bytes: &[u8]) {
            self.tick += 1;
            let file_id = match self.files.get(p) {
                Some(f) => f.file_id,
                None => {
                    self.next_id += 1;
                    self.next_id
                }
            };
            self.files.insert(p.to_string(), FakeFile { bytes: bytes.to_vec(), mtime_nanos: self.tick, file_id });
        }
        /// A symlink entry with its RAW (possibly relative) target — never canonicalized (REQ-SYSTEM-007).
        pub fn with_symlink(mut self, link: &str, raw_target: &str) -> Self {
            self.tick += 1;
            self.next_id += 1;
            self.symlinks.insert(
                link.to_string(),
                FakeLink { target: RawSymlinkTarget(raw_target.to_string()), mtime_nanos: self.tick, file_id: self.next_id },
            );
            self
        }
        /// Constructed-in env snapshot — the Fake's `raw_env` reads THIS, never the ambient process env.
        pub fn with_env(mut self, name: &str, value: &str) -> Self {
            self.env.insert(EnvName(name.to_string()), OsValue(value.to_string()));
            self
        }
        /// Per-OS path semantics on the Fake (REQ-SYSTEM-008/014): Darwin/Windows policies run here even
        /// where the test host is neither.
        pub fn with_policy(mut self, policy: Box<dyn OsPathPolicy>) -> Self {
            self.policy = policy;
            self
        }
        /// Follow symlinks (bounded); a relative target resolves against the link's parent directory.
        fn resolve(&self, p: &HostPath) -> Result<String, OsError> {
            let mut cur = p.as_str().to_string();
            for _ in 0..8 {
                match self.symlinks.get(&cur) {
                    None => return Ok(cur),
                    Some(l) => {
                        let t = l.target.0.as_str();
                        cur = if t.starts_with('/') {
                            t.to_string()
                        } else {
                            match cur.rfind('/') {
                                Some(i) => format!("{}/{}", &cur[..i], t),
                                None => t.to_string(),
                            }
                        };
                    }
                }
            }
            Err(OsError::Io { detail: format!("symlink loop at {}", p.as_str()) })
        }
        fn file_meta(f: &FakeFile) -> Metadata {
            // MUTANT `mutant_os_stat_mtime_absorbed_to_zero` (os-system row red-first evidence): the mtime is
            // absorbed to a constant 0, so a rewrite is invisible to the stat-level dirty check — the exact
            // silent-staleness the fail-closed Darwin impl refuses (`razel-os-darwin` errs on an unavailable
            // mtime). `metadata_exposes_dirtycheck_fields` must go RED. Never enable in a real build.
            #[cfg(feature = "mutant_os_stat_mtime_absorbed_to_zero")]
            let mtime_nanos = 0;
            #[cfg(not(feature = "mutant_os_stat_mtime_absorbed_to_zero"))]
            let mtime_nanos = f.mtime_nanos;
            Metadata { kind: FileKind::File, len: f.bytes.len() as u64, mtime_nanos, file_id: f.file_id }
        }
    }
    impl System for FakeSystem {
        fn read(&self, p: &HostPath) -> Result<Vec<u8>, OsError> {
            let key = self.resolve(p)?;
            match self.files.get(&key) {
                Some(f) => Ok(f.bytes.clone()),
                None => {
                    // MUTANT `mutant_os_missing_read_as_empty` (os-system row red-first evidence): the v3
                    // Absorb at the OS boundary — a missing path becomes `Ok(vec![])` flowing downstream
                    // instead of a typed `NotFound` (REQ-SYSTEM-004, constitution catalog #1).
                    // `missing_path_is_error_never_empty_value` must go RED. Never enable in a real build.
                    #[cfg(feature = "mutant_os_missing_read_as_empty")]
                    return Ok(Vec::new());
                    #[cfg(not(feature = "mutant_os_missing_read_as_empty"))]
                    Err(OsError::NotFound { path: p.as_str().into() })
                }
            }
        }
        fn write_atomic(&self, _p: &HostPath, _b: &[u8]) -> Result<(), OsError> {
            Err(OsError::Unsupported { op: "write_atomic", detail: "skeleton Fake is read-only via System; use put_file".into() })
        }
        fn exists(&self, p: &HostPath) -> Result<bool, OsError> {
            // lstat semantics, matching the Darwin impl (`symlink_metadata`): a dangling link EXISTS.
            Ok(self.files.contains_key(p.as_str()) || self.symlinks.contains_key(p.as_str()))
        }
        fn stat(&self, p: &HostPath) -> Result<Metadata, OsError> {
            let key = self.resolve(p)?;
            self.files.get(&key).map(Self::file_meta).ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
        }
        fn lstat(&self, p: &HostPath) -> Result<Metadata, OsError> {
            if let Some(l) = self.symlinks.get(p.as_str()) {
                #[cfg(feature = "mutant_os_stat_mtime_absorbed_to_zero")]
                let mtime_nanos = 0;
                #[cfg(not(feature = "mutant_os_stat_mtime_absorbed_to_zero"))]
                let mtime_nanos = l.mtime_nanos;
                return Ok(Metadata { kind: FileKind::Symlink, len: l.target.0.len() as u64, mtime_nanos, file_id: l.file_id });
            }
            self.files.get(p.as_str()).map(Self::file_meta).ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
        }
        fn list_dir(&self, p: &HostPath) -> Result<Vec<OsPathFragment>, OsError> {
            let prefix = format!("{}/", p.as_str());
            let mut out: Vec<OsPathFragment> = self
                .files
                .keys()
                .chain(self.symlinks.keys())
                .filter_map(|k| k.strip_prefix(&prefix).filter(|r| !r.contains('/')))
                .map(|r| OsPathFragment(r.to_string()))
                .collect();
            // Fail closed (REQ-SYSTEM-004): the Fake has no empty-dir entries, so a prefix with NO entries
            // is a MISSING directory — a typed NotFound, never a default empty listing. (razel-source's
            // DIRECTORY_LISTING maps NotFound → empty-listing VALUE explicitly, above the seam.)
            if out.is_empty() && !self.files.keys().chain(self.symlinks.keys()).any(|k| k.starts_with(&prefix)) {
                return Err(OsError::NotFound { path: p.as_str().into() });
            }
            out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())); // deterministic byte order
            Ok(out)
        }
        fn read_link(&self, p: &HostPath) -> Result<RawSymlinkTarget, OsError> {
            self.symlinks
                .get(p.as_str())
                .map(|l| l.target.clone())
                .ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
        }
        fn canonicalize(&self, p: &HostPath) -> Result<HostPath, OsError> { Ok(self.policy.canonicalize_alias(p)) }
        fn raw_env(&self, name: &EnvName) -> Option<OsValue> { self.env.get(name).cloned() }
        fn spawn(&self, _spec: &ProcessSpec) -> Result<ExitStatus, OsError> {
            Err(OsError::Unsupported { op: "spawn", detail: "Fake has no process model".into() })
        }
        fn path_policy(&self) -> &dyn OsPathPolicy { self.policy.as_ref() }

        // ── argv + UDS on the Fake (the in-memory paired-stream capability) ──
        fn args(&self) -> Vec<String> { self.args.clone() }
        fn uds_bind_listen(&self, path: &HostPath) -> Result<UdsListener, OsError> {
            Ok(UdsListener::new(self.net.bind(path.as_str())?))
        }
        fn uds_accept(&self, listener: &UdsListener) -> Result<UdsStream, OsError> {
            let st = listener.downcast_ref::<Arc<ListenerState>>()
                .ok_or_else(|| OsError::Invalid { what: "UdsListener".into(), detail: "foreign handle".into() })?;
            Ok(UdsStream::new(FakeNet::accept(st)))
        }
        fn uds_connect(&self, path: &HostPath) -> Result<UdsStream, OsError> {
            Ok(UdsStream::new(self.net.connect(path.as_str())?))
        }
        fn stream_read(&self, stream: &UdsStream, buf: &mut [u8]) -> Result<usize, OsError> {
            let end = stream.downcast_ref::<FakeStreamEnd>()
                .ok_or_else(|| OsError::Invalid { what: "UdsStream".into(), detail: "foreign handle".into() })?;
            end.rd.read(buf)
        }
        fn stream_write(&self, stream: &UdsStream, bytes: &[u8]) -> Result<usize, OsError> {
            let end = stream.downcast_ref::<FakeStreamEnd>()
                .ok_or_else(|| OsError::Invalid { what: "UdsStream".into(), detail: "foreign handle".into() })?;
            end.wr.write(bytes)
        }
        fn stream_close(&self, stream: &UdsStream) -> Result<(), OsError> {
            let end = stream.downcast_ref::<FakeStreamEnd>()
                .ok_or_else(|| OsError::Invalid { what: "UdsStream".into(), detail: "foreign handle".into() })?;
            end.wr.close();
            end.rd.close();
            Ok(())
        }
    }

    // ──────────────── Conformance harness — the ONE suite, run against ANY `System` impl ────────────────
    // (REQ-SYSTEM-005): the property fns are parameterized over `S: System`; the caller supplies the
    // fixture. `razel-os-api/tests/system_conformance.rs` runs them on the Fake; `razel-os-darwin/tests/
    // conformance.rs` runs the SAME fns on the real `DarwinSystem`.

    pub fn read_roundtrip<S: System>(sys: &S, p: &HostPath, expect: &[u8]) {
        assert_eq!(sys.read(p).expect("read must succeed"), expect, "read must return the bytes at path");
        assert_eq!(sys.stat(p).expect("stat must succeed").kind, FileKind::File, "stat kind");
    }
    /// REQ-SYSTEM-004: missingness is a typed error (or `Ok(false)` for `exists`), NEVER an empty value.
    pub fn missing_is_notfound<S: System>(sys: &S, absent: &HostPath) {
        assert!(matches!(sys.read(absent), Err(OsError::NotFound { .. })),
            "read of a missing path MUST be a typed NotFound, never Ok(empty bytes)");
        assert!(matches!(sys.stat(absent), Err(OsError::NotFound { .. })),
            "stat of a missing path MUST be a typed NotFound, never a default Metadata");
        assert!(matches!(sys.list_dir(absent), Err(OsError::NotFound { .. })),
            "list_dir of a missing path MUST be a typed NotFound, never an empty listing");
        assert!(matches!(sys.exists(absent), Ok(false)),
            "exists() of a missing path is Ok(false), not an error");
    }
    /// REQ-SYSTEM-006: `list_dir` is byte-sorted and identical across calls and impls.
    pub fn list_dir_is_deterministic<S: System>(sys: &S, dir: &HostPath, expect: &[&str]) {
        let got = sys.list_dir(dir).expect("list_dir must succeed");
        let names: Vec<&str> = got.iter().map(|f| f.as_str()).collect();
        assert_eq!(names, expect, "list_dir must be sorted by raw byte name, OS-independent");
        let mut sorted = names.clone();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(names, sorted, "list_dir order must BE the byte-sort order");
        assert_eq!(sys.list_dir(dir).expect("list_dir must succeed"), got, "list_dir must be stable across calls");
    }
    /// REQ-SYSTEM-007: `lstat` reports the link itself; `stat` follows it; `read_link` returns the RAW target.
    pub fn lstat_does_not_follow_final_symlink<S: System>(sys: &S, link: &HostPath, raw_target: &str, final_kind: FileKind) {
        assert_eq!(sys.lstat(link).expect("lstat must succeed").kind, FileKind::Symlink,
            "lstat must NOT follow the final symlink (kind == Symlink)");
        assert_eq!(sys.stat(link).expect("stat must succeed").kind, final_kind,
            "stat MUST follow the final symlink to the target's kind");
        assert_eq!(sys.read_link(link).expect("read_link must succeed").0, raw_target,
            "read_link must return the raw target exactly as observed (not canonicalized)");
    }
    /// REQ-SYSTEM-013: the dirty-check identity (size/mtime/file-id) is exposed and a rewrite is visible;
    /// the path's identity (`file_id`) is stable across the rewrite. No digest lives here (F4).
    pub fn metadata_dirtycheck_fields_see_rewrite(before: &Metadata, after: &Metadata) {
        assert_eq!(before.kind, FileKind::File);
        assert_eq!(after.kind, FileKind::File);
        assert_eq!(before.file_id, after.file_id, "an in-place rewrite must keep the file id stable");
        assert!(after.mtime_nanos > before.mtime_nanos || after.len != before.len,
            "a rewrite MUST be visible in the dirty-check fields (mtime advanced or size changed): before={before:?} after={after:?}");
    }

    /// The argv capability (T10-flagged): `args()` reflects the constructed-in command line and does
    /// NOT read the ambient process argv. Fake-only exact-match (the real impl's argv is the runtime
    /// harness's — see the Darwin twin for the shape check).
    pub fn args_reflect_construction(sys: &FakeSystem, expect: &[&str]) {
        let exp: Vec<String> = expect.iter().map(|s| s.to_string()).collect();
        assert_eq!(sys.args(), exp, "args() must return exactly the constructed argv, no ambient leakage");
    }

    /// The UDS byte-stream capability, run against ANY impl: bind→accept (a server thread) +
    /// connect→write→read echo (the client), then a clean client close the server observes as `Ok(0)`.
    /// The framing lives ABOVE this seam — this proves only that the raw byte pipe carries + EOFs.
    pub fn uds_stream_echo(sys: Arc<dyn System>, sock: &HostPath) {
        let listener = sys.uds_bind_listen(sock).expect("bind_listen must succeed");
        let server_sys = sys.clone();
        let server = std::thread::spawn(move || -> usize {
            let s = server_sys.uds_accept(&listener).expect("accept must succeed");
            let mut buf = [0u8; 64];
            let n = server_sys.stream_read(&s, &mut buf).expect("server read");
            server_sys.stream_write(&s, &buf[..n]).expect("server echo"); // echo the bytes back
            let eof = server_sys.stream_read(&s, &mut buf).expect("server read to EOF");
            server_sys.stream_close(&s).expect("server close");
            eof
        });

        let client = sys.uds_connect(sock).expect("connect must succeed");
        let msg = b"ping-through-the-seam";
        assert_eq!(sys.stream_write(&client, msg).expect("client write"), msg.len());
        let mut buf = [0u8; 64];
        let n = sys.stream_read(&client, &mut buf).expect("client read echo");
        assert_eq!(&buf[..n], msg, "the byte pipe must echo the exact bytes written");
        sys.stream_close(&client).expect("client close");

        let server_saw_eof = server.join().expect("server thread joins");
        assert_eq!(server_saw_eof, 0, "server must observe a clean EOF (Ok(0)) after the client closes");
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
