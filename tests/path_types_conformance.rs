//! PATH-TYPES conformance, OS-string half — the twin of `razel-ids/tests/path_types_conformance.rs`
//! (dev-docs/contracts/path-types.md; the row's gate command runs both). After the DRR48-3 split the
//! contract's OS-string vocabulary (`HostPath`, `OsPathFragment`, `RawSymlinkTarget`, `OsPathPolicy`)
//! lives HERE; this suite pins the raw-symlink law (REQ-PATHTYPES-003) and the per-OS policy fixtures
//! (REQ-PATHTYPES-004) against test-local reference policies implementing the real `OsPathPolicy` seam.
//! The row's red-first mutants live in the razel-ids half (the logical vocabulary).

use razel_os_api::{HostPath, OsError, OsPathFragment, OsPathPolicy, RawSymlinkTarget};
use std::any::TypeId;

// ──────────────── Test-local reference policies (the REQ-PATHTYPES-004 fixtures) ────────────────

fn reject_separators_and_dots(raw: &str) -> Option<OsError> {
    if raw.is_empty() || raw.contains('/') || raw.contains('\\') || raw == "." || raw == ".." {
        return Some(OsError::Invalid { what: "fragment".into(), detail: raw.into() });
    }
    None
}

/// Linux: byte-identity, case-SENSITIVE, `/` separator.
struct LinuxPolicy;
impl OsPathPolicy for LinuxPolicy {
    fn canonicalize_alias(&self, p: &HostPath) -> HostPath {
        p.clone()
    }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if let Some(e) = reject_separators_and_dots(raw) {
            return Err(e);
        }
        Ok(OsPathFragment::new_unchecked(raw))
    }
}

/// Windows: `/` and `\` both separate, comparison is case-INSENSITIVE (canonical form: backslash +
/// lowercase). Pinned by fixture, not inherited from the host.
struct WindowsPolicy;
impl OsPathPolicy for WindowsPolicy {
    fn canonicalize_alias(&self, p: &HostPath) -> HostPath {
        HostPath::new(p.as_str().replace('/', "\\").to_ascii_lowercase())
    }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if let Some(e) = reject_separators_and_dots(raw) {
            return Err(e);
        }
        Ok(OsPathFragment::new_unchecked(raw.to_ascii_lowercase()))
    }
}

/// Darwin: `/var`-family firmlink aliases canonicalize under `/private`. Case handling is deliberately
/// linux-like here — the final Darwin case-fold decision is a recorded pre-FREEZE open question in
/// dev-docs/contracts/path-types.md, not a specced-gate blocker.
struct DarwinPolicy;
impl OsPathPolicy for DarwinPolicy {
    fn canonicalize_alias(&self, p: &HostPath) -> HostPath {
        let s = p.as_str();
        for alias in ["/var", "/tmp", "/etc"] {
            if s == alias || s.starts_with(&format!("{alias}/")) {
                return HostPath::new(format!("/private{s}"));
            }
        }
        p.clone()
    }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if let Some(e) = reject_separators_and_dots(raw) {
            return Err(e);
        }
        Ok(OsPathFragment::new_unchecked(raw))
    }
}

// ──────────────── REQ-PATHTYPES-003 — raw symlink targets stay raw ────────────────

/// REQ-PATHTYPES-003: `RawSymlinkTarget` preserves the OS-returned target byte-for-byte — relative
/// forms, `.`/`..`, and platform separators are DATA here, never canonicalized away.
#[test]
fn relative_symlink_target_round_trips_raw() {
    for raw in ["../peer/./file", "sub/link2", "..\\win\\style", "/abs/target"] {
        let t = RawSymlinkTarget(raw.to_string());
        assert_eq!(t.0, raw, "the raw target must survive untouched");
    }
}

/// REQ-PATHTYPES-003: a raw link target is NOT a `HostPath` — distinct type, no conversion. A relative
/// target (the common case) has no host-absolute reading at all until a later contract interprets it
/// against its link's directory.
#[test]
fn raw_link_target_not_hostpath() {
    assert_ne!(
        TypeId::of::<RawSymlinkTarget>(),
        TypeId::of::<HostPath>(),
        "RawSymlinkTarget and HostPath must stay distinct types"
    );
    // No From/Into bridge exists between them (compile-fact: writing
    // `HostPath::from(RawSymlinkTarget(..))` does not resolve). The raw carrier happily holds a relative
    // target, which a host-ABSOLUTE path type must never represent.
    let rel = RawSymlinkTarget("../sibling".to_string());
    assert!(rel.0.starts_with(".."));
}

// ──────────────── REQ-PATHTYPES-004 — per-OS policy fixtures, pinned ────────────────

/// REQ-PATHTYPES-004: Windows separator + case behavior is pinned — `/` vs `\` and letter case do not
/// produce distinct canonical identities; fragments with embedded separators or dot-segments fail closed.
#[test]
fn windows_separator_and_case_policy() {
    let p = WindowsPolicy;
    assert_eq!(
        p.canonicalize_alias(&HostPath::new("C:/Foo/Bar")),
        p.canonicalize_alias(&HostPath::new("c:\\foo\\bar")),
        "separator and case must canonicalize identically"
    );
    assert_eq!(
        p.normalize_fragment("ReadMe.MD").unwrap(),
        p.normalize_fragment("readme.md").unwrap(),
        "windows fragment comparison is case-insensitive (canonical lowercase)"
    );
    assert!(p.normalize_fragment("a/b").is_err());
    assert!(p.normalize_fragment("a\\b").is_err());
    assert!(p.normalize_fragment("..").is_err());
}

/// REQ-PATHTYPES-004: Linux is case-SENSITIVE byte identity.
#[test]
fn linux_case_sensitive_policy() {
    let p = LinuxPolicy;
    assert_ne!(
        p.canonicalize_alias(&HostPath::new("/srv/Data")),
        p.canonicalize_alias(&HostPath::new("/srv/data")),
        "linux paths differing only in case are DIFFERENT paths"
    );
    assert_ne!(p.normalize_fragment("A").unwrap(), p.normalize_fragment("a").unwrap());
    assert!(p.normalize_fragment("a/b").is_err());
    assert!(p.normalize_fragment("..").is_err());
}

/// REQ-PATHTYPES-004 (DECIDED 2026-07-06, the pre-freeze open question): Darwin logical path identity is
/// BYTE-EXACT — `CaseFold::Sensitive` — per the Bazel-parity rule (Bazel never case-folds path/label
/// identity; APFS filesystem aliasing is an OS-effect concern for the source-probe layer, not identity).
#[test]
fn darwin_case_sensitive_logical_identity() {
    let p = DarwinPolicy;
    assert_ne!(p.normalize_fragment("A").unwrap(), p.normalize_fragment("a").unwrap(),
        "two spellings differing only in case are DISTINCT logical fragments on Darwin");
    assert_ne!(
        p.canonicalize_alias(&HostPath::new("/private/var/X")),
        p.canonicalize_alias(&HostPath::new("/private/var/x")),
        "alias canonicalization never case-folds either (byte-exact identity)"
    );
}

/// REQ-PATHTYPES-004: the Darwin `/var` firmlink alias canonicalizes so aliased spellings compare equal.
#[test]
fn darwin_var_alias_compares_equal() {
    let p = DarwinPolicy;
    assert_eq!(
        p.canonicalize_alias(&HostPath::new("/var/db/x")),
        p.canonicalize_alias(&HostPath::new("/private/var/db/x")),
        "/var/x and /private/var/x are one identity on Darwin"
    );
    assert_ne!(
        p.canonicalize_alias(&HostPath::new("/variant/x")),
        p.canonicalize_alias(&HostPath::new("/private/variant/x")),
        "the alias applies to the /var COMPONENT, not the /var prefix bytes"
    );
}

/// REQ-PATHTYPES-004: for a fixed policy and input, normalization is deterministic — same output,
/// byte-identical, every call. (The logical-half determinism gate — and its red-first mutant — is the
/// razel-ids twin's `normalization_is_deterministic`.)
#[test]
fn normalization_is_deterministic() {
    let policies: Vec<Box<dyn OsPathPolicy>> = vec![Box::new(LinuxPolicy), Box::new(WindowsPolicy), Box::new(DarwinPolicy)];
    for p in &policies {
        assert_eq!(
            p.normalize_fragment("Fragment.txt").unwrap(),
            p.normalize_fragment("Fragment.txt").unwrap(),
            "one policy, one input ⇒ one canonical fragment"
        );
        assert_eq!(
            p.canonicalize_alias(&HostPath::new("/var/x")),
            p.canonicalize_alias(&HostPath::new("/var/x")),
            "alias canonicalization must be a pure function"
        );
    }
}
