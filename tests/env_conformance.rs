//! PATHS-AND-ENV conformance (dev-docs/contracts/paths-and-env.md): environment as a graph input.
//! Each test maps to ≥1 REQ-PATHENV id; the suite runs against the reference mock
//! (`razel_os_api::env::mock::DeclaredClientEnv`) over the `FakeSystem` seam.
//!
//! Row red-first mutants (tools/gate.sh runs each and requires RED):
//!   mutant_env_undeclared_as_unset → undeclared_env_read_fails_closed
//!   mutant_env_read_not_recorded   → env_read_records_envvar_node
//!
//! Pinned ELSEWHERE and recorded, not duplicated here (per RazelV4ActionKeyLockdown.md §4):
//!   `host_absolute_path_not_in_action_identity` (REQ-PATHENV-007) and
//!   `effective_action_env_in_action_key` (REQ-PATHENV-008) are razel-action tests of those exact
//!   names (razel-action/src/lib.rs), backed by mutants `mutant_action_key_drops_tools` /
//!   `mutant_action_key_drops_exec_dims` and the raw-OS wall (tools/raw_os.py, empty allowlist).
//!   `no_ambient_env_above_system` (REQ-PATHENV-001's static half) is the same wall: naming `std::env`
//!   outside razel-os-darwin is a CI failure.
//!   `repository_rule_getenv_records_envvar_node` (REQ-PATHENV-009) is explicitly deferred to the
//!   fetch/Bzlmod cluster (ADR-0011), per the contract's own deferral clause.

use razel_core::{Error, Value};
use razel_os_api::conformance::FakeSystem;
use razel_os_api::env::mock::{DeclaredClientEnv, RecordedEnvDeps};
use razel_os_api::env::{ClientEnv, ClientEnvSnapshot, EnvValue, EnvVarKey, EnvVarNode, ENV_VAR};
use razel_os_api::{EnvName, OsValue};
use std::collections::BTreeSet;

fn n(s: &str) -> EnvName {
    EnvName(s.to_string())
}
fn declared(names: &[&str]) -> BTreeSet<EnvName> {
    names.iter().map(|s| n(s)).collect()
}

// ──────────────── REQ-PATHENV-001 — reads are recorded EnvVarNode dependencies ────────────────

/// REQ-PATHENV-001: every `ClientEnv::get` of a declared var records a dependency on that var's
/// `EnvVarKey` node key — one record per read, the exact key, nothing else. The mutant
/// `mutant_env_read_not_recorded` skips the record and this test must go red.
#[test]
fn env_read_records_envvar_node() {
    let sys = FakeSystem::new().with_env("CC", "clang");
    let env = DeclaredClientEnv::from_system(&sys, &declared(&["CC", "OPT"]));
    let mut deps = RecordedEnvDeps::new();
    assert_eq!(env.get(&mut deps, &n("CC")).expect("declared read"), EnvValue::Set(OsValue("clang".into())));
    assert_eq!(env.get(&mut deps, &n("OPT")).expect("declared read"), EnvValue::Unset);
    assert_eq!(env.get(&mut deps, &n("CC")).expect("declared read"), EnvValue::Set(OsValue("clang".into())));
    let cc = EnvVarKey { name: n("CC") }.node_key();
    let opt = EnvVarKey { name: n("OPT") }.node_key();
    assert_eq!(deps.0, vec![cc.clone(), opt, cc], "each read records exactly its var's node key, in order");
    assert_eq!(deps.0[0].kind(), ENV_VAR, "the recorded key is the ENV_VAR leaf kind");
}

/// REQ-PATHENV-001 (the seam half of `no_ambient_env_above_system`): the snapshot is a pure function of
/// the `System` seam + the declared set — two Systems with different host env yield different snapshots,
/// and the ambient test-runner env (PATH is always set) never leaks in. The static half — no `std::env`
/// above the seam AT ALL — is the raw-OS wall (tools/raw_os.py), recorded in the suite doc-comment.
#[test]
fn snapshot_reads_host_only_via_system_seam() {
    let host_a = FakeSystem::new().with_env("CC", "clang");
    let host_b = FakeSystem::new().with_env("CC", "gcc");
    let names = declared(&["CC", "PATH"]);
    let snap_a = ClientEnvSnapshot::capture(&host_a, &names);
    let snap_b = ClientEnvSnapshot::capture(&host_b, &names);
    assert_ne!(snap_a, snap_b, "the snapshot must reflect ITS System, not shared ambient state");
    assert_eq!(snap_a.declared[&n("CC")], EnvValue::Set(OsValue("clang".into())));
    assert_eq!(snap_b.declared[&n("CC")], EnvValue::Set(OsValue("gcc".into())));
    // PATH is set in the ambient test-runner env, but neither Fake declares-and-hosts it via the seam:
    assert_eq!(snap_a.declared[&n("PATH")], EnvValue::Unset,
        "the ambient process env has no channel into the snapshot — only System::raw_env does");
}

// ──────────────── REQ-PATHENV-002 — undeclared reads fail closed ────────────────

/// REQ-PATHENV-002: reading an UNDECLARED var is a loud typed `Error` — not `Unset`, not `""`, not any
/// default. The mutant `mutant_env_undeclared_as_unset` absorbs it to `Ok(Unset)` and this test must go
/// red. A failed read also records NO dependency (there is no node to depend on).
#[test]
fn undeclared_env_read_fails_closed() {
    let sys = FakeSystem::new().with_env("HOME", "/host/home"); // present on the host…
    let env = DeclaredClientEnv::from_system(&sys, &declared(&["CC"])); // …but NOT declared
    let mut deps = RecordedEnvDeps::new();
    let got = env.get(&mut deps, &n("HOME"));
    assert!(matches!(got, Err(Error::Invalid { .. })),
        "an undeclared env read MUST be a typed error, never a value: got {got:?}");
    assert!(deps.0.is_empty(), "a refused read records no dependency");
    assert!(!env.declared().contains(&n("HOME")));
}

// ──────────────── REQ-PATHENV-003 — Unset is explicit, three-way distinct ────────────────

/// REQ-PATHENV-003: declared-but-absent is the EXPLICIT `Unset` — distinct from `Set("")` (empty string)
/// and distinct from undeclared (an error). All three are told apart, including by content digest.
#[test]
fn unset_declared_is_explicit_not_empty() {
    let sys = FakeSystem::new().with_env("EMPTY", "");
    let env = DeclaredClientEnv::from_system(&sys, &declared(&["EMPTY", "ABSENT"]));
    let mut deps = RecordedEnvDeps::new();
    let empty = env.get(&mut deps, &n("EMPTY")).expect("declared read");
    let absent = env.get(&mut deps, &n("ABSENT")).expect("declared read");
    assert_eq!(empty, EnvValue::Set(OsValue(String::new())));
    assert_eq!(absent, EnvValue::Unset);
    assert_ne!(empty, absent, "Unset and Set(\"\") are DIFFERENT values");
    assert_ne!(empty.content_digest(), absent.content_digest(),
        "…and different content digests (the engine's change detection sees the difference)");
    assert!(env.get(&mut deps, &n("UNDECLARED")).is_err(), "undeclared stays an error, not a third value");
}

// ──────────────── REQ-PATHENV-004 — invalidation scope: exactly the readers ────────────────

/// REQ-PATHENV-004 (the seam half): distinct names are distinct node keys, a reader's recorded deps are
/// EXACTLY the names it read (so a change to var B cannot reach a reader of only A through the frozen
/// engine's recorded-dep invalidation), and an undeclared var has NO key channel at all. Value identity
/// is honest too: same value ⇒ equal digest (cutoff), changed value ⇒ different digest (invalidate).
#[test]
fn only_declared_env_change_invalidates() {
    let key_a = EnvVarKey { name: n("A") };
    let key_b = EnvVarKey { name: n("B") };
    assert_ne!(key_a.node_key(), key_b.node_key(), "one leaf per name — B's change cannot alias into A");
    assert_eq!(key_a.node_key(), EnvVarKey { name: n("A") }.node_key(), "the key encoding is canonical");

    let sys = FakeSystem::new().with_env("A", "1").with_env("B", "2");
    let env = DeclaredClientEnv::from_system(&sys, &declared(&["A", "B"]));
    let mut deps = RecordedEnvDeps::new();
    env.get(&mut deps, &n("A")).expect("read A");
    assert_eq!(deps.0, vec![key_a.node_key()],
        "a reader of only A depends on exactly A — nothing else can invalidate it");

    // an undeclared read fails BEFORE any dependency exists → an undeclared change invalidates nothing.
    let mut deps2 = RecordedEnvDeps::new();
    assert!(env.get(&mut deps2, &n("UNDECLARED")).is_err());
    assert!(deps2.0.is_empty());

    // value-level change detection: unchanged ⇒ equal (cutoff); changed ⇒ different (invalidate).
    let same = EnvValue::Set(OsValue("1".into()));
    assert!(same.value_eq(&EnvValue::Set(OsValue("1".into()))));
    assert_ne!(same.content_digest(), EnvValue::Set(OsValue("9".into())).content_digest());
}

// ──────────────── REQ-PATHENV-005 — PATH comes from the declared env, never the host ────────────────

/// REQ-PATHENV-005: the spawn env is projected from the DECLARED snapshot only — an undeclared host
/// `PATH` never appears; a declared `PATH` carries the seam-captured value. (The action-identity side of
/// this law is pinned by razel-action's `host_absolute_path_not_in_action_identity` /
/// `effective_action_env_in_action_key`; the exact-env spawn law by razel-os-darwin's conformance.)
#[test]
fn path_comes_from_declared_env_not_host() {
    let host = FakeSystem::new().with_env("PATH", "/host/bin").with_env("CC", "clang");
    // PATH not declared ⇒ it does NOT exist in the spawn env, whatever the host says:
    let undeclared_path = ClientEnvSnapshot::capture(&host, &declared(&["CC"]));
    let spawn_env = undeclared_path.to_spawn_env();
    assert!(!spawn_env.contains_key(&n("PATH")), "host PATH must not leak into a spawn env");
    assert_eq!(spawn_env[&n("CC")], OsValue("clang".into()));
    // PATH declared ⇒ the value is the SEAM-captured one, entering by declaration:
    let declared_path = ClientEnvSnapshot::capture(&host, &declared(&["PATH"]));
    assert_eq!(declared_path.to_spawn_env()[&n("PATH")], OsValue("/host/bin".into()),
        "a DECLARED PATH rides the declared channel — visible, recorded, invalidating");
    // …and a declared-but-unset var is absent from the spawn env (exact env, no empty-string default):
    let unset = ClientEnvSnapshot::capture(&host, &declared(&["NOPE"]));
    assert!(unset.to_spawn_env().is_empty());
}

// ──────────────── REQ-PATHENV-006 — no second path vocabulary ────────────────

/// REQ-PATHENV-006: this contract performs NO path normalization — `OsValue` bytes pass through
/// verbatim (aliased spellings, separators, dot-segments are DATA here). Path semantics stay in
/// path-types / `OsPathPolicy`; a value that needs path comparison goes through that policy, not
/// through any env-side rewrite.
#[test]
fn env_contract_uses_path_types_policy() {
    for raw in ["/var/db/x", "/private/var/db/x", "C:\\Foo\\..\\Bar", "../rel/./path"] {
        let sys = FakeSystem::new().with_env("P", raw);
        let env = DeclaredClientEnv::from_system(&sys, &declared(&["P"]));
        let mut deps = RecordedEnvDeps::new();
        assert_eq!(env.get(&mut deps, &n("P")).expect("declared read"), EnvValue::Set(OsValue(raw.into())),
            "env values are OPAQUE bytes — no second normalization policy may rewrite them");
    }
}

// ──────────────── the pure node body — EnvVarNode ────────────────

/// `EnvVarNode::compute` (the engine binding's pure body): a declared key yields the snapshot value; an
/// undeclared key fails closed (REQ-PATHENV-002 at the node level, not just the ClientEnv level).
#[test]
fn envvar_node_compute_matches_snapshot_and_fails_closed() {
    let sys = FakeSystem::new().with_env("CC", "clang");
    let node = EnvVarNode::new(ClientEnvSnapshot::capture(&sys, &declared(&["CC", "OPT"])));
    assert_eq!(node.compute(&EnvVarKey { name: n("CC") }).expect("declared"), EnvValue::Set(OsValue("clang".into())));
    assert_eq!(node.compute(&EnvVarKey { name: n("OPT") }).expect("declared"), EnvValue::Unset);
    assert!(matches!(node.compute(&EnvVarKey { name: n("HOME") }), Err(Error::Invalid { .. })),
        "an undeclared EnvVarNode demand is a typed error, never a default value");
}
