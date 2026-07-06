//! `razel-os-api::env` — environment as a graph input (dev-docs/contracts/paths-and-env.md).
//!
//! `ClientEnvSnapshot` + `EnvVarKey`/`EnvValue` make declared environment variables explicit graph
//! leaves: only DECLARED env reads are allowed (undeclared is a loud typed error, REQ-PATHENV-002), an
//! unset declared var is the explicit `EnvValue::Unset` (REQ-PATHENV-003), and every build-path read is
//! RECORDED as a dependency on the var's node key (REQ-PATHENV-001), so only a declared value change can
//! invalidate exactly its readers (REQ-PATHENV-004, via the frozen engine contract's recorded-dep law).
//! Ambient host env is visible ONLY through `System::raw_env` while constructing the snapshot — nothing
//! here (or above) names `std::env` (`tools/raw_os.py` makes that a CI failure, REQ-PATHENV-001's
//! `no_ambient_env_above_system` half).
//!
//! Wall note (why there is no `impl NodeFunction` in this file): the dependency wall keeps
//! `razel-os-api` BELOW the engine (`tools/seams.json`: this crate sees only `razel-core`), so the
//! engine-facing `NodeFunction` binding for the env leaf lands in the first engine-visible consumer
//! (razel-source's leaf family, like `FILE_STATE`). What lives HERE is everything the binding needs and
//! everything the contract owns: the canonical key (`EnvVarKey` is a real `razel_core::Key`), the leaf
//! value (`EnvValue` is a real `razel_core::Value`), the snapshot, the pure node body
//! (`EnvVarNode::compute`), and the recording read seam (`ClientEnv` over `EnvDepSink` — the narrow
//! slice of the engine's `DemandContext` this layer is allowed to see).
//!
//! This module deliberately defines NO path vocabulary and NO normalization: `OsValue` bytes pass
//! through verbatim; path semantics stay in path-types / `OsPathPolicy` (REQ-PATHENV-006).

use crate::{EnvMap, EnvName, OsValue, System};
use razel_core::{Digest, Error, Key, KindId, NodeKey, Value, ValuePolicy};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

pub mod mock;

/// The env-leaf node kind — L1 leaf band (10–19), next after razel-source's FILE_STATE..GLOB (10–13).
pub const ENV_VAR: KindId = KindId(14);

/// Typed key of one declared environment variable's leaf node.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EnvVarKey {
    pub name: EnvName,
}
impl Key for EnvVarKey {
    fn kind(&self) -> KindId { ENV_VAR }
    /// Canonical encoding: the raw env-name bytes (names are compared byte-exact; no case-fold, no trim).
    fn encode(&self) -> Vec<u8> { self.name.0.clone().into_bytes() }
}
impl EnvVarKey {
    pub fn node_key(&self) -> NodeKey { NodeKey::from_key(self) }
}

/// The leaf value: a declared var is either SET to bytes or explicitly UNSET. `Unset` is distinct from
/// `Set(OsValue(""))` and distinct from undeclared (which is an `Error`, not a value) — REQ-PATHENV-003.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EnvValue {
    Set(OsValue),
    Unset,
}
impl EnvValue {
    /// Canonical bytes (tag + payload) — deterministic, so the content digest is stable.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            EnvValue::Unset => vec![0u8],
            EnvValue::Set(v) => {
                let mut b = Vec::with_capacity(1 + v.0.len());
                b.push(1u8);
                b.extend_from_slice(v.0.as_bytes());
                b
            }
        }
    }
}
impl Value for EnvValue {
    fn policy(&self) -> ValuePolicy {
        ValuePolicy { comparable: true, always_dirty: false, shareable: true, serializable: true, process_local: false }
    }
    fn value_eq(&self, other: &dyn Value) -> bool {
        other.as_any().downcast_ref::<EnvValue>().is_some_and(|o| o == self)
    }
    fn content_digest(&self) -> Digest { Digest::of(&self.canonical_bytes()) }
    fn as_any(&self) -> &dyn Any { self }
}

/// The declared env snapshot: the ONE place ambient host env is observed, and only via
/// `System::raw_env` (never `std::env` — the raw-OS wall). Everything on the build path reads THIS.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClientEnvSnapshot {
    pub declared: BTreeMap<EnvName, EnvValue>,
}
impl ClientEnvSnapshot {
    /// Capture the declared names from the host through the `System` seam. A var the host lacks is the
    /// EXPLICIT `Unset` (REQ-PATHENV-003) — never silently dropped, never defaulted to `""`.
    pub fn capture(sys: &dyn System, declared: &BTreeSet<EnvName>) -> ClientEnvSnapshot {
        let mut map = BTreeMap::new();
        for name in declared {
            let v = match sys.raw_env(name) {
                Some(v) => EnvValue::Set(v),
                None => EnvValue::Unset,
            };
            map.insert(name.clone(), v);
        }
        ClientEnvSnapshot { declared: map }
    }
    /// Project the snapshot into an EXACT spawn env (`ProcessSpec.env` is never merged with the host
    /// environment): only declared-and-SET vars appear — `PATH` comes from here or not at all
    /// (REQ-PATHENV-005, REQ-SYSTEM-009).
    pub fn to_spawn_env(&self) -> EnvMap {
        self.declared
            .iter()
            .filter_map(|(k, v)| match v {
                EnvValue::Set(val) => Some((k.clone(), val.clone())),
                EnvValue::Unset => None,
            })
            .collect()
    }
}

/// The dependency-recording capability a `ClientEnv::get` needs — the narrow slice of the engine's
/// `DemandContext` visible below the wall. The engine adapter implements this by demanding
/// `EnvVarKey::node_key()`; tests implement it by recording.
pub trait EnvDepSink {
    fn record_env_dep(&mut self, key: &EnvVarKey);
}

/// Read a declared env var as a RECORDED dependency (REQ-PATHENV-001). Reading an undeclared name is a
/// loud typed `Error` — never empty, never `Unset`, never a default (REQ-PATHENV-002).
pub trait ClientEnv {
    fn get(&self, deps: &mut dyn EnvDepSink, name: &EnvName) -> Result<EnvValue, Error>;
    fn declared(&self) -> &BTreeSet<EnvName>;
}

/// The env leaf's pure node body: `EnvVarNode(key)` yields the snapshot's value for a DECLARED name and
/// fails closed on an undeclared one. The `NodeFunction` wrapper (key decode + `ComputeResult`) binds in
/// the first engine-visible crate (see the module doc's wall note).
pub struct EnvVarNode {
    snapshot: ClientEnvSnapshot,
}
impl EnvVarNode {
    pub fn new(snapshot: ClientEnvSnapshot) -> Self { Self { snapshot } }
    pub fn compute(&self, key: &EnvVarKey) -> Result<EnvValue, Error> {
        self.snapshot.declared.get(&key.name).cloned().ok_or_else(|| Error::Invalid {
            what: "undeclared EnvVarNode demand (REQ-PATHENV-002)".into(),
            detail: key.name.0.clone(),
        })
    }
}
