//! Reference `ClientEnv` mock (the paths-and-env row's mock artifact) + a recording `EnvDepSink`.
//! The conformance suite (`razel-os-api/tests/env_conformance.rs`) runs against THIS; the row's
//! red-first mutants live here (cargo features, never enabled in a real build).

use super::{ClientEnv, ClientEnvSnapshot, EnvDepSink, EnvValue, EnvVarKey};
use crate::{EnvName, System};
use razel_core::{Error, NodeKey};
use std::collections::BTreeSet;

/// Test-side `EnvDepSink`: records each read's node key, in read order.
#[derive(Default)]
pub struct RecordedEnvDeps(pub Vec<NodeKey>);
impl RecordedEnvDeps {
    pub fn new() -> Self { Self::default() }
}
impl EnvDepSink for RecordedEnvDeps {
    fn record_env_dep(&mut self, key: &EnvVarKey) {
        self.0.push(key.node_key());
    }
}

/// The reference `ClientEnv`: a declared snapshot, fail-closed reads, recorded dependencies.
pub struct DeclaredClientEnv {
    snapshot: ClientEnvSnapshot,
    declared_names: BTreeSet<EnvName>,
}
impl DeclaredClientEnv {
    pub fn new(snapshot: ClientEnvSnapshot) -> Self {
        let declared_names = snapshot.declared.keys().cloned().collect();
        Self { snapshot, declared_names }
    }
    /// Capture the declared set from the host through the `System` seam (the one ambient window).
    pub fn from_system(sys: &dyn System, declared: &BTreeSet<EnvName>) -> Self {
        Self::new(ClientEnvSnapshot::capture(sys, declared))
    }
    pub fn snapshot(&self) -> &ClientEnvSnapshot { &self.snapshot }
}
impl ClientEnv for DeclaredClientEnv {
    fn get(&self, deps: &mut dyn EnvDepSink, name: &EnvName) -> Result<EnvValue, Error> {
        match self.snapshot.declared.get(name) {
            Some(v) => {
                // MUTANT `mutant_env_read_not_recorded` (paths-and-env row red-first evidence): the read
                // succeeds but the dependency is NOT recorded — a later change to the var can no longer
                // invalidate its reader (the F2/F3 unrecorded-input hole). `env_read_records_envvar_node`
                // must go RED. Never enable in a real build.
                #[cfg(feature = "mutant_env_read_not_recorded")]
                let _ = &deps;
                #[cfg(not(feature = "mutant_env_read_not_recorded"))]
                deps.record_env_dep(&EnvVarKey { name: name.clone() });
                Ok(v.clone())
            }
            None => {
                // MUTANT `mutant_env_undeclared_as_unset` (paths-and-env row red-first evidence): an
                // UNDECLARED read absorbs to `Ok(Unset)` instead of a loud typed error — the silent
                // undeclared-env default REQ-PATHENV-002 forbids. `undeclared_env_read_fails_closed`
                // must go RED. Never enable in a real build.
                #[cfg(feature = "mutant_env_undeclared_as_unset")]
                return Ok(EnvValue::Unset);
                #[cfg(not(feature = "mutant_env_undeclared_as_unset"))]
                Err(Error::Invalid {
                    what: "undeclared env read (REQ-PATHENV-002)".into(),
                    detail: name.0.clone(),
                })
            }
        }
    }
    fn declared(&self) -> &BTreeSet<EnvName> { &self.declared_names }
}
