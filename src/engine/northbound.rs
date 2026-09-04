//! cfab's northbound: the ~300 lines of holod that turn a configuration tree into provider
//! commits and read operational state back, without gRPC, database, lock, or privdrop.
//! The loop is copied from holo-daemon/src/northbound/core.rs (Holo Core Contributors, MIT).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use holo_northbound::api::daemon::{CommitRequest, GetRequest, Request};
use holo_northbound::configuration::{
    CommitPhase, ConfigChange, Provider, ValidateFn, changes_from_diff, validate,
};
use holo_northbound::error::Error as NbError;
use holo_northbound::{NbDaemonSender, NbProviderReceiver};
use holo_protocol::InstanceShared;
use holo_utils::ibus;
use holo_utils::southbound::FibPolicy;
use holo_utils::yang::{ContextExt, SchemaNodeExt};
use holo_yang::YANG_CTX;
use holo_yang::implemented_modules::{BFD, INTERFACE, OSPF, ROUTING};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use yang5::context::Context;
use yang5::data::{
    Data, DataDiffFlags, DataFormat, DataParserFlags, DataPrinterFlags, DataTree,
    DataValidationFlags,
};

use crate::error::{Error, Result};

/// The process-global YANG context, built once from exactly the modules the two providers
/// implement (never holo's `ALL`: a module without a provider would be silently unowned).
pub fn yang_ctx() -> &'static Arc<Context> {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let mut ctx = holo_yang::new_context();
        let modules: Vec<&str> = [INTERFACE, ROUTING, OSPF, BFD].concat();
        holo_yang::load_modules(&mut ctx, &modules);
        ctx.cache_data_paths();
        // Set-if-unset: the engine binary sets it exactly once; a test process shares one.
        let _ = YANG_CTX.set(Arc::new(ctx));
    });
    YANG_CTX.get().expect("YANG_CTX set above")
}

/// Parse + validate a candidate configuration tree (leafrefs enforced, state excluded).
pub fn parse_candidate(tree: &Value) -> Result<DataTree<'static>> {
    let ctx = yang_ctx();
    let text = serde_json::to_string(tree).map_err(Error::fatal)?;
    DataTree::parse_string(
        ctx,
        text,
        DataFormat::JSON,
        DataParserFlags::empty(),
        DataValidationFlags::NO_STATE,
    )
    .map_err(|e| {
        Error::fatal(format!(
            "engine: configuration tree rejected: {}",
            yang_err(&e)
        ))
    })
}

fn yang_err(e: &yang5::Error) -> String {
    let mut s = e
        .msg
        .clone()
        .unwrap_or_else(|| format!("libyang error {}", e.errcode));
    if let Some(p) = &e.path {
        s.push_str(&format!(" (path {p})"));
    }
    s
}

/// The YANG paths and validation functions of one provider (holod's `register_provider`).
pub fn register_provider<P: Provider>(
    index: usize,
    registered_paths: &mut HashMap<String, usize>,
    validation_fns: &mut Vec<ValidateFn>,
) {
    for path in P::YANG_OPS_CONFIG.paths() {
        registered_paths.insert(path.to_owned(), index);
    }
    validation_fns.extend(P::validation_fns());
}

/// Map every configuration schema node to the provider owning its closest registered
/// ancestor (holod's `resolve_provider_paths`); nodes with no registered ancestor are absent.
pub fn resolve_provider_paths(
    ctx: &Context,
    registered_paths: &HashMap<String, usize>,
) -> HashMap<String, usize> {
    let mut provider_paths = HashMap::new();
    for snode in ctx.traverse().filter(|snode| snode.is_config()) {
        let path = snode.data_path();
        let mut ancestor = path.as_str();
        loop {
            if let Some(index) = registered_paths.get(ancestor) {
                provider_paths.insert(path.clone(), *index);
                break;
            }
            let Some(index) = ancestor.rfind('/') else {
                break;
            };
            ancestor = &ancestor[..index];
        }
    }
    provider_paths
}

/// The first change no started provider owns. holod drops such changes silently (spec §13
/// F7); cfab refuses the whole commit instead — it is how a holo-yang/provider feature
/// mismatch surfaces.
pub fn first_unmapped<'a>(
    changes: &'a [ConfigChange],
    provider_paths: &HashMap<String, usize>,
) -> Option<&'a str> {
    changes
        .iter()
        .find(|(key, _)| !provider_paths.contains_key(&key.path))
        .map(|(_, data_path)| data_path.as_str())
}

pub struct Northbound {
    running: Arc<DataTree<'static>>,
    providers: Vec<NbDaemonSender>,
    provider_paths: HashMap<String, usize>,
    validation_fns: Vec<ValidateFn>,
    pub rx_providers: NbProviderReceiver,
}

impl Northbound {
    /// Start holo-interface + holo-routing (which spawns the OSPF instances and the BFD
    /// instance itself). Must run inside the tokio runtime: the providers spawn tasks.
    pub fn start(hostname: &str, fib_policy: FibPolicy) -> Northbound {
        let ctx = yang_ctx();
        let running = Arc::new(DataTree::new(ctx));

        let (ibus_tx, ibus_rx) = ibus::ibus_channels();
        let (provider_tx, rx_providers) = mpsc::unbounded_channel();
        let shared = InstanceShared {
            db: None,
            hostname: Some(hostname.to_string()),
            fib_policy: Arc::new(fib_policy),
            ..Default::default()
        };

        let mut providers = Vec::new();
        let mut registered_paths = HashMap::new();
        let mut validation_fns = Vec::new();

        let daemon_tx = holo_interface::start(
            provider_tx.clone(),
            &ibus_tx,
            ibus_rx.interface,
            shared.clone(),
        );
        register_provider::<holo_interface::Master>(
            providers.len(),
            &mut registered_paths,
            &mut validation_fns,
        );
        providers.push(daemon_tx);

        let daemon_tx = holo_routing::start(provider_tx, &ibus_tx, ibus_rx.routing, shared);
        register_provider::<holo_routing::Master>(
            providers.len(),
            &mut registered_paths,
            &mut validation_fns,
        );
        providers.push(daemon_tx);

        let provider_paths = resolve_provider_paths(ctx, &registered_paths);
        Northbound {
            running,
            providers,
            provider_paths,
            validation_fns,
            rx_providers,
        }
    }

    /// Two-phase commit of a full candidate (holod's `create_transaction`): validate, diff
    /// against running, refuse unmapped changes, Prepare everywhere, then Apply — or Abort
    /// everywhere and fail.
    pub async fn commit(&mut self, candidate: DataTree<'static>) -> Result<()> {
        let candidate = Arc::new(candidate);
        validate(&self.validation_fns, &candidate).map_err(|e| {
            Error::fatal(format!(
                "engine: configuration validation failed: {}",
                nb_err(&e)
            ))
        })?;

        let diff = self
            .running
            .diff(&candidate, DataDiffFlags::DEFAULTS)
            .map_err(|e| Error::fatal(format!("engine: diff failed: {}", yang_err(&e))))?;
        if diff.iter().next().is_none() {
            return Ok(());
        }
        let changes = changes_from_diff(&diff);
        if let Some(path) = first_unmapped(&changes, &self.provider_paths) {
            return Err(Error::fatal(format!(
                "engine: no provider owns configuration path {path} (holo-yang module set and \
                 started providers disagree; refusing to drop it silently)"
            )));
        }

        match self
            .commit_phase_notify(CommitPhase::Prepare, &candidate, &changes)
            .await
        {
            Ok(()) => {
                self.commit_phase_notify(CommitPhase::Apply, &candidate, &changes)
                    .await?;
                self.running = candidate;
                Ok(())
            }
            Err(e) => {
                // Abort everywhere; the Prepare error is the one worth reporting.
                let _ = self
                    .commit_phase_notify(CommitPhase::Abort, &candidate, &changes)
                    .await;
                Err(e)
            }
        }
    }

    async fn commit_phase_notify(
        &mut self,
        phase: CommitPhase,
        candidate: &Arc<DataTree<'static>>,
        changes: &[ConfigChange],
    ) -> Result<()> {
        let mut batches = vec![Vec::new(); self.providers.len()];
        for (change_key, data_path) in changes {
            if let Some(index) = self.provider_paths.get(&change_key.path)
                && let Some(batch) = batches.get_mut(*index)
            {
                batch.push((change_key.clone(), data_path.clone()));
            }
        }
        for (daemon_tx, changes) in self.providers.iter().zip(batches) {
            let (responder_tx, responder_rx) = oneshot::channel();
            let request = Request::Commit(CommitRequest {
                phase,
                old_config: self.running.clone(),
                new_config: candidate.clone(),
                changes,
                responder: Some(responder_tx),
            });
            daemon_tx
                .send(request)
                .await
                .map_err(|_| Error::fatal("engine: a provider exited during commit"))?;
            responder_rx
                .await
                .map_err(|_| Error::fatal("engine: a provider dropped its commit response"))?
                .map_err(|e| {
                    Error::fatal(format!("engine: commit {phase:?} rejected: {}", nb_err(&e)))
                })?;
        }
        Ok(())
    }

    /// The providers' merged operational tree as libyang's JSON.
    pub async fn get_state(&self) -> Result<Value> {
        let ctx = yang_ctx();
        let mut dtree = DataTree::new(ctx);
        for daemon_tx in &self.providers {
            let (responder_tx, responder_rx) = oneshot::channel();
            let request = Request::Get(GetRequest {
                path: None,
                responder: Some(responder_tx),
            });
            daemon_tx
                .send(request)
                .await
                .map_err(|_| Error::fatal("engine: a provider exited"))?;
            let response = responder_rx
                .await
                .map_err(|_| Error::fatal("engine: a provider dropped its state response"))?
                .map_err(|e| Error::fatal(format!("engine: state read failed: {}", nb_err(&e))))?;
            dtree.merge(&response.data).map_err(|e| {
                Error::fatal(format!("engine: state merge failed: {}", yang_err(&e)))
            })?;
        }
        let text = dtree
            .print_string(DataFormat::JSON, DataPrinterFlags::WITH_SIBLINGS)
            .map_err(|e| Error::fatal(format!("engine: state print failed: {}", yang_err(&e))))?;
        if text.is_empty() {
            return Ok(Value::Object(Default::default()));
        }
        serde_json::from_str(&text).map_err(Error::fatal)
    }

    /// holod's teardown: drop the provider senders, then wait until every provider task has
    /// exited (holo-routing uninstalls its routes on that path).
    pub async fn shutdown(mut self) {
        self.providers.clear();
        while self.rx_providers.recv().await.is_some() {}
    }
}

/// holo's Display for its northbound error hides the path and detail; spell them out.
fn nb_err(e: &NbError) -> String {
    match e {
        NbError::Validate(v) => format!("{} at {}", v.message, v.path),
        NbError::Parse { path, error } => format!("cannot parse change at {path}: {error:?}"),
        NbError::Prepare { path, error } => format!("{} at {path}", error.message),
        NbError::RpcNotFound
        | NbError::RpcRelay(_)
        | NbError::RpcCallback(_)
        | NbError::RelayUnreachable
        | NbError::YangInvalidListKeys => format!("{e}"),
        NbError::YangInvalidPath(y) | NbError::YangInvalidData(y) => {
            format!("{e}: {}", yang_err(y))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RawConfig;
    use crate::derive::View;
    use crate::model::Fabric;
    use holo_northbound::configuration::{ChangeKey, ChangeOp};

    fn fabric() -> Fabric {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/fabric.conf"))
                .unwrap();
        Fabric::from_raw(&RawConfig::parse(&text).unwrap()).unwrap()
    }

    fn provider_paths() -> HashMap<String, usize> {
        let mut registered = HashMap::new();
        let mut fns = Vec::new();
        register_provider::<holo_interface::Master>(0, &mut registered, &mut fns);
        register_provider::<holo_routing::Master>(1, &mut registered, &mut fns);
        resolve_provider_paths(yang_ctx(), &registered)
    }

    #[test]
    fn yang_context_builds_and_is_shared() {
        let a = Arc::as_ptr(yang_ctx());
        let b = Arc::as_ptr(yang_ctx());
        assert_eq!(a, b);
        assert!(yang_ctx().get_module_latest("ietf-ospf").is_some());
        assert!(yang_ctx().get_module_latest("ietf-bfd-ip-sh").is_some());
        assert!(
            yang_ctx().get_module_latest("ietf-vrrp").is_none(),
            "vrrp is gate 3"
        );
    }

    #[test]
    fn generated_tree_parses_and_validates_no_state() {
        let f = fabric();
        for member in ["pve1-tb", "pve3-tb"] {
            let v = View::new(&f, member).unwrap();
            let tree = crate::emit::engine::generate(&v).unwrap();
            let dtree = parse_candidate(&tree).unwrap_or_else(|e| panic!("{member}: {e}"));
            assert!(dtree.traverse().count() > 10);
        }
    }

    /// F2: the OSPF interface leafrefs point at ietf-interfaces entries; without them the
    /// tree is invalid (which is why the emitter carries the bare interface list).
    #[test]
    fn tree_without_interfaces_fails_the_leafref() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let mut tree = crate::emit::engine::generate(&v).unwrap();
        tree.as_object_mut()
            .unwrap()
            .remove("ietf-interfaces:interfaces")
            .unwrap();
        let err = parse_candidate(&tree).unwrap_err().to_string();
        assert!(err.contains("leafref"), "{err}");
        assert!(err.contains("/if:interfaces/if:interface/if:name"), "{err}");
        assert!(err.contains("/interfaces/interface[name='cfab-"), "{err}");
    }

    #[test]
    fn provider_paths_cover_every_registered_path() {
        let paths = provider_paths();
        let mut n = 0;
        for (want, p) in [(0usize, holo_interface::Master::YANG_OPS_CONFIG.paths())]
            .into_iter()
            .flat_map(|(i, it)| it.map(move |p| (i, p)))
            .chain(
                holo_routing::Master::YANG_OPS_CONFIG
                    .paths()
                    .map(|p| (1usize, p)),
            )
        {
            assert_eq!(paths.get(p), Some(&want), "{p}");
            n += 1;
        }
        assert!(n > 50, "only {n} registered paths");
    }

    /// F7 in practice: every change cfab's own tree produces has an owner.
    #[test]
    fn generated_tree_has_no_unmapped_change() {
        let f = fabric();
        let v = View::new(&f, "pve1-tb").unwrap();
        let candidate = parse_candidate(&crate::emit::engine::generate(&v).unwrap()).unwrap();
        let running = DataTree::new(yang_ctx());
        let diff = running.diff(&candidate, DataDiffFlags::DEFAULTS).unwrap();
        let changes = changes_from_diff(&diff);
        assert!(changes.len() > 20, "{}", changes.len());
        assert_eq!(first_unmapped(&changes, &provider_paths()), None);
    }

    #[test]
    fn unmapped_change_is_named() {
        let mut paths = HashMap::new();
        paths.insert("/ietf-interfaces:interfaces/interface".to_string(), 0);
        let changes: Vec<ConfigChange> = vec![
            (
                ChangeKey::new(
                    "/ietf-interfaces:interfaces/interface".into(),
                    ChangeOp::Create,
                ),
                "/ietf-interfaces:interfaces/interface[name='cfab-st']".into(),
            ),
            (
                ChangeKey::new(
                    "/ietf-interfaces:interfaces/interface/description".into(),
                    ChangeOp::Create,
                ),
                "/ietf-interfaces:interfaces/interface[name='cfab-st']/description".into(),
            ),
        ];
        assert_eq!(
            first_unmapped(&changes, &paths),
            Some("/ietf-interfaces:interfaces/interface[name='cfab-st']/description")
        );
        assert_eq!(first_unmapped(&changes[..1], &paths), None);
    }
}
