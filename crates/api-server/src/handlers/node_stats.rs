//! Kubelet endpoints this platform serves NATIVELY, from storage.
//!
//! Upstream a kubelet serves these over HTTPS on :10250 and `nodes/proxy`
//! forwards to it. rusternetes has no kubelet HTTP server — `metrics_bind_port`
//! defaults to `None` — because its components share storage instead of calling
//! one another: the kubelet publishes and the api-server serves, which is
//! already how `metrics.k8s.io` works here. The contract a client sees is the
//! upstream one; how it is satisfied is this platform's business.
//!
//! **Why these live on their own routes rather than as a branch inside
//! `proxy_node`.** `proxy_node` says it forwards a request to the kubelet, and it
//! does. A special case hidden in it would make that documentation false for one
//! path, and the next person adding a kubelet endpoint would not know which
//! behaviour they were extending. With a route per natively-served endpoint, the
//! router IS the list: what is here is served from storage, and everything else
//! genuinely proxies — and fails honestly when there is nothing to proxy to.
//!
//! Only `/stats/summary` is implemented, because only its node filesystem
//! figures are read by anything here (`metrics.k8s.io` carries cpu and memory
//! but has no field for disk). `/metrics/cadvisor`, `/pods` and the rest remain
//! unimplemented and fall through to the proxy.

use crate::{middleware::AuthContext, state::ApiServerState};
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use rusternetes_common::{
    Result,
    authz::{Decision, RequestAttributes},
    resources::{NodeStatsSummary, node_stats_summary_key},
};
use rusternetes_storage::Storage;
use std::sync::Arc;

/// `GET /api/v1/nodes/{name}/proxy/stats/summary`
///
/// Authorized identically to the proxy it stands in for — `nodes/proxy`, not
/// `nodes` — so a client's existing grant works unchanged and no caller gains
/// access by this being served differently.
pub async fn get_node_stats_summary(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(node_name): Path<String>,
) -> Result<Json<NodeStatsSummary>> {
    let attrs = RequestAttributes::new(auth_ctx.user, "get", "nodes/proxy")
        .with_api_group("")
        .with_name(&node_name);
    if let Decision::Deny(reason) = state.authorizer.authorize(&attrs).await? {
        return Err(rusternetes_common::Error::Forbidden(reason));
    }

    // NotFound when the kubelet has not published yet — a node that exists but
    // has not reported is not an empty summary, and answering with zeros would
    // have a consumer render 0% disk for a filesystem nobody has looked at.
    let summary: NodeStatsSummary = state
        .storage
        .as_ref()
        .get(&node_stats_summary_key(&node_name))
        .await?;
    Ok(Json(summary))
}
