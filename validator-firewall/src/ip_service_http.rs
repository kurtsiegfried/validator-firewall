use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cidr::Ipv4Cidr;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::auth::AddAuthorizationLayer;
use tracing::{debug, info, warn};

pub struct IPState {
    pub http_nodes: Arc<RwLock<HashSet<Ipv4Cidr>>>,
    pub blocked_nodes: Arc<RwLock<HashSet<Ipv4Cidr>>>,
}

impl IPState {
    pub fn new() -> Self {
        IPState {
            http_nodes: Arc::new(RwLock::new(HashSet::new())),
            blocked_nodes: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn add_http_node(&self, node: Ipv4Cidr) {
        self.http_nodes.write().await.insert(node);
    }

    pub async fn add_blocked_node(&self, node: Ipv4Cidr) {
        self.blocked_nodes.write().await.insert(node);
    }

    pub async fn remove_blocked_node(&self, node: Ipv4Cidr) {
        self.blocked_nodes.write().await.remove(&node);
    }

    pub async fn remove_http_node(&self, node: Ipv4Cidr) {
        self.http_nodes.write().await.remove(&node);
    }

    pub async fn get_combined_nodes(&self) -> HashSet<Ipv4Cidr> {
        let mut combined_nodes = HashSet::new();
        combined_nodes.extend(self.blocked_nodes.read().await.iter());
        let allow_listed = self.http_nodes.read().await;
        combined_nodes.retain(|node| !allow_listed.contains(node));

        combined_nodes
    }
}

/// Returns a redacted form of `token` showing only the first 4 chars.
/// Tokens shorter than 4 chars are fully redacted to avoid leaking them.
fn mask_token(token: &str) -> String {
    const VISIBLE: usize = 4;
    if token.chars().count() <= VISIBLE {
        "****".to_string()
    } else {
        let prefix: String = token.chars().take(VISIBLE).collect();
        format!("{prefix}****")
    }
}

pub fn create_router(state: Arc<IPState>, token: Option<String>) -> Router {
    async fn get_deny_list(state: State<Arc<IPState>>) -> impl IntoResponse {
        let nodes = state.get_combined_nodes().await;
        let nodes: Vec<String> = nodes.iter().map(|node| node.to_string()).collect();
        let body = serde_json::to_string(&nodes).unwrap();
        (StatusCode::OK, body)
    }

    async fn get_http_nodes(state: State<Arc<IPState>>) -> impl IntoResponse {
        let nodes = state.http_nodes.read().await;
        let nodes: Vec<String> = nodes.iter().map(|node| node.to_string()).collect();
        let body = serde_json::to_string(&nodes).unwrap();
        (StatusCode::OK, body)
    }

    async fn add_http_node(
        state: State<Arc<IPState>>,
        Json(payload): Json<Ipv4Cidr>,
    ) -> impl IntoResponse {
        debug!("add_http_node: {:?}", payload);
        state.add_http_node(payload).await;
        (StatusCode::CREATED, payload.to_string())
    }

    async fn get_blocked_nodes(state: State<Arc<IPState>>) -> impl IntoResponse {
        let nodes = state.blocked_nodes.read().await;
        let nodes: Vec<String> = nodes.iter().map(|node| node.to_string()).collect();
        let body = serde_json::to_string(&nodes).unwrap();
        (StatusCode::OK, body)
    }

    async fn add_blocked_node(
        state: State<Arc<IPState>>,
        Json(payload): Json<Ipv4Cidr>,
    ) -> impl IntoResponse {
        debug!("add_blocked_node: {:?}", payload);
        state.add_blocked_node(payload).await;
        (StatusCode::CREATED, payload.to_string())
    }

    async fn remove_blocked_node(
        state: State<Arc<IPState>>,
        Json(payload): Json<Ipv4Cidr>,
    ) -> impl IntoResponse {
        debug!("remove_blocked_node: {:?}", payload);
        state.remove_blocked_node(payload).await;
        (StatusCode::OK, payload.to_string())
    }

    async fn remove_http_node(
        state: State<Arc<IPState>>,
        Json(payload): Json<Ipv4Cidr>,
    ) -> impl IntoResponse {
        debug!("remove_http_node: {:?}", payload);
        state.remove_http_node(payload).await;
        (StatusCode::OK, payload.to_string())
    }

    let app = Router::new()
        .route("/", get(get_deny_list))
        .route("/nodes", get(get_deny_list))
        .with_state(state.clone());
    if let Some(token) = token {
        info!(
            "Adding authentication layer with token: {}",
            mask_token(&token)
        );
        Router::new()
            .route(
                "/allowed",
                post(add_http_node)
                    .delete(remove_http_node)
                    .get(get_http_nodes),
            )
            .route(
                "/blocked",
                post(add_blocked_node)
                    .delete(remove_blocked_node)
                    .get(get_blocked_nodes),
            )
            .route_layer(AddAuthorizationLayer::bearer(&token))
            .with_state(state.clone())
            .merge(app)
    } else {
        warn!("No authentication configured for write layer.");
        Router::new()
            .route(
                "/allowed",
                post(add_http_node)
                    .delete(remove_http_node)
                    .get(get_http_nodes),
            )
            .route(
                "/blocked",
                post(add_blocked_node)
                    .delete(remove_blocked_node)
                    .get(get_blocked_nodes),
            )
            .with_state(state.clone())
            .merge(app)
    }
}

#[cfg(test)]
mod tests {
    use super::mask_token;

    #[test]
    fn masks_long_tokens_to_first_four_chars() {
        assert_eq!(mask_token("abcdefghij"), "abcd****");
    }

    #[test]
    fn fully_redacts_short_tokens() {
        assert_eq!(mask_token("abcd"), "****");
        assert_eq!(mask_token(""), "****");
    }

    #[test]
    fn handles_multibyte_chars_safely() {
        // 4 chars (8 bytes) — borderline, should fully redact rather than slice mid-codepoint.
        assert_eq!(mask_token("héllo"), "héll****");
    }
}
