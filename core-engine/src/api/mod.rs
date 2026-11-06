// src/api/mod.rs
//! HTTP API foundation for TRACESEAL.
//! Provides application state, router construction, and health endpoint.

use axum::{
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::storage::EvidenceStore;

/// Shared application state for the API.
#[derive(Clone)]
pub struct AppState {
    /// Evidence store used by the API.
    pub store: Arc<EvidenceStore>,
}

impl AppState {
    pub fn new(store: EvidenceStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }
}

/// Create the Axum router.
/// Currently only the health endpoint is exposed.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .with_state(state)
}

/// Health check handler – returns a static JSON payload.
async fn health_handler() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// Health response schema.
#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Run the HTTP server, binding to the loopback interface by default.
///
/// The function blocks until the server is shut down via the provided
/// `shutdown_signal` future.
pub async fn run_server(
    bind_addr: Option<SocketAddr>,
    state: AppState,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    // Default to 127.0.0.1:3000 if not supplied.
    let addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 3000)));

    // Enforce loopback unless caller explicitly opts‑in via `--allow-external` in CLI.
    if !addr.ip().is_loopback() {
        // The CLI already guards against this, but we keep a defensive warning.
        eprintln!(
            "[WARNING] Binding HTTP server to non‑loopback address {} – ensure this is intentional.",
            addr
        );
    }

    let app = create_router(state);

    // Use TcpListener + axum::serve as recommended for Axum 0.8.
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
}

    bind_addr: Option<SocketAddr>,
    state: AppState,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    // Default to 127.0.0.1:3000 if not supplied.
    let addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 3000)));

    // Warn if a non‑loopback address is used – the caller may have overridden.
    if !addr.ip().is_loopback() {
        eprintln!(
            "[WARNING] Binding HTTP server to non‑loopback address {} – this may expose the API externally.",
            addr
        );
    }

    let app = create_router(state);

    // Axum's `serve` will handle graceful shutdown when the signal completes.
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal)
        .await
}
