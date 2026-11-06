mod error;
mod handlers;
mod models;

pub use error::ApiError;
pub use models::*;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::storage::EvidenceStore;

/// Shared application state for the API.
#[derive(Clone)]
pub struct AppState {
    /// Evidence store used by the API.
    pub store: Arc<EvidenceStore>,
    /// Semaphore limiting concurrent verifier runs.
    pub verifier_semaphore: Arc<tokio::sync::Semaphore>,
    /// Timeout for verifier subprocesses.
    pub verifier_timeout: Duration,
}

impl AppState {
    /// Construct a minimal AppState with default concurrency (1) and no timeout.
    pub fn new(store: EvidenceStore) -> Self {
        Self {
            store: Arc::new(store),
            verifier_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            verifier_timeout: Duration::from_secs(30),
        }
    }

    /// Construct an AppState with configurable concurrency and timeout.
    pub fn with_options(store: EvidenceStore, max_concurrency: usize, timeout: Duration) -> Self {
        Self {
            store: Arc::new(store),
            verifier_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrency)),
            verifier_timeout: timeout,
        }
    }
}

/// Create the Axum router with all API routes registered.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(frontend))
        .route("/app", get(frontend))
        .route("/health", get(handlers::health))
        .route("/api/v1/evidence", post(handlers::submit_evidence))
        .route(
            "/api/v1/evidence/{evidence_id}",
            get(handlers::get_evidence_metadata),
        )
        .route(
            "/api/v1/evidence/{evidence_id}/artifacts/{artifact_type}",
            get(handlers::get_artifact),
        )
        .route(
            "/api/v1/evidence/{evidence_id}/verifications",
            get(handlers::get_verification_history),
        )
        .route(
            "/api/v1/evidence/{evidence_id}/reverify",
            post(handlers::reverify_evidence),
        )
        .with_state(state)
}

/// Run the HTTP server, binding to the loopback interface by default.
///
/// The function blocks until the server is shut down via the provided
/// `shutdown_signal` future.
pub async fn run_server(
    bind_addr: impl Into<SocketAddr>,
    state: Arc<AppState>,
) -> Result<(), std::io::Error> {
    let addr: SocketAddr = bind_addr.into();

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
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("install CTRL+C handler");
        })
        .await
}
