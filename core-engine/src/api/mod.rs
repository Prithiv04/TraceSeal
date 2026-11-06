mod handlers;

use axum::{routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::storage::EvidenceStore;
use crate::api::handlers;

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
    pub fn with_options(
        store: EvidenceStore,
        max_concurrency: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            store: Arc::new(store),
            verifier_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrency)),
            verifier_timeout: timeout,
        }
    }
}

/// Create the Axum router.
/// Currently only the health endpoint is exposed, plus the evidence routes defined in `handlers`.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        // evidence endpoints are defined inside handlers module (imported in handlers.rs)
        .with_state(state)
}

/// Run the HTTP server, binding to the loopback interface by default.
///
/// The function blocks until the server is shut down via the provided
/// `shutdown_signal` future.
pub async fn run_server(
    bind_addr: Option<SocketAddr>,
    state: Arc<AppState>,
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
