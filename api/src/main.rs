mod handlers;
mod middleware;
mod config;
mod scanner;

use axum::{
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;

use crate::config::Config;
use nabla_core::DbPool;
use nabla_auth::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub auth_service: AuthService,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nabla_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;

    nabla_core::database::create_tables(&db).await?;

    let auth_service = AuthService::new(db.clone());

    let state = AppState {
        db,
        auth_service,
        config: config.clone(),
    };

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/webhooks/github", post(handlers::github_webhook))
        .route("/webhooks/stripe", post(handlers::stripe_webhook))
        .route("/metrics", get(handlers::metrics))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}