use secrets_scanner_api::{ApiDoc, db, routes};
use std::net::{IpAddr, SocketAddr};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() {
    let database_path = db::default_path();
    if let Some(directory) = database_path.parent() {
        std::fs::create_dir_all(directory).expect("failed to create database directory");
    }
    let db = db::Db::open(&database_path).expect("failed to open database");
    db.seed().await.expect("failed to seed database");

    let app = routes::router(db)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
        .merge(SwaggerUi::new("/swagger-ui").url("/api/openapi.json", ApiDoc::openapi()));
    let port = std::env::var("API_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3001);
    let host = std::env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let address = SocketAddr::new(
        host.parse::<IpAddr>()
            .expect("API_HOST must be a valid IP address"),
        port,
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("failed to bind API listener");

    println!("Rust API listening at http://{address}");
    axum::serve(listener, app).await.expect("API server failed");
}
