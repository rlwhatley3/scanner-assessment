use axum::{Json, Router, extract::Path, http::StatusCode, routing::get};
use std::{
    path::{Path as FilePath, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::fs;

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

pub fn router() -> Router {
    Router::new().route("/{name}", get(load).put(save))
}

async fn load(Path(name): Path<String>) -> Result<Json<serde_json::Value>, StatusCode> {
    let path = file_path(&name)?;
    let contents = fs::read(path).await.map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    })?;
    let document =
        serde_json::from_slice(&contents).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(document))
}

async fn save(
    Path(name): Path<String>,
    Json(document): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !is_valid_snapshot(&document) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = file_path(&name)?;
    let directory = path.parent().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::create_dir_all(directory)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let temporary_path = directory.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let contents =
        serde_json::to_vec_pretty(&document).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(&temporary_path, contents)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if fs::rename(&temporary_path, path).await.is_err() {
        let _ = fs::remove_file(temporary_path).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(serde_json::json!({ "name": name, "saved": true })))
}

fn file_path(name: &str) -> Result<PathBuf, StatusCode> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    FilePath::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|root| root.join("whiteboard").join(format!("{name}.tldraw.json")))
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn is_valid_snapshot(document: &serde_json::Value) -> bool {
    let Some(document) = document.get("document") else {
        return false;
    };
    document
        .get("store")
        .is_some_and(serde_json::Value::is_object)
        && document
            .get("schema")
            .is_some_and(serde_json::Value::is_object)
}
