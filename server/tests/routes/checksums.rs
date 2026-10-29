use crate::{app, send};
use axum::http::StatusCode;
use serde_json::json;

fn hex_hash() -> serde_json::Value {
    json!({
        "algorithm": "hash",
        "hash": "sha256",
        "bytes": 4,
        "encoding": "hex",
        "prefixLength": 5,
        "length": 8,
    })
}

#[tokio::test]
async fn an_example_value_is_checked_and_split_into_its_parts() {
    let app = app();
    // SHA-256("abc") starts ba7816bf.
    let (status, result) = send(
        &app,
        "POST",
        "/api/checksums/try",
        Some(json!({ "checksum": hex_hash(), "value": "acme_abcba7816bf" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result,
        json!({ "valid": true, "layout": { "coveredStart": 5, "checksumStart": 8 } })
    );

    let (_, result) = send(
        &app,
        "POST",
        "/api/checksums/try",
        Some(json!({ "checksum": hex_hash(), "value": "acme_abdba7816bf" })),
    )
    .await;
    assert_eq!(result["valid"], false);

    let (_, result) = send(
        &app,
        "POST",
        "/api/checksums/try",
        Some(json!({ "checksum": { "algorithm": "luhn" }, "value": "4111 1111 1111 1111" })),
    )
    .await;
    assert_eq!(result, json!({ "valid": true, "layout": null }));
}

#[tokio::test]
async fn a_setup_that_cant_run_is_explained() {
    let app = app();
    let mut too_short = hex_hash();
    too_short["length"] = json!(4);
    for checksum in [too_short, json!({ "algorithm": "made_up" })] {
        let (status, body) = send(
            &app,
            "POST",
            "/api/checksums/try",
            Some(json!({ "checksum": checksum, "value": "acme_abc" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
    }
}
