use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common {
    include!("../common/mod.rs");
}

use common::{create_test_state, setup_test_db};

async fn make_request(
    app: axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {}", t));
    }

    let body = body
        .map(|v| Body::from(serde_json::to_string(&v).unwrap()))
        .unwrap_or(Body::empty());

    let response = app.oneshot(req.body(body).unwrap()).await.unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or(json!({}));

    (status, json)
}

#[tokio::test]
async fn test_register_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let unique_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool.clone());
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("dup_{}@example.com", uuid::Uuid::new_v4());

    // First registration
    let (status, _) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second registration with same email
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("already registered"));
}

#[tokio::test]
async fn test_login_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("login_{}@example.com", uuid::Uuid::new_v4());

    // Register first
    make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    // Then login
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn test_login_wrong_password() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("wrongpw_{}@example.com", uuid::Uuid::new_v4());

    // Register
    make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    // Login with wrong password
    let app2 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app2,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "wrongpassword"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(app, "GET", "/api/auth/me", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_with_valid_token() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("me_{}@example.com", uuid::Uuid::new_v4());

    // Register
    let (_, body) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    let token = body["access_token"].as_str().unwrap();

    // Get /me
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(app2, "GET", "/api/auth/me", None, Some(token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"], unique_email);
}
