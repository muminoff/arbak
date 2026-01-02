use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common {
    include!("common/mod.rs");
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

// ============================================================================
// Password Reset Tests
// ============================================================================

#[tokio::test]
async fn test_forgot_password_always_returns_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    // Request reset for non-existent email
    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/forgot-password",
        Some(json!({ "email": "nonexistent@example.com" })),
        None,
    )
    .await;

    // Should always return success (prevents email enumeration)
    assert_eq!(status, StatusCode::OK);
    assert!(body["message"].as_str().unwrap().contains("password reset link"));
}

#[tokio::test]
async fn test_forgot_password_for_existing_user() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("reset_{}@example.com", uuid::Uuid::new_v4());

    // Register a user
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

    // Request password reset
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/forgot-password",
        Some(json!({ "email": &unique_email })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["message"].as_str().unwrap().contains("password reset link"));
}

#[tokio::test]
async fn test_reset_password_invalid_token() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/reset-password",
        Some(json!({
            "token": "invalid_token_12345",
            "password": "newpassword123"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("Invalid or expired"));
}

#[tokio::test]
async fn test_reset_password_short_password() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/reset-password",
        Some(json!({
            "token": "some_token",
            "password": "short"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("at least 8 characters"));
}

#[tokio::test]
async fn test_reset_password_full_flow() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool.clone());
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("fullreset_{}@example.com", uuid::Uuid::new_v4());

    // 1. Register a user
    make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "oldpassword123"
        })),
        None,
    )
    .await;

    // 2. Get user ID from database
    let user = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM users WHERE email = $1"
    )
    .bind(&unique_email)
    .fetch_one(&pool)
    .await
    .unwrap();

    // 3. Create a reset token directly in database for testing
    let token = arbak::repositories::PasswordResetRepository::create_token(&pool, user.0)
        .await
        .unwrap();

    // 4. Reset password with the token
    let app2 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/reset-password",
        Some(json!({
            "token": &token,
            "password": "newpassword456"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["message"].as_str().unwrap().contains("successfully"));

    // 5. Verify old password no longer works
    let app3 = arbak::routes::create_router(state.clone());
    let (status, _) = make_request(
        app3,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "oldpassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 6. Verify new password works
    let app4 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app4,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "newpassword456"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_reset_password_token_cannot_be_reused() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool.clone());
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("reuse_{}@example.com", uuid::Uuid::new_v4());

    // Register a user
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

    // Get user ID
    let user = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM users WHERE email = $1"
    )
    .bind(&unique_email)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create a reset token
    let token = arbak::repositories::PasswordResetRepository::create_token(&pool, user.0)
        .await
        .unwrap();

    // First reset should succeed
    let app2 = arbak::routes::create_router(state.clone());
    let (status, _) = make_request(
        app2,
        "POST",
        "/api/auth/reset-password",
        Some(json!({
            "token": &token,
            "password": "newpassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second reset with same token should fail
    let app3 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app3,
        "POST",
        "/api/auth/reset-password",
        Some(json!({
            "token": &token,
            "password": "anotherpassword123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("Invalid or expired"));
}
