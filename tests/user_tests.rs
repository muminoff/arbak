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

async fn register_and_get_token(state: arbak::AppState) -> (String, uuid::Uuid, arbak::AppState) {
    let app = arbak::routes::create_router(state.clone());
    let unique_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let (_, body) = make_request(
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

    let token = body["access_token"].as_str().unwrap().to_string();

    // Get user ID from /me endpoint
    let app2 = arbak::routes::create_router(state.clone());
    let (_, me_body) = make_request(app2, "GET", "/api/auth/me", None, Some(&token)).await;
    let user_id = uuid::Uuid::parse_str(me_body["data"]["id"].as_str().unwrap()).unwrap();

    (token, user_id, state)
}

async fn register_admin_user(state: arbak::AppState) -> (String, uuid::Uuid, arbak::AppState) {
    let app = arbak::routes::create_router(state.clone());
    let unique_email = format!("admin_{}@example.com", uuid::Uuid::new_v4());
    let (_, body) = make_request(
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

    let token = body["access_token"].as_str().unwrap().to_string();

    // Get user ID from /me endpoint
    let app2 = arbak::routes::create_router(state.clone());
    let (_, me_body) = make_request(app2, "GET", "/api/auth/me", None, Some(&token)).await;
    let user_id = uuid::Uuid::parse_str(me_body["data"]["id"].as_str().unwrap()).unwrap();

    // Assign admin role directly in the database
    let admin_role = sqlx::query_as::<_, (uuid::Uuid,)>("SELECT id FROM roles WHERE name = 'admin'")
        .fetch_optional(&state.pool)
        .await
        .unwrap();

    if let Some((role_id,)) = admin_role {
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(user_id)
            .bind(role_id)
            .execute(&state.pool)
            .await
            .unwrap();
    }

    (token, user_id, state)
}

// ============================================================================
// User List Tests
// ============================================================================

#[tokio::test]
async fn test_list_users_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(app, "GET", "/api/users", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_users_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, _, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(app, "GET", "/api/users", None, Some(&token)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_list_users_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(app, "GET", "/api/users", None, Some(&admin_token)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    assert!(body["pagination"]["total_items"].is_number());
}

#[tokio::test]
async fn test_list_users_with_pagination() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/users?page=1&per_page=5",
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    assert_eq!(body["pagination"]["page"].as_i64().unwrap(), 1);
    assert_eq!(body["pagination"]["per_page"].as_i64().unwrap(), 5);
}

#[tokio::test]
async fn test_list_users_with_search() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/users?search=admin",
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_list_users_with_is_active_filter() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/users?is_active=true",
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    // All returned users should be active
    for user in body["data"].as_array().unwrap() {
        assert_eq!(user["is_active"].as_bool().unwrap(), true);
    }
}

// ============================================================================
// Get User Tests
// ============================================================================

#[tokio::test]
async fn test_get_user_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/users/{}", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_user_self_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        &format!("/api/users/{}", user_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"].as_str().unwrap(), user_id.to_string());
}

#[tokio::test]
async fn test_get_user_other_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register first user
    let (token1, _, state) = register_and_get_token(state).await;
    // Register second user
    let (_, user2_id, state) = register_and_get_token(state).await;

    // User 1 tries to view User 2's profile
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/users/{}", user2_id),
        None,
        Some(&token1),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_get_user_admin_can_view_any() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    // Admin views regular user
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        &format!("/api/users/{}", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"].as_str().unwrap(), user_id.to_string());
}

#[tokio::test]
async fn test_get_user_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/users/{}", fake_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================================
// Update User Tests
// ============================================================================

#[tokio::test]
async fn test_update_user_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", fake_id),
        Some(json!({ "email": "new@example.com" })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_update_user_self_email() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let new_email = format!("updated_{}@example.com", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "email": new_email })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"].as_str().unwrap(), new_email);
}

#[tokio::test]
async fn test_update_user_self_password() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "password": "newpassword123" })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_update_user_password_too_short() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "password": "short" })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_user_email_empty() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "email": "  " })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_user_email_already_taken() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register first user
    let (token1, user1_id, state) = register_and_get_token(state).await;

    // Register second user and get their email
    let (_, user2_id, state) = register_and_get_token(state).await;

    // Get user2's email
    let (admin_token, _, state) = register_admin_user(state).await;
    let app2 = arbak::routes::create_router(state.clone());
    let (_, user2_body) = make_request(
        app2,
        "GET",
        &format!("/api/users/{}", user2_id),
        None,
        Some(&admin_token),
    )
    .await;
    let user2_email = user2_body["data"]["email"].as_str().unwrap().to_string();

    // User1 tries to change email to user2's email
    let app3 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app3,
        "PUT",
        &format!("/api/users/{}", user1_id),
        Some(json!({ "email": user2_email })),
        Some(&token1),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_user_other_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register first user
    let (token1, _, state) = register_and_get_token(state).await;
    // Register second user
    let (_, user2_id, state) = register_and_get_token(state).await;

    // User 1 tries to update User 2
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user2_id),
        Some(json!({ "email": "hacked@example.com" })),
        Some(&token1),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_update_user_admin_can_update_any() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    let new_email = format!("admin_updated_{}@example.com", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "email": new_email })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"].as_str().unwrap(), new_email);
}

#[tokio::test]
async fn test_update_user_is_active_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    // Regular user tries to change their is_active status
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "is_active": false })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_update_user_admin_can_change_is_active() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "PUT",
        &format!("/api/users/{}", user_id),
        Some(json!({ "is_active": false })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["is_active"].as_bool().unwrap(), false);
}

// ============================================================================
// Activate/Deactivate User Tests
// ============================================================================

#[tokio::test]
async fn test_activate_user_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/activate", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_activate_user_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/activate", user_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_activate_user_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    // Deactivate user first
    let app = arbak::routes::create_router(state.clone());
    make_request(
        app,
        "POST",
        &format!("/api/users/{}/deactivate", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    // Now activate
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        &format!("/api/users/{}/activate", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["is_active"].as_bool().unwrap(), true);
}

#[tokio::test]
async fn test_deactivate_user_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/deactivate", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_deactivate_user_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/deactivate", user_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_deactivate_user_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/deactivate", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["is_active"].as_bool().unwrap(), false);
}

#[tokio::test]
async fn test_deactivate_user_cannot_deactivate_self() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, admin_id, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/deactivate", admin_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// Delete User Tests
// ============================================================================

#[tokio::test]
async fn test_delete_user_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_user_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}", user_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_delete_user_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);

    // Register admin
    let (admin_token, _, state) = register_admin_user(state).await;
    // Register regular user
    let (_, user_id, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"].as_str().unwrap(), "User deleted");

    // Verify user is deleted
    let app2 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app2,
        "GET",
        &format!("/api/users/{}", user_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_user_cannot_delete_self() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, admin_id, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}", admin_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}", fake_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}
