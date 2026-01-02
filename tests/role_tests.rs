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

async fn register_and_get_token(state: arbak::AppState) -> (String, arbak::AppState) {
    let app = arbak::routes::create_router(state.clone());
    let unique_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let password = "password123";

    // Register the user
    let (status, _) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": unique_email,
            "password": password
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Registration failed");

    // Directly verify the email in the database
    sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
        .bind(&unique_email)
        .execute(&state.pool)
        .await
        .expect("Failed to verify email");

    // Login to get the token
    let app = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": unique_email,
            "password": password
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Login failed: {:?}", body);

    let token = body["access_token"].as_str().unwrap().to_string();
    (token, state)
}

async fn register_admin_user(state: arbak::AppState) -> (String, uuid::Uuid, arbak::AppState) {
    let app = arbak::routes::create_router(state.clone());
    let unique_email = format!("admin_{}@example.com", uuid::Uuid::new_v4());
    let password = "password123";

    // Register the user
    let (status, _) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": unique_email,
            "password": password
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Admin registration failed");

    // Directly verify the email in the database
    sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
        .bind(&unique_email)
        .execute(&state.pool)
        .await
        .expect("Failed to verify admin email");

    // Login to get the token
    let app = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": unique_email,
            "password": password
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Admin login failed: {:?}", body);

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
// Role List Tests
// ============================================================================

#[tokio::test]
async fn test_list_roles_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(app, "GET", "/api/roles", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_roles_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(app, "GET", "/api/roles", None, Some(&token)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    // Should have at least 'user' and 'admin' roles from seed data
    let roles = body["data"].as_array().unwrap();
    assert!(!roles.is_empty());
}

// ============================================================================
// Get Role Tests
// ============================================================================

#[tokio::test]
async fn test_get_role_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(app, "GET", &format!("/api/roles/{}", fake_id), None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_role_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/roles/{}", fake_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // First list roles to get a valid ID
    let app = arbak::routes::create_router(state.clone());
    let (_, body) = make_request(app, "GET", "/api/roles", None, Some(&token)).await;
    let roles = body["data"].as_array().unwrap();
    let role_id = roles[0]["id"].as_str().unwrap();

    // Now get the specific role
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "GET",
        &format!("/api/roles/{}", role_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["id"].is_string());
    assert!(body["data"]["name"].is_string());
}

// ============================================================================
// Create Role Tests
// ============================================================================

#[tokio::test]
async fn test_create_role_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": "test-role",
            "description": "A test role"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": "test-role",
            "description": "A test role"
        })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_create_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let unique_name = format!("test-role-{}", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "A test role"
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["name"], unique_name);
    assert_eq!(body["data"]["description"], "A test role");
}

#[tokio::test]
async fn test_create_role_duplicate_name() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let unique_name = format!("dup-role-{}", uuid::Uuid::new_v4());

    // Create first role
    let app = arbak::routes::create_router(state.clone());
    let (status, _) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "First role"
        })),
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Try to create duplicate
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Duplicate role"
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("already exists"));
}

#[tokio::test]
async fn test_create_role_empty_name() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": "   ",
            "description": "Empty name role"
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("cannot be empty"));
}

// ============================================================================
// Update Role Tests
// ============================================================================

#[tokio::test]
async fn test_update_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/roles/{}", fake_id),
        Some(json!({
            "name": "updated-role",
            "description": "Updated description"
        })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_update_role_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "PUT",
        &format!("/api/roles/{}", fake_id),
        Some(json!({
            "name": "updated-role",
            "description": "Updated description"
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Create a role first
    let unique_name = format!("update-role-{}", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state.clone());
    let (_, body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Original"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = body["data"]["id"].as_str().unwrap();

    // Update the role
    let updated_name = format!("updated-{}", uuid::Uuid::new_v4());
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "PUT",
        &format!("/api/roles/{}", role_id),
        Some(json!({
            "name": updated_name,
            "description": "Updated description"
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["name"], updated_name);
    assert_eq!(body["data"]["description"], "Updated description");
}

// ============================================================================
// Delete Role Tests
// ============================================================================

#[tokio::test]
async fn test_delete_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/roles/{}", fake_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_delete_role_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/roles/{}", fake_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Create a role first
    let unique_name = format!("delete-role-{}", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state.clone());
    let (_, body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "To be deleted"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = body["data"]["id"].as_str().unwrap();

    // Delete the role
    let app2 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app2,
        "DELETE",
        &format!("/api/roles/{}", role_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "Role deleted");

    // Verify it's gone
    let app3 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app3,
        "GET",
        &format!("/api/roles/{}", role_id),
        None,
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================================
// User Role Assignment Tests
// ============================================================================

#[tokio::test]
async fn test_get_user_roles_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/users/{}/roles", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_user_roles_user_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/users/{}/roles", fake_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_roles_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Get own user ID
    let app = arbak::routes::create_router(state.clone());
    let (_, me_body) = make_request(app, "GET", "/api/auth/me", None, Some(&token)).await;
    let user_id = me_body["data"]["id"].as_str().unwrap();

    // Get user roles
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "GET",
        &format!("/api/users/{}/roles", user_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["roles"].is_array());
    // New users should have the 'user' role
    let roles = body["data"]["roles"].as_array().unwrap();
    assert!(roles.iter().any(|r| r.as_str() == Some("user")));
}

#[tokio::test]
async fn test_assign_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_user_id = uuid::Uuid::new_v4();
    let fake_role_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/roles", fake_user_id),
        Some(json!({
            "role_id": fake_role_id.to_string()
        })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_assign_role_user_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Get a valid role ID
    let app = arbak::routes::create_router(state.clone());
    let (_, body) = make_request(app, "GET", "/api/roles", None, Some(&admin_token)).await;
    let role_id = body["data"][0]["id"].as_str().unwrap();

    let fake_user_id = uuid::Uuid::new_v4();
    let app2 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app2,
        "POST",
        &format!("/api/users/{}/roles", fake_user_id),
        Some(json!({
            "role_id": role_id
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_assign_role_role_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, admin_id, state) = register_admin_user(state).await;

    let fake_role_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/users/{}/roles", admin_id),
        Some(json!({
            "role_id": fake_role_id.to_string()
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_assign_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Register a new user
    let (user_token, state) = register_and_get_token(state).await;
    let app = arbak::routes::create_router(state.clone());
    let (_, me_body) = make_request(app, "GET", "/api/auth/me", None, Some(&user_token)).await;
    let user_id = me_body["data"]["id"].as_str().unwrap();

    // Create a new role
    let unique_name = format!("assign-role-{}", uuid::Uuid::new_v4());
    let app2 = arbak::routes::create_router(state.clone());
    let (_, role_body) = make_request(
        app2,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Role to assign"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = role_body["data"]["id"].as_str().unwrap();

    // Assign the role
    let app3 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app3,
        "POST",
        &format!("/api/users/{}/roles", user_id),
        Some(json!({
            "role_id": role_id
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "Role assigned successfully");

    // Verify the role was assigned
    let app4 = arbak::routes::create_router(state);
    let (_, roles_body) = make_request(
        app4,
        "GET",
        &format!("/api/users/{}/roles", user_id),
        None,
        Some(&admin_token),
    )
    .await;
    let roles = roles_body["data"]["roles"].as_array().unwrap();
    assert!(roles.iter().any(|r| r.as_str() == Some(&unique_name)));
}

#[tokio::test]
async fn test_remove_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_user_id = uuid::Uuid::new_v4();
    let fake_role_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/users/{}/roles/{}", fake_user_id, fake_role_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_remove_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Register a new user
    let (user_token, state) = register_and_get_token(state).await;
    let app = arbak::routes::create_router(state.clone());
    let (_, me_body) = make_request(app, "GET", "/api/auth/me", None, Some(&user_token)).await;
    let user_id = me_body["data"]["id"].as_str().unwrap();

    // Create and assign a role
    let unique_name = format!("remove-role-{}", uuid::Uuid::new_v4());
    let app2 = arbak::routes::create_router(state.clone());
    let (_, role_body) = make_request(
        app2,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Role to remove"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = role_body["data"]["id"].as_str().unwrap();

    // Assign the role
    let app3 = arbak::routes::create_router(state.clone());
    make_request(
        app3,
        "POST",
        &format!("/api/users/{}/roles", user_id),
        Some(json!({
            "role_id": role_id
        })),
        Some(&admin_token),
    )
    .await;

    // Remove the role
    let app4 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app4,
        "DELETE",
        &format!("/api/users/{}/roles/{}", user_id, role_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "Role removed from user");

    // Verify the role was removed
    let app5 = arbak::routes::create_router(state);
    let (_, roles_body) = make_request(
        app5,
        "GET",
        &format!("/api/users/{}/roles", user_id),
        None,
        Some(&admin_token),
    )
    .await;
    let roles = roles_body["data"]["roles"].as_array().unwrap();
    assert!(!roles.iter().any(|r| r.as_str() == Some(&unique_name)));
}

// ============================================================================
// Permission Tests
// ============================================================================

#[tokio::test]
async fn test_list_permissions_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(app, "GET", "/api/permissions", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_permissions_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(app, "GET", "/api/permissions", None, Some(&token)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_get_role_permissions_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let fake_id = uuid::Uuid::new_v4();
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/roles/{}/permissions", fake_id),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_role_permissions_role_not_found() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "GET",
        &format!("/api/roles/{}/permissions", fake_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_role_permissions_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Get a valid role ID
    let app = arbak::routes::create_router(state.clone());
    let (_, body) = make_request(app, "GET", "/api/roles", None, Some(&token)).await;
    let role_id = body["data"][0]["id"].as_str().unwrap();

    // Get role permissions
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "GET",
        &format!("/api/roles/{}/permissions", role_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_add_permission_to_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_role_id = uuid::Uuid::new_v4();
    let fake_perm_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "POST",
        &format!("/api/roles/{}/permissions", fake_role_id),
        Some(json!({
            "permission_id": fake_perm_id.to_string()
        })),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_add_permission_to_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Create a new role
    let unique_name = format!("perm-role-{}", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state.clone());
    let (_, role_body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Role for permission test"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = role_body["data"]["id"].as_str().unwrap();

    // Get a permission ID
    let app2 = arbak::routes::create_router(state.clone());
    let (_, perm_body) = make_request(app2, "GET", "/api/permissions", None, Some(&admin_token)).await;
    let permissions = perm_body["data"].as_array().unwrap();

    // Skip if no permissions exist
    if permissions.is_empty() {
        return;
    }

    let perm_id = permissions[0]["id"].as_str().unwrap();

    // Add permission to role
    let app3 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app3,
        "POST",
        &format!("/api/roles/{}/permissions", role_id),
        Some(json!({
            "permission_id": perm_id
        })),
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());

    // Verify the permission was added
    let permissions = body["data"].as_array().unwrap();
    assert!(permissions.iter().any(|p| p["id"].as_str() == Some(perm_id)));
}

#[tokio::test]
async fn test_remove_permission_from_role_requires_admin() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    let fake_role_id = uuid::Uuid::new_v4();
    let fake_perm_id = uuid::Uuid::new_v4();
    let app = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app,
        "DELETE",
        &format!("/api/roles/{}/permissions/{}", fake_role_id, fake_perm_id),
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_remove_permission_from_role_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (admin_token, _, state) = register_admin_user(state).await;

    // Create a new role
    let unique_name = format!("remove-perm-role-{}", uuid::Uuid::new_v4());
    let app = arbak::routes::create_router(state.clone());
    let (_, role_body) = make_request(
        app,
        "POST",
        "/api/roles",
        Some(json!({
            "name": unique_name,
            "description": "Role for permission removal test"
        })),
        Some(&admin_token),
    )
    .await;
    let role_id = role_body["data"]["id"].as_str().unwrap();

    // Get a permission ID
    let app2 = arbak::routes::create_router(state.clone());
    let (_, perm_body) = make_request(app2, "GET", "/api/permissions", None, Some(&admin_token)).await;
    let permissions = perm_body["data"].as_array().unwrap();

    // Skip if no permissions exist
    if permissions.is_empty() {
        return;
    }

    let perm_id = permissions[0]["id"].as_str().unwrap();

    // Add permission first
    let app3 = arbak::routes::create_router(state.clone());
    make_request(
        app3,
        "POST",
        &format!("/api/roles/{}/permissions", role_id),
        Some(json!({
            "permission_id": perm_id
        })),
        Some(&admin_token),
    )
    .await;

    // Remove permission
    let app4 = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app4,
        "DELETE",
        &format!("/api/roles/{}/permissions/{}", role_id, perm_id),
        None,
        Some(&admin_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "Permission removed from role");

    // Verify permission was removed
    let app5 = arbak::routes::create_router(state);
    let (_, role_perms_body) = make_request(
        app5,
        "GET",
        &format!("/api/roles/{}/permissions", role_id),
        None,
        Some(&admin_token),
    )
    .await;
    let perms = role_perms_body["data"].as_array().unwrap();
    assert!(!perms.iter().any(|p| p["id"].as_str() == Some(perm_id)));
}
