use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::AuthUser,
    error::{AppResult, ErrorResponse},
    models::{CreateUser, UserWithRoles},
    repositories::UserRepository,
    services::{AuthResponse, AuthService, LoginRequest},
    AppState,
};

#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "auth",
    request_body = CreateUser,
    responses(
        (status = 200, description = "User registered successfully", body = AuthResponse),
        (status = 400, description = "Validation error", body = ErrorResponse)
    )
)]
async fn register(
    State(state): State<AppState>,
    Json(input): Json<CreateUser>,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::register(
        &state.pool,
        input,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse)
    )
)]
async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::login(
        &state.pool,
        input,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Token refreshed", body = AuthResponse),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse)
    )
)]
async fn refresh(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::refresh(
        &state.pool,
        claims.sub,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

/// Response wrapper for user data
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    pub data: UserWithRoles,
}

#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user info", body = UserResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse)
    )
)]
async fn me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let user = UserRepository::get_with_roles(&state.pool, claims.sub)
        .await?
        .ok_or(crate::error::AppError::NotFound)?;

    Ok(Json(serde_json::json!({ "data": user })))
}

/// Create auth routes - split into public and protected
pub fn auth_routes() -> (Router<AppState>, Router<AppState>) {
    let public = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    let protected = Router::new()
        .route("/refresh", post(refresh))
        .route("/me", get(me));

    (public, protected)
}
