use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::AuthUser,
    error::AppResult,
    models::CreateUser,
    repositories::UserRepository,
    services::{AuthResponse, AuthService, LoginRequest},
    AppState,
};

/// POST /api/auth/register
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

/// POST /api/auth/login
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

/// POST /api/auth/refresh (requires auth)
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

/// GET /api/auth/me (requires auth)
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
