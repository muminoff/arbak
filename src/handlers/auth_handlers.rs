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
    operation_id = "registerUser",
    summary = "Register a new user",
    description = "Creates a new user account with the provided email and password. \
                   Automatically assigns the default 'user' role and returns a JWT token for immediate API access. \
                   Password must be at least 8 characters.",
    request_body(
        description = "User registration credentials",
        content = CreateUser
    ),
    responses(
        (status = 201, description = "User created successfully. Returns JWT token valid for 15 minutes.", body = AuthResponse),
        (status = 400, description = "Invalid input: email format incorrect or password too short (min 8 characters)", body = ErrorResponse),
        (status = 409, description = "Email address is already registered", body = ErrorResponse)
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
    operation_id = "loginUser",
    summary = "Authenticate user",
    description = "Validates user credentials and returns a JWT token for API access. \
                   The token should be included in subsequent requests as 'Authorization: Bearer <token>'.",
    request_body(
        description = "User login credentials",
        content = LoginRequest
    ),
    responses(
        (status = 200, description = "Login successful. Returns JWT token valid for 15 minutes.", body = AuthResponse),
        (status = 401, description = "Invalid email or password, or user account is deactivated", body = ErrorResponse)
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
    operation_id = "refreshToken",
    summary = "Refresh access token",
    description = "Issues a new JWT token using a valid existing token. Use this to extend your session \
                   before the current token expires. The new token will have a fresh 15-minute validity period.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "New JWT token issued successfully", body = AuthResponse),
        (status = 401, description = "Current token is invalid, expired, or user account is deactivated", body = ErrorResponse)
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

/// Wrapper containing user profile data
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    /// User profile with assigned roles
    pub data: UserWithRoles,
}

#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "auth",
    operation_id = "getCurrentUser",
    summary = "Get current user profile",
    description = "Returns the profile of the currently authenticated user, including their assigned roles. \
                   Useful for displaying user info in the UI or checking permissions client-side.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User profile retrieved successfully", body = UserResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse)
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
