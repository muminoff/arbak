use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    auth::{hash_password, AuthUser},
    error::{AppError, AppResult, ErrorResponse},
    models::{CreateUser, UserWithRoles},
    repositories::{EmailVerificationRepository, PasswordResetRepository, UserRepository},
    services::{AuthResponse, AuthService, LoginRequest, RegisterResponse},
    AppState,
};

#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "auth",
    operation_id = "registerUser",
    summary = "Register a new user",
    description = "Creates a new user account with the provided email and password. \
                   A verification email will be sent (logged to console in development). \
                   User must verify their email before they can login. \
                   Password must be at least 8 characters.",
    request_body(
        description = "User registration credentials",
        content = CreateUser
    ),
    responses(
        (status = 200, description = "Registration successful. Verification email sent.", body = RegisterResponse),
        (status = 400, description = "Invalid input: email format incorrect or password too short (min 8 characters)", body = ErrorResponse),
        (status = 409, description = "Email address is already registered", body = ErrorResponse)
    )
)]
async fn register(
    State(state): State<AppState>,
    Json(input): Json<CreateUser>,
) -> AppResult<Json<RegisterResponse>> {
    let response = AuthService::register(&state.pool, input).await?;
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    operation_id = "loginUser",
    summary = "Authenticate user",
    description = "Validates user credentials and returns a JWT token for API access. \
                   The token should be included in subsequent requests as 'Authorization: Bearer <token>'. \
                   User must have verified their email before logging in.",
    request_body(
        description = "User login credentials",
        content = LoginRequest
    ),
    responses(
        (status = 200, description = "Login successful. Returns JWT token valid for 15 minutes.", body = AuthResponse),
        (status = 400, description = "Email not verified", body = ErrorResponse),
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

// ============================================================================
// Email Verification
// ============================================================================

/// Request body for email verification
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    /// The verification token received via email
    #[schema(example = "abc123def456...")]
    pub token: String,
}

/// Request body for resending verification email
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResendVerificationRequest {
    /// Email address to resend verification to
    #[schema(example = "user@example.com", format = "email")]
    pub email: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/verify-email",
    tag = "auth",
    operation_id = "verifyEmail",
    summary = "Verify email address",
    description = "Verifies the user's email address using the token sent during registration. \
                   After successful verification, the user can login.",
    request_body(
        description = "Email verification token",
        content = VerifyEmailRequest
    ),
    responses(
        (status = 200, description = "Email verified successfully", body = MessageResponse),
        (status = 400, description = "Invalid or expired verification token", body = ErrorResponse)
    )
)]
async fn verify_email(
    State(state): State<AppState>,
    Json(input): Json<VerifyEmailRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Find valid token
    let user_id = EmailVerificationRepository::find_valid_token(&state.pool, &input.token)
        .await?
        .ok_or_else(|| AppError::Validation("Invalid or expired verification token".to_string()))?;

    // Mark email as verified
    UserRepository::set_email_verified(&state.pool, user_id, true).await?;

    // Invalidate all verification tokens for this user
    EmailVerificationRepository::invalidate_user_tokens(&state.pool, user_id).await?;

    tracing::info!("Email verified for user {}", user_id);

    Ok(Json(MessageResponse {
        message: "Email verified successfully. You can now login.".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/resend-verification",
    tag = "auth",
    operation_id = "resendVerification",
    summary = "Resend verification email",
    description = "Resends the verification email to the specified address. \
                   For security reasons, always returns success even if email is not registered. \
                   The new token expires after 24 hours.",
    request_body(
        description = "Email address to resend verification to",
        content = ResendVerificationRequest
    ),
    responses(
        (status = 200, description = "Verification email sent (check console in development)", body = MessageResponse),
        (status = 400, description = "Email already verified", body = ErrorResponse)
    )
)]
async fn resend_verification(
    State(state): State<AppState>,
    Json(input): Json<ResendVerificationRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Always return success to prevent email enumeration
    let response = MessageResponse {
        message: "If the email exists and is not verified, a verification link has been sent"
            .to_string(),
    };

    // Check if user exists
    let user = UserRepository::find_by_email(&state.pool, &input.email).await?;

    if let Some(user) = user {
        // Check if already verified
        if user.email_verified {
            return Err(AppError::Validation("Email is already verified".to_string()));
        }

        // Generate new verification token
        let token = EmailVerificationRepository::create_token(&state.pool, user.id).await?;

        // Log the verification link (in production, this would send an email)
        let verification_link = format!("http://localhost:3000/verify-email?token={}", token);
        tracing::info!(
            "Email verification resent for {}: {}",
            input.email,
            verification_link
        );
    }

    Ok(Json(response))
}

// ============================================================================
// Password Reset
// ============================================================================

/// Request body for forgot password
#[derive(Debug, Deserialize, ToSchema)]
pub struct ForgotPasswordRequest {
    /// Email address of the account to reset
    #[schema(example = "user@example.com", format = "email")]
    pub email: String,
}

/// Request body for password reset
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    /// The reset token received via email
    #[schema(example = "abc123def456...")]
    pub token: String,
    /// New password (must be at least 8 characters)
    #[schema(example = "newsecurepassword123", min_length = 8)]
    pub password: String,
}

/// Generic success response
#[derive(serde::Serialize, ToSchema)]
pub struct MessageResponse {
    /// Success message
    #[schema(example = "Password reset email sent")]
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/forgot-password",
    tag = "auth",
    operation_id = "forgotPassword",
    summary = "Request password reset",
    description = "Initiates a password reset by sending a reset link to the provided email address. \
                   For security reasons, this endpoint always returns success even if the email is not registered. \
                   The reset token expires after 1 hour.",
    request_body(
        description = "Email address for password reset",
        content = ForgotPasswordRequest
    ),
    responses(
        (status = 200, description = "Password reset initiated (check console for reset link in development)", body = MessageResponse),
        (status = 400, description = "Invalid email format", body = ErrorResponse)
    )
)]
async fn forgot_password(
    State(state): State<AppState>,
    Json(input): Json<ForgotPasswordRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Always return success to prevent email enumeration
    let response = MessageResponse {
        message: "If the email exists, a password reset link has been sent".to_string(),
    };

    // Check if user exists
    let user = UserRepository::find_by_email(&state.pool, &input.email).await?;

    if let Some(user) = user {
        // Generate reset token
        let token = PasswordResetRepository::create_token(&state.pool, user.id).await?;

        // Log the reset link (in production, this would send an email)
        let reset_link = format!(
            "http://localhost:3000/reset-password?token={}",
            token
        );
        tracing::info!(
            "Password reset requested for {}: {}",
            input.email,
            reset_link
        );
    }

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/api/auth/reset-password",
    tag = "auth",
    operation_id = "resetPassword",
    summary = "Reset password with token",
    description = "Resets the user's password using a valid reset token. The token must not be expired or already used. \
                   After successful reset, all existing reset tokens for this user are invalidated.",
    request_body(
        description = "Reset token and new password",
        content = ResetPasswordRequest
    ),
    responses(
        (status = 200, description = "Password reset successfully", body = MessageResponse),
        (status = 400, description = "Invalid or expired token, or password too short", body = ErrorResponse)
    )
)]
async fn reset_password(
    State(state): State<AppState>,
    Json(input): Json<ResetPasswordRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Validate password length
    if input.password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Find valid token
    let user_id = PasswordResetRepository::find_valid_token(&state.pool, &input.token)
        .await?
        .ok_or_else(|| AppError::Validation("Invalid or expired reset token".to_string()))?;

    // Hash the new password
    let password_hash = hash_password(&input.password)?;

    // Update the password
    UserRepository::update_password(&state.pool, user_id, &password_hash).await?;

    // Invalidate all reset tokens for this user
    PasswordResetRepository::invalidate_user_tokens(&state.pool, user_id).await?;

    tracing::info!("Password reset successful for user {}", user_id);

    Ok(Json(MessageResponse {
        message: "Password has been reset successfully".to_string(),
    }))
}

/// Create auth routes - split into public and protected
pub fn auth_routes() -> (Router<AppState>, Router<AppState>) {
    let public = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email", post(verify_email))
        .route("/resend-verification", post(resend_verification))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password));

    let protected = Router::new()
        .route("/refresh", post(refresh))
        .route("/me", get(me));

    (public, protected)
}
