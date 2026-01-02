use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::{encode_token, hash_password, verify_password, Claims},
    error::{AppError, AppResult},
    models::CreateUser,
    repositories::{RoleRepository, UserRepository},
};

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    #[schema(example = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")]
    pub access_token: String,
    #[schema(example = "Bearer")]
    pub token_type: String,
    #[schema(example = 900)]
    pub expires_in: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "securepassword123")]
    pub password: String,
}

pub struct AuthService;

impl AuthService {
    /// Register a new user.
    pub async fn register(
        pool: &PgPool,
        input: CreateUser,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Check if email already exists
        if UserRepository::find_by_email(pool, &input.email)
            .await?
            .is_some()
        {
            return Err(AppError::Validation("Email already registered".to_string()));
        }

        // Validate email format (basic check)
        if !input.email.contains('@') {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        // Validate password length
        if input.password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        // Hash password and create user
        let password_hash = hash_password(&input.password)?;
        let user = UserRepository::create(pool, &input.email, &password_hash).await?;

        // Assign default 'user' role
        if let Some(role) = RoleRepository::find_by_name(pool, "user").await? {
            UserRepository::assign_role(pool, user.id, role.id).await?;
        }

        // Get roles and generate token
        let roles = UserRepository::get_user_roles(pool, user.id).await?;
        let claims = Claims::new(user.id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }

    /// Login a user.
    pub async fn login(
        pool: &PgPool,
        input: LoginRequest,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Find user by email
        let user = UserRepository::find_by_email(pool, &input.email)
            .await?
            .ok_or(AppError::Unauthorized)?;

        // Verify user is active
        if !user.is_active {
            return Err(AppError::Unauthorized);
        }

        // Verify password
        if !verify_password(&input.password, &user.password_hash)? {
            return Err(AppError::Unauthorized);
        }

        // Get roles and generate token
        let roles = UserRepository::get_user_roles(pool, user.id).await?;
        let claims = Claims::new(user.id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }

    /// Refresh a token (generate new token from valid claims).
    pub async fn refresh(
        pool: &PgPool,
        user_id: Uuid,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Verify user still exists and is active
        let user = UserRepository::find_by_id(pool, user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if !user.is_active {
            return Err(AppError::Unauthorized);
        }

        // Get fresh roles and generate new token
        let roles = UserRepository::get_user_roles(pool, user_id).await?;
        let claims = Claims::new(user_id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }
}
