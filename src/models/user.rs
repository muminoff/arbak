use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct User {
    /// Unique user identifier
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    /// User's email address (unique)
    #[schema(example = "user@example.com")]
    pub email: String,
    #[serde(skip_serializing)]
    #[schema(ignore)]
    pub password_hash: String,
    /// Whether the user account is active. Inactive users cannot login.
    #[schema(example = true)]
    pub is_active: bool,
    /// Whether the user's email has been verified
    #[schema(example = true)]
    pub email_verified: bool,
    /// Timestamp when the account was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the account was last modified
    pub updated_at: DateTime<Utc>,
}

/// User registration request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUser {
    /// Email address for the new account. Must be unique and valid format.
    #[schema(example = "user@example.com", format = "email")]
    pub email: String,
    /// Account password. Must be at least 8 characters.
    #[schema(example = "securepassword123", min_length = 8)]
    pub password: String,
}

/// User profile with assigned roles
#[derive(Debug, Serialize, ToSchema)]
pub struct UserWithRoles {
    /// Unique user identifier
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    /// User's email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Whether the user account is active
    #[schema(example = true)]
    pub is_active: bool,
    /// Whether the user's email has been verified
    #[schema(example = true)]
    pub email_verified: bool,
    /// List of role names assigned to the user
    #[schema(example = json!(["user", "admin"]))]
    pub roles: Vec<String>,
    /// Timestamp when the account was created
    pub created_at: DateTime<Utc>,
}

/// Request body for updating a user
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    /// New email address (optional)
    #[schema(example = "newemail@example.com")]
    pub email: Option<String>,
    /// New password (optional, must be at least 8 characters if provided)
    #[schema(example = "newsecurepassword123", min_length = 8)]
    pub password: Option<String>,
    /// Whether the account is active (optional)
    #[schema(example = true)]
    pub is_active: Option<bool>,
}
