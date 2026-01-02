use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    #[schema(ignore)]
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUser {
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "securepassword123")]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserWithRoles {
    pub id: Uuid,
    #[schema(example = "user@example.com")]
    pub email: String,
    pub is_active: bool,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
}
