use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request body for creating a new role
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRole {
    /// Unique role name (e.g., "admin", "editor", "viewer")
    #[schema(example = "editor")]
    pub name: String,
    /// Optional description of the role's purpose
    #[schema(example = "Can edit documents but not delete them")]
    pub description: Option<String>,
}

/// Request body for updating a role
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRole {
    /// New role name
    #[schema(example = "content-editor")]
    pub name: String,
    /// New role description
    #[schema(example = "Can edit and publish content")]
    pub description: Option<String>,
}

/// Request body for assigning a role to a user
#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRole {
    /// The ID of the role to assign
    pub role_id: Uuid,
}

/// Response containing a list of role names
#[derive(Debug, Serialize, ToSchema)]
pub struct UserRolesResponse {
    pub user_id: Uuid,
    pub roles: Vec<String>,
}
