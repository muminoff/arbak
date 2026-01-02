use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_action", rename_all = "lowercase")]
pub enum PermissionAction {
    Create,
    Read,
    Update,
    Delete,
    Manage,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub resource_type: String,
    pub action: PermissionAction,
    pub description: Option<String>,
}
