use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct Document {
    pub id: Uuid,
    #[schema(example = "My Document")]
    pub title: String,
    #[schema(example = "Document content here")]
    pub content: Option<String>,
    pub owner_id: Uuid,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct DocumentAccess {
    pub document_id: Uuid,
    pub user_id: Uuid,
    pub can_read: bool,
    pub can_write: bool,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocument {
    #[schema(example = "My Document")]
    pub title: String,
    #[schema(example = "Document content here")]
    pub content: Option<String>,
    #[serde(default)]
    pub is_public: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocument {
    #[schema(example = "Updated Title")]
    pub title: Option<String>,
    #[schema(example = "Updated content")]
    pub content: Option<String>,
    pub is_public: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ShareDocument {
    pub user_id: Uuid,
    #[serde(default = "default_true")]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
}

fn default_true() -> bool {
    true
}
