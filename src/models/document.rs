use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// A document with RLS-controlled access. Visibility depends on ownership, sharing, and public flag.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct Document {
    /// Unique document identifier
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    /// Document title (required, cannot be empty)
    #[schema(example = "Q4 Planning Document")]
    pub title: String,
    /// Document body content (optional, can be null)
    #[schema(example = "This document outlines our Q4 objectives...")]
    pub content: Option<String>,
    /// User ID of the document owner who has full control
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub owner_id: Uuid,
    /// If true, document is visible to all authenticated users
    #[schema(example = false)]
    pub is_public: bool,
    /// Timestamp when the document was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the document was last modified
    pub updated_at: DateTime<Utc>,
}

/// Document sharing permission grant for a specific user
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct DocumentAccess {
    /// ID of the shared document
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub document_id: Uuid,
    /// ID of the user who has been granted access
    #[schema(example = "660e8400-e29b-41d4-a716-446655440000")]
    pub user_id: Uuid,
    /// Whether the user can view the document
    #[schema(example = true)]
    pub can_read: bool,
    /// Whether the user can modify the document
    #[schema(example = false)]
    pub can_write: bool,
    /// Timestamp when access was granted
    pub granted_at: DateTime<Utc>,
}

/// Request body for creating a new document
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocument {
    /// Document title (required, cannot be empty)
    #[schema(example = "Meeting Notes", min_length = 1)]
    pub title: String,
    /// Document body content (optional)
    #[schema(example = "Discussed project timeline and milestones.")]
    pub content: Option<String>,
    /// Set to true to make document visible to all users. Defaults to false (private).
    #[serde(default)]
    #[schema(example = false)]
    pub is_public: bool,
}

/// Request body for updating a document. All fields are optional - only provided fields are updated.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocument {
    /// New document title (if provided, cannot be empty)
    #[schema(example = "Updated Meeting Notes")]
    pub title: Option<String>,
    /// New document content (set to null to clear content)
    #[schema(example = "Updated content with action items.")]
    pub content: Option<String>,
    /// Change document visibility. true = public, false = private.
    #[schema(example = true)]
    pub is_public: Option<bool>,
}

/// Request body for sharing a document with another user
#[derive(Debug, Deserialize, ToSchema)]
pub struct ShareDocument {
    /// ID of the user to share with (must exist)
    #[schema(example = "660e8400-e29b-41d4-a716-446655440000")]
    pub user_id: Uuid,
    /// Grant read permission. Defaults to true.
    #[serde(default = "default_true")]
    #[schema(example = true)]
    pub can_read: bool,
    /// Grant write permission. Defaults to false.
    #[serde(default)]
    #[schema(example = false)]
    pub can_write: bool,
}

fn default_true() -> bool {
    true
}
