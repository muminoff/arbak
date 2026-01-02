use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppResult,
    models::{Document, DocumentAccess},
};

pub struct DocumentRepository;

impl DocumentRepository {
    /// Find all documents with pagination and optional search (RLS will filter based on current user).
    pub async fn find_all(
        tx: &mut Transaction<'_, Postgres>,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> AppResult<Vec<Document>> {
        let docs = match search {
            Some(term) if !term.trim().is_empty() => {
                let pattern = format!("%{}%", term.trim());
                sqlx::query_as::<_, Document>(
                    r#"
                    SELECT id, title, content, owner_id, is_public, created_at, updated_at
                    FROM documents
                    WHERE title ILIKE $3 OR content ILIKE $3
                    ORDER BY created_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                )
                .bind(limit)
                .bind(offset)
                .bind(pattern)
                .fetch_all(&mut **tx)
                .await?
            }
            _ => {
                sqlx::query_as::<_, Document>(
                    r#"
                    SELECT id, title, content, owner_id, is_public, created_at, updated_at
                    FROM documents
                    ORDER BY created_at DESC
                    LIMIT $1 OFFSET $2
                    "#,
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&mut **tx)
                .await?
            }
        };

        Ok(docs)
    }

    /// Count total documents with optional search (RLS will filter based on current user).
    pub async fn count(tx: &mut Transaction<'_, Postgres>, search: Option<&str>) -> AppResult<i64> {
        let row: (i64,) = match search {
            Some(term) if !term.trim().is_empty() => {
                let pattern = format!("%{}%", term.trim());
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM documents
                    WHERE title ILIKE $1 OR content ILIKE $1
                    "#,
                )
                .bind(pattern)
                .fetch_one(&mut **tx)
                .await?
            }
            _ => {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM documents
                    "#,
                )
                .fetch_one(&mut **tx)
                .await?
            }
        };

        Ok(row.0)
    }

    /// Find a document by ID (RLS will filter).
    pub async fn find_by_id(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> AppResult<Option<Document>> {
        let doc = sqlx::query_as::<_, Document>(
            r#"
            SELECT id, title, content, owner_id, is_public, created_at, updated_at
            FROM documents
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;

        Ok(doc)
    }

    /// Create a new document.
    pub async fn create(
        tx: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        title: &str,
        content: Option<&str>,
        is_public: bool,
    ) -> AppResult<Document> {
        let doc = sqlx::query_as::<_, Document>(
            r#"
            INSERT INTO documents (owner_id, title, content, is_public)
            VALUES ($1, $2, $3, $4)
            RETURNING id, title, content, owner_id, is_public, created_at, updated_at
            "#,
        )
        .bind(owner_id)
        .bind(title)
        .bind(content)
        .bind(is_public)
        .fetch_one(&mut **tx)
        .await?;

        Ok(doc)
    }

    /// Update a document.
    pub async fn update(
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        title: Option<&str>,
        content: Option<&str>,
        is_public: Option<bool>,
    ) -> AppResult<Option<Document>> {
        let doc = sqlx::query_as::<_, Document>(
            r#"
            UPDATE documents
            SET
                title = COALESCE($2, title),
                content = COALESCE($3, content),
                is_public = COALESCE($4, is_public),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, title, content, owner_id, is_public, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(title)
        .bind(content)
        .bind(is_public)
        .fetch_optional(&mut **tx)
        .await?;

        Ok(doc)
    }

    /// Delete a document.
    pub async fn delete(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM documents
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Share a document with a user.
    pub async fn share(
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
        user_id: Uuid,
        can_read: bool,
        can_write: bool,
    ) -> AppResult<DocumentAccess> {
        let access = sqlx::query_as::<_, DocumentAccess>(
            r#"
            INSERT INTO document_access (document_id, user_id, can_read, can_write)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (document_id, user_id)
            DO UPDATE SET can_read = $3, can_write = $4
            RETURNING document_id, user_id, can_read, can_write, granted_at
            "#,
        )
        .bind(document_id)
        .bind(user_id)
        .bind(can_read)
        .bind(can_write)
        .fetch_one(&mut **tx)
        .await?;

        Ok(access)
    }

    /// Remove document access for a user.
    pub async fn unshare(
        tx: &mut Transaction<'_, Postgres>,
        document_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM document_access
            WHERE document_id = $1 AND user_id = $2
            "#,
        )
        .bind(document_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
