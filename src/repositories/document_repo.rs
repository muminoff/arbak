use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppResult,
    models::{Document, DocumentAccess},
};

pub struct DocumentRepository;

impl DocumentRepository {
    /// Find all documents with pagination, search, filters, and sorting (RLS will filter based on current user).
    /// Note: sort_column and sort_direction must be pre-validated to prevent SQL injection.
    pub async fn find_all(
        tx: &mut Transaction<'_, Postgres>,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        is_public: Option<bool>,
        sort_column: &str,
        sort_direction: &str,
    ) -> AppResult<Vec<Document>> {
        let order_clause = format!("{} {}", sort_column, sort_direction);

        // Build WHERE conditions dynamically
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 3; // $1 = limit, $2 = offset

        if let Some(term) = search {
            if !term.trim().is_empty() {
                conditions.push(format!("(title ILIKE ${} OR content ILIKE ${})", param_idx, param_idx));
                param_idx += 1;
            }
        }

        if is_public.is_some() {
            conditions.push(format!("is_public = ${}", param_idx));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            r#"
            SELECT id, title, content, owner_id, is_public, created_at, updated_at
            FROM documents
            {}
            ORDER BY {}
            LIMIT $1 OFFSET $2
            "#,
            where_clause, order_clause
        );

        let mut q = sqlx::query_as::<_, Document>(&query)
            .bind(limit)
            .bind(offset);

        if let Some(term) = search {
            if !term.trim().is_empty() {
                q = q.bind(format!("%{}%", term.trim()));
            }
        }

        if let Some(public) = is_public {
            q = q.bind(public);
        }

        let docs = q.fetch_all(&mut **tx).await?;
        Ok(docs)
    }

    /// Count total documents with optional filters (RLS will filter based on current user).
    pub async fn count(
        tx: &mut Transaction<'_, Postgres>,
        search: Option<&str>,
        is_public: Option<bool>,
    ) -> AppResult<i64> {
        // Build WHERE conditions dynamically
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 1;

        if let Some(term) = search {
            if !term.trim().is_empty() {
                conditions.push(format!("(title ILIKE ${} OR content ILIKE ${})", param_idx, param_idx));
                param_idx += 1;
            }
        }

        if is_public.is_some() {
            conditions.push(format!("is_public = ${}", param_idx));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!("SELECT COUNT(*) FROM documents {}", where_clause);

        let mut q = sqlx::query_as::<_, (i64,)>(&query);

        if let Some(term) = search {
            if !term.trim().is_empty() {
                q = q.bind(format!("%{}%", term.trim()));
            }
        }

        if let Some(public) = is_public {
            q = q.bind(public);
        }

        let row = q.fetch_one(&mut **tx).await?;

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
