use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppResult,
    models::{Permission, PermissionAction},
};

pub struct PermissionRepository;

impl PermissionRepository {
    /// Get all permissions.
    pub async fn find_all(pool: &PgPool) -> AppResult<Vec<Permission>> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT id, resource_type, action, description
            FROM permissions
            ORDER BY resource_type, action
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(permissions)
    }

    /// Find a permission by ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<Permission>> {
        let permission = sqlx::query_as::<_, Permission>(
            r#"
            SELECT id, resource_type, action, description
            FROM permissions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(permission)
    }

    /// Get all permissions for a role.
    pub async fn get_role_permissions(pool: &PgPool, role_id: Uuid) -> AppResult<Vec<Permission>> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.id, p.resource_type, p.action, p.description
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = $1
            ORDER BY p.resource_type, p.action
            "#,
        )
        .bind(role_id)
        .fetch_all(pool)
        .await?;

        Ok(permissions)
    }

    /// Add a permission to a role.
    pub async fn add_permission_to_role(
        pool: &PgPool,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES ($1, $2)
            ON CONFLICT (role_id, permission_id) DO NOTHING
            "#,
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Remove a permission from a role.
    pub async fn remove_permission_from_role(
        pool: &PgPool,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            DELETE FROM role_permissions
            WHERE role_id = $1 AND permission_id = $2
            "#,
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Create a new permission.
    pub async fn create(
        pool: &PgPool,
        resource_type: &str,
        action: PermissionAction,
        description: Option<&str>,
    ) -> AppResult<Permission> {
        let permission = sqlx::query_as::<_, Permission>(
            r#"
            INSERT INTO permissions (resource_type, action, description)
            VALUES ($1, $2, $3)
            RETURNING id, resource_type, action, description
            "#,
        )
        .bind(resource_type)
        .bind(action)
        .bind(description)
        .fetch_one(pool)
        .await?;

        Ok(permission)
    }

    /// Delete a permission.
    pub async fn delete(pool: &PgPool, id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM permissions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
