use sqlx::PgPool;
use uuid::Uuid;

use crate::{error::AppResult, models::Role};

pub struct RoleRepository;

impl RoleRepository {
    /// Get all roles.
    pub async fn find_all(pool: &PgPool) -> AppResult<Vec<Role>> {
        let roles = sqlx::query_as::<_, Role>(
            r#"
            SELECT id, name, description, created_at
            FROM roles
            ORDER BY name
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(roles)
    }

    /// Find a role by ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<Role>> {
        let role = sqlx::query_as::<_, Role>(
            r#"
            SELECT id, name, description, created_at
            FROM roles
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(role)
    }

    /// Find a role by name.
    pub async fn find_by_name(pool: &PgPool, name: &str) -> AppResult<Option<Role>> {
        let role = sqlx::query_as::<_, Role>(
            r#"
            SELECT id, name, description, created_at
            FROM roles
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(role)
    }

    /// Create a new role.
    pub async fn create(pool: &PgPool, name: &str, description: Option<&str>) -> AppResult<Role> {
        let role = sqlx::query_as::<_, Role>(
            r#"
            INSERT INTO roles (name, description)
            VALUES ($1, $2)
            RETURNING id, name, description, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .fetch_one(pool)
        .await?;

        Ok(role)
    }

    /// Update a role.
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> AppResult<Option<Role>> {
        let role = sqlx::query_as::<_, Role>(
            r#"
            UPDATE roles
            SET name = $2, description = $3
            WHERE id = $1
            RETURNING id, name, description, created_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .fetch_optional(pool)
        .await?;

        Ok(role)
    }

    /// Delete a role.
    pub async fn delete(pool: &PgPool, id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM roles
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
