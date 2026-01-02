use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppResult,
    models::{User, UserWithRoles},
};

pub struct UserRepository;

impl UserRepository {
    /// Find a user by email (for login).
    pub async fn find_by_email(pool: &PgPool, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, is_active, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Find a user by ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, is_active, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Create a new user.
    pub async fn create(pool: &PgPool, email: &str, password_hash: &str) -> AppResult<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash)
            VALUES ($1, $2)
            RETURNING id, email, password_hash, is_active, created_at, updated_at
            "#,
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    /// Get all role names for a user.
    pub async fn get_user_roles(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<String>> {
        let roles = sqlx::query_scalar::<_, String>(
            r#"
            SELECT r.name
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        Ok(roles)
    }

    /// Assign a role to a user.
    pub async fn assign_role(pool: &PgPool, user_id: Uuid, role_id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO user_roles (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Remove a role from a user.
    pub async fn remove_role(pool: &PgPool, user_id: Uuid, role_id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2
            "#,
        )
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get user with roles.
    pub async fn get_with_roles(pool: &PgPool, user_id: Uuid) -> AppResult<Option<UserWithRoles>> {
        let user = Self::find_by_id(pool, user_id).await?;
        match user {
            Some(u) => {
                let roles = Self::get_user_roles(pool, user_id).await?;
                Ok(Some(UserWithRoles {
                    id: u.id,
                    email: u.email,
                    is_active: u.is_active,
                    roles,
                    created_at: u.created_at,
                }))
            }
            None => Ok(None),
        }
    }
}
