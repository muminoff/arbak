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
            SELECT id, email, password_hash, is_active, email_verified, created_at, updated_at
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
            SELECT id, email, password_hash, is_active, email_verified, created_at, updated_at
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
            RETURNING id, email, password_hash, is_active, email_verified, created_at, updated_at
            "#,
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    /// Set user email_verified status.
    pub async fn set_email_verified(pool: &PgPool, id: Uuid, verified: bool) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET email_verified = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(verified)
        .execute(pool)
        .await?;

        Ok(())
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
                    email_verified: u.email_verified,
                    roles,
                    created_at: u.created_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get all users with pagination.
    pub async fn find_all(
        pool: &PgPool,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<Vec<User>> {
        let mut query = String::from(
            r#"
            SELECT id, email, password_hash, is_active, email_verified, created_at, updated_at
            FROM users
            WHERE 1=1
            "#,
        );

        let mut param_count = 0;

        if search.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND email ILIKE ${}", param_count));
        }

        if is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        param_count += 1;
        let limit_param = param_count;
        param_count += 1;
        let offset_param = param_count;

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            limit_param, offset_param
        ));

        let mut db_query = sqlx::query_as::<_, User>(&query);

        if let Some(s) = search {
            db_query = db_query.bind(format!("%{}%", s));
        }

        if let Some(active) = is_active {
            db_query = db_query.bind(active);
        }

        db_query = db_query.bind(limit).bind(offset);

        let users = db_query.fetch_all(pool).await?;
        Ok(users)
    }

    /// Count total users matching criteria.
    pub async fn count(
        pool: &PgPool,
        search: Option<&str>,
        is_active: Option<bool>,
    ) -> AppResult<i64> {
        let mut query = String::from("SELECT COUNT(*) FROM users WHERE 1=1");
        let mut param_count = 0;

        if search.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND email ILIKE ${}", param_count));
        }

        if is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query);

        if let Some(s) = search {
            db_query = db_query.bind(format!("%{}%", s));
        }

        if let Some(active) = is_active {
            db_query = db_query.bind(active);
        }

        let count = db_query.fetch_one(pool).await?;
        Ok(count)
    }

    /// Update a user's email.
    pub async fn update_email(pool: &PgPool, id: Uuid, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET email = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, email, password_hash, is_active, email_verified, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Update a user's password.
    pub async fn update_password(
        pool: &PgPool,
        id: Uuid,
        password_hash: &str,
    ) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET password_hash = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, email, password_hash, is_active, email_verified, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(password_hash)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Set user active status.
    pub async fn set_active(pool: &PgPool, id: Uuid, is_active: bool) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET is_active = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, email, password_hash, is_active, email_verified, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(is_active)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Delete a user (hard delete).
    pub async fn delete(pool: &PgPool, id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
