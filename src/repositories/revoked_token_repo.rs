use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;

pub struct RevokedTokenRepository;

impl RevokedTokenRepository {
    /// Revoke a token by adding its JTI to the blacklist
    pub async fn revoke_token(
        pool: &PgPool,
        jti: Uuid,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO revoked_tokens (jti, user_id, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (jti) DO NOTHING
            "#,
        )
        .bind(jti)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Check if a token has been revoked
    pub async fn is_token_revoked(pool: &PgPool, jti: Uuid) -> AppResult<bool> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)
            "#,
        )
        .bind(jti)
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    /// Cleanup expired revoked tokens (optional, can be run periodically)
    pub async fn cleanup_expired(pool: &PgPool) -> AppResult<u64> {
        let result = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }
}
