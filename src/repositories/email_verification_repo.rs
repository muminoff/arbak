use chrono::{Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;

pub struct EmailVerificationRepository;

impl EmailVerificationRepository {
    /// Generate a secure random token (32 bytes = 64 hex chars)
    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(bytes)
    }

    /// Hash a token using SHA256
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create an email verification token for a user
    /// Returns the plain token (to be sent to user) - only the hash is stored
    pub async fn create_token(pool: &PgPool, user_id: Uuid) -> AppResult<String> {
        let token = Self::generate_token();
        let token_hash = Self::hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(24);

        sqlx::query(
            r#"
            INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(pool)
        .await?;

        Ok(token)
    }

    /// Find a valid (not expired, not used) token and return the user_id
    pub async fn find_valid_token(pool: &PgPool, token: &str) -> AppResult<Option<Uuid>> {
        let token_hash = Self::hash_token(token);

        let result = sqlx::query_as::<_, (Uuid,)>(
            r#"
            SELECT user_id
            FROM email_verification_tokens
            WHERE token_hash = $1
              AND expires_at > NOW()
              AND used_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(result.map(|(user_id,)| user_id))
    }

    /// Mark a token as used
    pub async fn mark_token_used(pool: &PgPool, token: &str) -> AppResult<()> {
        let token_hash = Self::hash_token(token);

        sqlx::query(
            r#"
            UPDATE email_verification_tokens
            SET used_at = NOW()
            WHERE token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Invalidate all verification tokens for a user
    pub async fn invalidate_user_tokens(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE email_verification_tokens
            SET used_at = NOW()
            WHERE user_id = $1 AND used_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
