use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub async fn create_pool(database_url: &str) -> AppResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(AppError::from)
}

/// A database connection with RLS context set for a specific user.
/// All queries executed through this connection will be filtered by RLS policies.
pub struct AuthenticatedConnection<'a> {
    tx: Transaction<'a, Postgres>,
}

impl<'a> AuthenticatedConnection<'a> {
    /// Create a new authenticated connection with RLS context set for the given user.
    pub async fn new(pool: &PgPool, user_id: Uuid) -> AppResult<AuthenticatedConnection<'static>> {
        let mut tx = pool.begin().await?;

        // Set the session variable that RLS policies use
        // Using SET LOCAL ensures it's scoped to this transaction
        sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;

        Ok(AuthenticatedConnection { tx })
    }

    /// Get a mutable reference to the underlying transaction for executing queries.
    pub fn executor(&mut self) -> &mut Transaction<'a, Postgres> {
        &mut self.tx
    }

    /// Commit the transaction.
    pub async fn commit(self) -> AppResult<()> {
        self.tx.commit().await?;
        Ok(())
    }

    /// Rollback the transaction (happens automatically on drop, but explicit is clearer).
    pub async fn rollback(self) -> AppResult<()> {
        self.tx.rollback().await?;
        Ok(())
    }
}
