use arbak::{config::Config, db::create_pool, AppState};
use sqlx::PgPool;

pub async fn setup_test_db() -> PgPool {
    dotenvy::dotenv().ok();
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");

    let pool = create_pool(&database_url).await.expect("Failed to create pool");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

pub fn test_config() -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").expect("DATABASE_URL required"),
        jwt_secret: "test-jwt-secret-minimum-32-characters!!".to_string(),
        jwt_expiration_seconds: 3600,
        host: "127.0.0.1".to_string(),
        port: 0, // Random port
    }
}

pub fn create_test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        config: test_config(),
    }
}
