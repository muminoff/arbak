# RBAC System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a minimal RBAC system with PostgreSQL Row-Level Security enforcement at the database level.

**Architecture:** Layered Rust application using Axum for HTTP, SQLx for database access with compile-time query checking, and PostgreSQL RLS for authorization. Every authenticated request sets RLS context via transaction-scoped session variables.

**Tech Stack:** Rust, Axum 0.7, SQLx 0.8, PostgreSQL 15+, JWT (jsonwebtoken), Argon2 password hashing

---

## Phase 1: Foundation

### Task 1.1: Update Cargo.toml with Dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Update Cargo.toml**

```toml
[package]
name = "arbak"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Web framework
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# Database
sqlx = { version = "0.8", features = [
    "runtime-tokio",
    "tls-rustls",
    "postgres",
    "uuid",
    "chrono",
    "migrate"
]}

# Auth
jsonwebtoken = "9"
argon2 = "0.5"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Utils
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
tokio-test = "0.4"
```

**Step 2: Verify build**

Run: `cargo build`
Expected: Compiles with new dependencies

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add all project dependencies"
```

---

### Task 1.2: Create Config Module

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs`

**Step 1: Create config.rs**

```rust
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration_seconds: i64,
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenvy::dotenv().ok();

        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_expiration_seconds: env::var("JWT_EXPIRATION_SECONDS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .unwrap_or(900),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
```

**Step 2: Update main.rs to use config**

```rust
mod config;

use config::Config;

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 3: Create .env.example**

Create file `.env.example`:
```
DATABASE_URL=postgres://app_user:password@localhost:5432/arbak_db
JWT_SECRET=your-256-bit-secret-key-here-minimum-32-chars
JWT_EXPIRATION_SECONDS=900
RUST_LOG=info,sqlx=warn
HOST=0.0.0.0
PORT=3000
```

**Step 4: Add .env to .gitignore**

Append to `.gitignore`:
```
.env
```

**Step 5: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add src/config.rs src/main.rs .env.example .gitignore
git commit -m "feat: add configuration module with env loading"
```

---

### Task 1.3: Create Error Module

**Files:**
- Create: `src/error.rs`

**Step 1: Create error.rs**

```rust
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Permission denied")]
    Forbidden,

    #[error("Resource not found")]
    NotFound,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AppError::Internal(e) => {
                tracing::error!("Internal error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
            }
        };

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
```

**Step 2: Add to main.rs**

```rust
mod config;
mod error;

use config::Config;

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/error.rs src/main.rs
git commit -m "feat: add unified error handling with AppError"
```

---

## Phase 2: Database Layer

### Task 2.1: Create Database Migration

**Files:**
- Create: `migrations/001_initial_schema.sql`

**Step 1: Create migrations directory and schema file**

```sql
-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enum types
CREATE TYPE permission_action AS ENUM ('create', 'read', 'update', 'delete', 'manage');

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Permissions table
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_type VARCHAR(100) NOT NULL,
    action permission_action NOT NULL,
    description TEXT,
    UNIQUE(resource_type, action)
);

-- Role-Permission junction
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User-Role junction
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Documents table (example RLS-protected resource)
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    content TEXT,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    is_public BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Document access grants
CREATE TABLE document_access (
    document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    can_read BOOLEAN DEFAULT true,
    can_write BOOLEAN DEFAULT false,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (document_id, user_id)
);

-- Indexes
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_documents_owner_id ON documents(owner_id);
CREATE INDEX idx_document_access_user_id ON document_access(user_id);
CREATE INDEX idx_document_access_document_id ON document_access(document_id);

-- Helper function to get current user ID from session
CREATE OR REPLACE FUNCTION current_user_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', true), '')::UUID;
EXCEPTION
    WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper function to check if current user has a specific permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_resource_type VARCHAR,
    p_action permission_action
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = current_user_id()
          AND p.resource_type = p_resource_type
          AND (p.action = p_action OR p.action = 'manage')
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Enable RLS on documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- RLS Policies for documents
CREATE POLICY documents_select ON documents FOR SELECT USING (
    owner_id = current_user_id()
    OR is_public = true
    OR EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = id
          AND da.user_id = current_user_id()
          AND da.can_read = true
    )
    OR user_has_permission('document', 'read')
);

CREATE POLICY documents_insert ON documents FOR INSERT WITH CHECK (
    owner_id = current_user_id()
    AND user_has_permission('document', 'create')
);

CREATE POLICY documents_update ON documents FOR UPDATE USING (
    owner_id = current_user_id()
    OR EXISTS (
        SELECT 1 FROM document_access da
        WHERE da.document_id = id
          AND da.user_id = current_user_id()
          AND da.can_write = true
    )
    OR user_has_permission('document', 'update')
);

CREATE POLICY documents_delete ON documents FOR DELETE USING (
    owner_id = current_user_id()
    OR user_has_permission('document', 'delete')
);

-- Enable RLS on document_access
ALTER TABLE document_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_access FORCE ROW LEVEL SECURITY;

CREATE POLICY document_access_select ON document_access FOR SELECT USING (
    user_id = current_user_id()
    OR EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

CREATE POLICY document_access_insert ON document_access FOR INSERT WITH CHECK (
    EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);

CREATE POLICY document_access_delete ON document_access FOR DELETE USING (
    EXISTS (
        SELECT 1 FROM documents d
        WHERE d.id = document_id AND d.owner_id = current_user_id()
    )
);
```

**Step 2: Commit**

```bash
git add migrations/
git commit -m "feat: add initial database schema with RLS policies"
```

---

### Task 2.2: Create Seed Data Migration

**Files:**
- Create: `migrations/002_seed_data.sql`

**Step 1: Create seed data file**

```sql
-- Default roles
INSERT INTO roles (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000001', 'admin', 'Full system access'),
    ('00000000-0000-0000-0000-000000000002', 'user', 'Standard user access'),
    ('00000000-0000-0000-0000-000000000003', 'viewer', 'Read-only access');

-- Default permissions
INSERT INTO permissions (resource_type, action, description) VALUES
    ('document', 'create', 'Create new documents'),
    ('document', 'read', 'Read any document'),
    ('document', 'update', 'Update any document'),
    ('document', 'delete', 'Delete any document'),
    ('document', 'manage', 'Full document access'),
    ('user', 'create', 'Create new users'),
    ('user', 'read', 'View user profiles'),
    ('user', 'update', 'Update user profiles'),
    ('user', 'delete', 'Delete users'),
    ('user', 'manage', 'Full user access');

-- Admin gets 'manage' on everything
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions WHERE action = 'manage';

-- User gets create, read, update on documents
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', id FROM permissions
WHERE resource_type = 'document' AND action IN ('create', 'read', 'update');

-- Viewer gets read on documents
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource_type = 'document' AND action = 'read';
```

**Step 2: Commit**

```bash
git add migrations/002_seed_data.sql
git commit -m "feat: add seed data for roles and permissions"
```

---

### Task 2.3: Create Database Pool Module

**Files:**
- Create: `src/db/mod.rs`
- Create: `src/db/pool.rs`

**Step 1: Create src/db/mod.rs**

```rust
mod pool;

pub use pool::{create_pool, AuthenticatedConnection};
```

**Step 2: Create src/db/pool.rs**

```rust
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
```

**Step 3: Update main.rs**

```rust
mod config;
mod db;
mod error;

use config::Config;

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 4: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/db/
git commit -m "feat: add database pool with AuthenticatedConnection for RLS"
```

---

### Task 2.4: Create Models

**Files:**
- Create: `src/models/mod.rs`
- Create: `src/models/user.rs`
- Create: `src/models/role.rs`
- Create: `src/models/permission.rs`
- Create: `src/models/document.rs`

**Step 1: Create src/models/mod.rs**

```rust
mod document;
mod permission;
mod role;
mod user;

pub use document::{Document, DocumentAccess, CreateDocument, UpdateDocument, ShareDocument};
pub use permission::{Permission, PermissionAction};
pub use role::Role;
pub use user::{User, CreateUser, UserWithRoles};
```

**Step 2: Create src/models/user.rs**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserWithRoles {
    pub id: Uuid,
    pub email: String,
    pub is_active: bool,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
}
```

**Step 3: Create src/models/role.rs**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}
```

**Step 4: Create src/models/permission.rs**

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "permission_action", rename_all = "lowercase")]
pub enum PermissionAction {
    Create,
    Read,
    Update,
    Delete,
    Manage,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub resource_type: String,
    pub action: PermissionAction,
    pub description: Option<String>,
}
```

**Step 5: Create src/models/document.rs**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Document {
    pub id: Uuid,
    pub title: String,
    pub content: Option<String>,
    pub owner_id: Uuid,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DocumentAccess {
    pub document_id: Uuid,
    pub user_id: Uuid,
    pub can_read: bool,
    pub can_write: bool,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDocument {
    pub title: String,
    pub content: Option<String>,
    #[serde(default)]
    pub is_public: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDocument {
    pub title: Option<String>,
    pub content: Option<String>,
    pub is_public: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ShareDocument {
    pub user_id: Uuid,
    #[serde(default = "default_true")]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
}

fn default_true() -> bool {
    true
}
```

**Step 6: Update main.rs**

```rust
mod config;
mod db;
mod error;
mod models;

use config::Config;

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 7: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 8: Commit**

```bash
git add src/models/
git commit -m "feat: add data models for users, roles, permissions, documents"
```

---

## Phase 3: Authentication

### Task 3.1: Create Password Hashing Module

**Files:**
- Create: `src/auth/mod.rs`
- Create: `src/auth/password.rs`

**Step 1: Create src/auth/mod.rs**

```rust
mod password;

pub use password::{hash_password, verify_password};
```

**Step 2: Create src/auth/password.rs**

```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::{AppError, AppResult};

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hashing failed: {}", e)))
}

/// Verify a password against a hash.
pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid password hash: {}", e)))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "secure_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_different_passwords_different_hashes() {
        let hash1 = hash_password("password1").unwrap();
        let hash2 = hash_password("password1").unwrap();

        // Same password should produce different hashes (due to random salt)
        assert_ne!(hash1, hash2);
    }
}
```

**Step 3: Update main.rs**

```rust
mod auth;
mod config;
mod db;
mod error;
mod models;

use config::Config;

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 4: Run tests**

Run: `cargo test auth::password`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/auth/
git commit -m "feat: add Argon2 password hashing with tests"
```

---

### Task 3.2: Create JWT Module

**Files:**
- Modify: `src/auth/mod.rs`
- Create: `src/auth/jwt.rs`

**Step 1: Create src/auth/jwt.rs**

```rust
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,           // user_id
    pub email: String,
    pub roles: Vec<String>,  // role names (for client-side UI)
    pub exp: i64,            // expiration timestamp
    pub iat: i64,            // issued at
}

impl Claims {
    pub fn new(user_id: Uuid, email: String, roles: Vec<String>, expiration_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id,
            email,
            roles,
            iat: now.timestamp(),
            exp: (now + Duration::seconds(expiration_seconds)).timestamp(),
        }
    }
}

/// Encode claims into a JWT token.
pub fn encode_token(claims: &Claims, secret: &str) -> AppResult<String> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(AppError::from)
}

/// Decode and validate a JWT token.
pub fn decode_token(token: &str, secret: &str) -> AppResult<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_token() {
        let user_id = Uuid::new_v4();
        let claims = Claims::new(
            user_id,
            "test@example.com".to_string(),
            vec!["user".to_string()],
            3600,
        );
        let secret = "test-secret-key-minimum-32-chars!!";

        let token = encode_token(&claims, secret).unwrap();
        let decoded = decode_token(&token, secret).unwrap();

        assert_eq!(decoded.sub, user_id);
        assert_eq!(decoded.email, "test@example.com");
        assert_eq!(decoded.roles, vec!["user"]);
    }

    #[test]
    fn test_invalid_token_fails() {
        let secret = "test-secret-key-minimum-32-chars!!";
        let result = decode_token("invalid.token.here", secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_fails() {
        let claims = Claims::new(
            Uuid::new_v4(),
            "test@example.com".to_string(),
            vec![],
            3600,
        );
        let token = encode_token(&claims, "secret1-minimum-32-characters!!").unwrap();
        let result = decode_token(&token, "secret2-minimum-32-characters!!");
        assert!(result.is_err());
    }
}
```

**Step 2: Update src/auth/mod.rs**

```rust
mod jwt;
mod password;

pub use jwt::{decode_token, encode_token, Claims};
pub use password::{hash_password, verify_password};
```

**Step 3: Run tests**

Run: `cargo test auth::jwt`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/auth/
git commit -m "feat: add JWT encoding/decoding with tests"
```

---

### Task 3.3: Create Auth Middleware

**Files:**
- Modify: `src/auth/mod.rs`
- Create: `src/auth/middleware.rs`

**Step 1: Create src/auth/middleware.rs**

```rust
use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{
    auth::{decode_token, Claims},
    error::{AppError, AppResult},
    AppState,
};

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(request: &Request) -> AppResult<&str> {
    let header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)
}

/// Middleware that validates JWT and stores claims in request extensions.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&request)?;
    let claims = decode_token(token, &state.config.jwt_secret)?;

    // Store claims in request extensions for handlers to access
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extension trait to easily get the current user from request extensions.
pub trait RequestExt {
    fn user_id(&self) -> AppResult<Uuid>;
    fn claims(&self) -> AppResult<&Claims>;
}

impl<B> RequestExt for axum::http::Request<B> {
    fn user_id(&self) -> AppResult<Uuid> {
        self.extensions()
            .get::<Claims>()
            .map(|c| c.sub)
            .ok_or(AppError::Unauthorized)
    }

    fn claims(&self) -> AppResult<&Claims> {
        self.extensions()
            .get::<Claims>()
            .ok_or(AppError::Unauthorized)
    }
}

/// Extractor for getting claims in handlers.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(AuthUser)
            .ok_or(AppError::Unauthorized)
    }
}
```

**Step 2: Update src/auth/mod.rs**

```rust
mod jwt;
mod middleware;
mod password;

pub use jwt::{decode_token, encode_token, Claims};
pub use middleware::{auth_middleware, AuthUser};
pub use password::{hash_password, verify_password};
```

**Step 3: Create AppState stub in main.rs for now**

```rust
mod auth;
mod config;
mod db;
mod error;
mod models;

use config::Config;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 4: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/auth/ src/main.rs
git commit -m "feat: add auth middleware with JWT validation and AuthUser extractor"
```

---

## Phase 4: Repositories

### Task 4.1: Create User Repository

**Files:**
- Create: `src/repositories/mod.rs`
- Create: `src/repositories/user_repo.rs`

**Step 1: Create src/repositories/mod.rs**

```rust
mod user_repo;

pub use user_repo::UserRepository;
```

**Step 2: Create src/repositories/user_repo.rs**

```rust
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
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/repositories/
git commit -m "feat: add user repository with CRUD operations"
```

---

### Task 4.2: Create Role Repository

**Files:**
- Modify: `src/repositories/mod.rs`
- Create: `src/repositories/role_repo.rs`

**Step 1: Create src/repositories/role_repo.rs**

```rust
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
```

**Step 2: Update src/repositories/mod.rs**

```rust
mod role_repo;
mod user_repo;

pub use role_repo::RoleRepository;
pub use user_repo::UserRepository;
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/repositories/
git commit -m "feat: add role repository"
```

---

### Task 4.3: Create Document Repository

**Files:**
- Modify: `src/repositories/mod.rs`
- Create: `src/repositories/document_repo.rs`

**Step 1: Create src/repositories/document_repo.rs**

```rust
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppResult,
    models::{Document, DocumentAccess},
};

pub struct DocumentRepository;

impl DocumentRepository {
    /// Find all documents (RLS will filter based on current user).
    pub async fn find_all(tx: &mut Transaction<'_, Postgres>) -> AppResult<Vec<Document>> {
        let docs = sqlx::query_as::<_, Document>(
            r#"
            SELECT id, title, content, owner_id, is_public, created_at, updated_at
            FROM documents
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&mut **tx)
        .await?;

        Ok(docs)
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
```

**Step 2: Update src/repositories/mod.rs**

```rust
mod document_repo;
mod role_repo;
mod user_repo;

pub use document_repo::DocumentRepository;
pub use role_repo::RoleRepository;
pub use user_repo::UserRepository;
```

**Step 3: Update main.rs to include repositories**

```rust
mod auth;
mod config;
mod db;
mod error;
mod models;
mod repositories;

use config::Config;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 4: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/repositories/ src/main.rs
git commit -m "feat: add document repository with RLS-aware queries"
```

---

## Phase 5: Services

### Task 5.1: Create Auth Service

**Files:**
- Create: `src/services/mod.rs`
- Create: `src/services/auth_service.rs`

**Step 1: Create src/services/mod.rs**

```rust
mod auth_service;

pub use auth_service::AuthService;
```

**Step 2: Create src/services/auth_service.rs**

```rust
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{encode_token, hash_password, verify_password, Claims},
    error::{AppError, AppResult},
    models::CreateUser,
    repositories::{RoleRepository, UserRepository},
};

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub struct AuthService;

impl AuthService {
    /// Register a new user.
    pub async fn register(
        pool: &PgPool,
        input: CreateUser,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Check if email already exists
        if UserRepository::find_by_email(pool, &input.email)
            .await?
            .is_some()
        {
            return Err(AppError::Validation("Email already registered".to_string()));
        }

        // Validate email format (basic check)
        if !input.email.contains('@') {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        // Validate password length
        if input.password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        // Hash password and create user
        let password_hash = hash_password(&input.password)?;
        let user = UserRepository::create(pool, &input.email, &password_hash).await?;

        // Assign default 'user' role
        if let Some(role) = RoleRepository::find_by_name(pool, "user").await? {
            UserRepository::assign_role(pool, user.id, role.id).await?;
        }

        // Get roles and generate token
        let roles = UserRepository::get_user_roles(pool, user.id).await?;
        let claims = Claims::new(user.id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }

    /// Login a user.
    pub async fn login(
        pool: &PgPool,
        input: LoginRequest,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Find user by email
        let user = UserRepository::find_by_email(pool, &input.email)
            .await?
            .ok_or(AppError::Unauthorized)?;

        // Verify user is active
        if !user.is_active {
            return Err(AppError::Unauthorized);
        }

        // Verify password
        if !verify_password(&input.password, &user.password_hash)? {
            return Err(AppError::Unauthorized);
        }

        // Get roles and generate token
        let roles = UserRepository::get_user_roles(pool, user.id).await?;
        let claims = Claims::new(user.id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }

    /// Refresh a token (generate new token from valid claims).
    pub async fn refresh(
        pool: &PgPool,
        user_id: Uuid,
        jwt_secret: &str,
        jwt_expiration: i64,
    ) -> AppResult<AuthResponse> {
        // Verify user still exists and is active
        let user = UserRepository::find_by_id(pool, user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if !user.is_active {
            return Err(AppError::Unauthorized);
        }

        // Get fresh roles and generate new token
        let roles = UserRepository::get_user_roles(pool, user_id).await?;
        let claims = Claims::new(user_id, user.email, roles, jwt_expiration);
        let token = encode_token(&claims, jwt_secret)?;

        Ok(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: jwt_expiration,
        })
    }
}
```

**Step 3: Update main.rs**

```rust
mod auth;
mod config;
mod db;
mod error;
mod models;
mod repositories;
mod services;

use config::Config;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

fn main() {
    let config = Config::from_env();
    println!("Config loaded: {:?}", config);
}
```

**Step 4: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add src/services/
git commit -m "feat: add auth service with register, login, refresh"
```

---

## Phase 6: HTTP Handlers

### Task 6.1: Create Auth Handlers

**Files:**
- Create: `src/handlers/mod.rs`
- Create: `src/handlers/auth_handlers.rs`

**Step 1: Create src/handlers/mod.rs**

```rust
mod auth_handlers;

pub use auth_handlers::auth_routes;
```

**Step 2: Create src/handlers/auth_handlers.rs**

```rust
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::AuthUser,
    error::AppResult,
    models::CreateUser,
    repositories::UserRepository,
    services::{AuthResponse, AuthService, LoginRequest},
    AppState,
};

/// POST /api/auth/register
async fn register(
    State(state): State<AppState>,
    Json(input): Json<CreateUser>,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::register(
        &state.pool,
        input,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

/// POST /api/auth/login
async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::login(
        &state.pool,
        input,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

/// POST /api/auth/refresh (requires auth)
async fn refresh(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<AuthResponse>> {
    let response = AuthService::refresh(
        &state.pool,
        claims.sub,
        &state.config.jwt_secret,
        state.config.jwt_expiration_seconds,
    )
    .await?;

    Ok(Json(response))
}

/// GET /api/auth/me (requires auth)
async fn me(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let user = UserRepository::get_with_roles(&state.pool, claims.sub)
        .await?
        .ok_or(crate::error::AppError::NotFound)?;

    Ok(Json(serde_json::json!({ "data": user })))
}

/// Create auth routes - split into public and protected
pub fn auth_routes() -> (Router<AppState>, Router<AppState>) {
    let public = Router::new()
        .route("/register", post(register))
        .route("/login", post(login));

    let protected = Router::new()
        .route("/refresh", post(refresh))
        .route("/me", get(me));

    (public, protected)
}
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/handlers/
git commit -m "feat: add auth handlers (register, login, refresh, me)"
```

---

### Task 6.2: Create Document Handlers

**Files:**
- Modify: `src/handlers/mod.rs`
- Create: `src/handlers/document_handlers.rs`

**Step 1: Create src/handlers/document_handlers.rs**

```rust
use axum::{
    extract::{Path, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    db::AuthenticatedConnection,
    error::{AppError, AppResult},
    models::{CreateDocument, Document, ShareDocument, UpdateDocument},
    repositories::DocumentRepository,
    AppState,
};

/// GET /api/documents
async fn list_documents(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let docs = DocumentRepository::find_all(conn.executor()).await?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": docs })))
}

/// GET /api/documents/:id
async fn get_document(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let doc = DocumentRepository::find_by_id(conn.executor(), id)
        .await?
        .ok_or(AppError::NotFound)?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": doc })))
}

/// POST /api/documents
async fn create_document(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(input): Json<CreateDocument>,
) -> AppResult<Json<serde_json::Value>> {
    if input.title.is_empty() {
        return Err(AppError::Validation("Title is required".to_string()));
    }

    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let doc = DocumentRepository::create(
        conn.executor(),
        claims.sub,
        &input.title,
        input.content.as_deref(),
        input.is_public,
    )
    .await?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": doc })))
}

/// PUT /api/documents/:id
async fn update_document(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateDocument>,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let doc = DocumentRepository::update(
        conn.executor(),
        id,
        input.title.as_deref(),
        input.content.as_deref(),
        input.is_public,
    )
    .await?
    .ok_or(AppError::NotFound)?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": doc })))
}

/// DELETE /api/documents/:id
async fn delete_document(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let deleted = DocumentRepository::delete(conn.executor(), id).await?;
    conn.commit().await?;

    if !deleted {
        return Err(AppError::NotFound);
    }

    Ok(Json(serde_json::json!({ "message": "Document deleted" })))
}

/// POST /api/documents/:id/share
async fn share_document(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<ShareDocument>,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;

    // Verify document exists and user owns it
    let doc = DocumentRepository::find_by_id(conn.executor(), id)
        .await?
        .ok_or(AppError::NotFound)?;

    if doc.owner_id != claims.sub {
        return Err(AppError::Forbidden);
    }

    let access = DocumentRepository::share(
        conn.executor(),
        id,
        input.user_id,
        input.can_read,
        input.can_write,
    )
    .await?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": access })))
}

/// Create document routes (all protected)
pub fn document_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_documents).post(create_document))
        .route(
            "/:id",
            get(get_document)
                .put(update_document)
                .delete(delete_document),
        )
        .route("/:id/share", post(share_document))
}
```

**Step 2: Update src/handlers/mod.rs**

```rust
mod auth_handlers;
mod document_handlers;

pub use auth_handlers::auth_routes;
pub use document_handlers::document_routes;
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/handlers/
git commit -m "feat: add document handlers with RLS-protected CRUD"
```

---

### Task 6.3: Create Routes Module and Main Application

**Files:**
- Create: `src/routes.rs`
- Modify: `src/main.rs`

**Step 1: Create src/routes.rs**

```rust
use axum::{middleware, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::{auth::auth_middleware, handlers, AppState};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let (auth_public, auth_protected) = handlers::auth_routes();

    // Public routes (no auth required)
    let public_routes = Router::new().nest("/auth", auth_public);

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .nest("/auth", auth_protected)
        .nest("/documents", handlers::document_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Combine all routes under /api
    Router::new()
        .nest("/api", public_routes.merge(protected_routes))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
```

**Step 2: Update src/main.rs**

```rust
mod auth;
mod config;
mod db;
mod error;
mod handlers;
mod models;
mod repositories;
mod routes;
mod services;

use config::Config;
use sqlx::PgPool;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arbak=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    tracing::info!("Configuration loaded");

    // Create database pool
    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Database pool created");

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Database migrations applied");

    // Create app state
    let state = AppState {
        pool,
        config: config.clone(),
    };

    // Create router
    let app = routes::create_router(state);

    // Start server
    let addr = config.server_addr();
    tracing::info!("Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add src/routes.rs src/main.rs
git commit -m "feat: add router and main application entry point"
```

---

## Phase 7: Integration Testing Setup

### Task 7.1: Create Test Helpers

**Files:**
- Create: `tests/common/mod.rs`

**Step 1: Create tests directory and common module**

```rust
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
```

**Step 2: Verify build**

Run: `cargo build`
Expected: Compiles (tests not run yet)

**Step 3: Commit**

```bash
git add tests/
git commit -m "test: add test helpers for integration tests"
```

---

### Task 7.2: Create Auth Integration Tests

**Files:**
- Create: `tests/integration/auth_tests.rs`
- Create: `tests/integration/mod.rs`

**Step 1: Create tests/integration/mod.rs**

```rust
mod auth_tests;
```

**Step 2: Create tests/integration/auth_tests.rs**

```rust
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common {
    include!("../common/mod.rs");
}

use common::{create_test_state, setup_test_db};

async fn make_request(
    app: axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {}", t));
    }

    let body = body
        .map(|v| Body::from(serde_json::to_string(&v).unwrap()))
        .unwrap_or(Body::empty());

    let response = app.oneshot(req.body(body).unwrap()).await.unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or(json!({}));

    (status, json)
}

#[tokio::test]
async fn test_register_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let unique_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let (status, body) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_register_duplicate_email() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool.clone());
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("dup_{}@example.com", uuid::Uuid::new_v4());

    // First registration
    let (status, _) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second registration with same email
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("already registered"));
}

#[tokio::test]
async fn test_login_success() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("login_{}@example.com", uuid::Uuid::new_v4());

    // Register first
    make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    // Then login
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app2,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn test_login_wrong_password() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("wrongpw_{}@example.com", uuid::Uuid::new_v4());

    // Register
    make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    // Login with wrong password
    let app2 = arbak::routes::create_router(state);
    let (status, _) = make_request(
        app2,
        "POST",
        "/api/auth/login",
        Some(json!({
            "email": &unique_email,
            "password": "wrongpassword"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_requires_auth() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    let (status, _) = make_request(app, "GET", "/api/auth/me", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_with_valid_token() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state.clone());

    let unique_email = format!("me_{}@example.com", uuid::Uuid::new_v4());

    // Register
    let (_, body) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": &unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    let token = body["access_token"].as_str().unwrap();

    // Get /me
    let app2 = arbak::routes::create_router(state);
    let (status, body) = make_request(app2, "GET", "/api/auth/me", None, Some(token)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"], unique_email);
}
```

**Step 3: Make lib.rs public for tests**

Create `src/lib.rs`:
```rust
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod models;
pub mod repositories;
pub mod routes;
pub mod services;

use config::Config;
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}
```

**Step 4: Update main.rs to use lib**

```rust
use arbak::{config::Config, db, routes, AppState};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arbak=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    tracing::info!("Configuration loaded");

    // Create database pool
    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Database pool created");

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Database migrations applied");

    // Create app state
    let state = AppState {
        pool,
        config: config.clone(),
    };

    // Create router
    let app = routes::create_router(state);

    // Start server
    let addr = config.server_addr();
    tracing::info!("Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Step 5: Verify build and tests compile**

Run: `cargo build --tests`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add src/lib.rs src/main.rs tests/
git commit -m "test: add auth integration tests"
```

---

## Summary

This implementation plan covers:

1. **Phase 1**: Foundation (Cargo.toml, Config, Error handling)
2. **Phase 2**: Database (Migrations, Pool with RLS, Models)
3. **Phase 3**: Authentication (Password hashing, JWT, Middleware)
4. **Phase 4**: Repositories (User, Role, Document)
5. **Phase 5**: Services (Auth service)
6. **Phase 6**: HTTP Layer (Handlers, Routes, Main)
7. **Phase 7**: Integration Testing

**Total Tasks:** ~15 bite-sized tasks
**Estimated commits:** 15+

Each task follows TDD principles where applicable and includes explicit verification steps.
