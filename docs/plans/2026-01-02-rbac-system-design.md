# RBAC System Design Document

**Date:** 2026-01-02
**Status:** Validated
**Project:** arbak

---

## Overview

A minimal but production-ready Role-Based Access Control (RBAC) system in Rust using SQLx, Tokio, Axum, and PostgreSQL. Security enforcement happens at the database level via PostgreSQL Row-Level Security (RLS), not in application code.

---

## 1. Core Architecture & Database Design

### Fundamental Approach

- Security enforcement via PostgreSQL Row-Level Security (RLS)
- No WHERE clauses for access control in Rust code
- Fail-secure: if RLS context isn't set, queries return zero rows

### Database Tables

| Table | Purpose |
|-------|---------|
| `users` | User accounts with email/password |
| `roles` | Named permission groups (admin, user, viewer) |
| `permissions` | Resource + action pairs (document:read, user:manage) |
| `role_permissions` | Links roles to permissions |
| `user_roles` | Links users to roles |
| `documents` | Example RLS-protected resource |
| `document_access` | Per-document sharing grants |

### RLS Mechanism

1. App sets `app.current_user_id` session variable on each connection
2. PostgreSQL function `current_user_id()` reads this variable
3. RLS policies use `current_user_id()` to filter rows automatically

### Document Access Rules

- **Read:** Owner OR public OR explicitly shared OR has `document:read` permission
- **Create:** Has `document:create` permission AND sets self as owner
- **Update:** Owner OR has write access OR has `document:update` permission
- **Delete:** Owner OR has `document:delete` permission

---

## 2. Authentication & RLS Context Flow

### JWT Authentication

1. Client POSTs credentials to `/auth/login`
2. Server validates against DB, generates JWT with user_id, email, roles
3. Token expires in 15 minutes (use refresh tokens for longer sessions)

### Per-Request RLS Context

1. Middleware extracts & validates JWT from `Authorization: Bearer <token>`
2. Begins transaction
3. Executes `SET LOCAL app.current_user_id = '<user_uuid>'`
4. Handler queries execute (RLS auto-filters)
5. Commits transaction

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Token storage | Client-side only | Stateless, scalable |
| Token lifetime | 15 minutes | Short-lived for security |
| RLS context scope | Transaction-level | `SET LOCAL` ensures isolation |
| Password hashing | Argon2id | Current best practice |

### AuthenticatedConnection

A wrapper type that ensures RLS context is always set before any query executes. This is the security linchpin.

---

## 3. Project Structure

```
arbak/
├── Cargo.toml
├── .env
├── migrations/
│   └── 001_initial_schema.sql
├── src/
│   ├── main.rs              # Server bootstrap
│   ├── lib.rs               # Public API for testing
│   ├── config.rs            # Environment variables
│   ├── error.rs             # Unified AppError
│   ├── db/
│   │   ├── mod.rs
│   │   └── pool.rs          # Connection pool, AuthenticatedConnection
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs           # Token encode/decode
│   │   ├── password.rs      # Argon2 hashing
│   │   └── middleware.rs    # JWT extraction, RLS context
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── role.rs
│   │   ├── permission.rs
│   │   └── document.rs
│   ├── repositories/
│   │   ├── mod.rs
│   │   ├── user_repo.rs
│   │   ├── role_repo.rs
│   │   └── document_repo.rs
│   ├── services/
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   └── document_service.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── auth_handlers.rs
│   │   ├── user_handlers.rs
│   │   └── document_handlers.rs
│   └── routes.rs
└── tests/
    ├── common/
    │   └── mod.rs
    └── integration/
        ├── auth_tests.rs
        └── rbac_tests.rs
```

### Layer Responsibilities

| Layer | Purpose |
|-------|---------|
| `handlers/` | HTTP request/response translation |
| `services/` | Business logic, orchestration |
| `repositories/` | Database queries (no business logic) |
| `models/` | Data structures matching DB tables |
| `db/` | Connection management, RLS context |
| `auth/` | Security primitives |

---

## 4. API Design

### Endpoints

#### Authentication (Public)
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Get JWT
- `POST /api/auth/refresh` - Renew JWT
- `GET /api/auth/me` - Current user info (authenticated)

#### Users (Admin only)
- `GET /api/users` - List users
- `GET /api/users/:id` - Get user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `POST /api/users/:id/roles` - Assign role
- `DELETE /api/users/:id/roles/:role_id` - Remove role

#### Roles (Admin only)
- `GET /api/roles` - List roles
- `POST /api/roles` - Create role
- `PUT /api/roles/:id` - Update role
- `DELETE /api/roles/:id` - Delete role
- `POST /api/roles/:id/permissions` - Add permission

#### Documents (RLS-protected)
- `GET /api/documents` - List (auto-filtered by RLS)
- `POST /api/documents` - Create
- `GET /api/documents/:id` - Get single
- `PUT /api/documents/:id` - Update
- `DELETE /api/documents/:id` - Delete
- `POST /api/documents/:id/share` - Share with user

### Error Handling

| Error Type | HTTP Status | When |
|------------|-------------|------|
| `Unauthorized` | 401 | Missing/invalid JWT |
| `Forbidden` | 403 | Valid JWT but no permission |
| `NotFound` | 404 | Resource doesn't exist (or hidden by RLS) |
| `Validation` | 400 | Invalid request data |
| `Database` | 500 | SQLx errors (logged, not exposed) |
| `Internal` | 500 | Unexpected errors |

### Response Format

```json
// Success
{ "data": { ... } }

// Error
{ "error": "Human-readable message" }
```

---

## 5. Testing Strategy

### Three-Tier Approach

1. **Unit Tests** - JWT, password hashing, validation (no DB)
2. **Repository Tests** - Direct DB with AuthenticatedConnection
3. **Integration Tests** - Full HTTP → Axum → DB with RLS

### Critical RLS Test Scenarios

| Scenario | Expected |
|----------|----------|
| User A queries User B's private doc | Empty / 404 |
| User A queries public doc | Returns doc |
| User A queries doc shared with them | Returns doc |
| Admin queries any doc | Returns doc |
| No RLS context set | Zero rows |
| User creates doc with wrong owner_id | Insert fails |

### Test Database

- Dedicated test database with same schema + RLS
- Each test runs in transaction, rolled back after
- Seed data: 3 roles + permissions

---

## 6. Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "postgres", "uuid", "chrono", "migrate"] }
jsonwebtoken = "9"
argon2 = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
```

---

## 7. Out of Scope

- OAuth/social login
- Email verification
- Password reset flow
- Rate limiting
- Audit logging
- Multi-tenancy
- Caching layer
- GraphQL

---

## 8. Success Criteria

1. User can register, login, and receive JWT
2. Authenticated requests automatically have RLS context set
3. Users only see documents they have access to
4. Admin users can manage all resources
5. All SQL queries are compile-time checked via SQLx macros
6. Zero application-level WHERE clauses for access control
