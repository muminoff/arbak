# Arbak - RBAC with PostgreSQL Row-Level Security

A minimal Role-Based Access Control (RBAC) system using PostgreSQL Row-Level Security (RLS) for database-level authorization.

## Features

- JWT-based authentication (HS256, 15-minute expiration)
- Argon2 password hashing
- PostgreSQL RLS for automatic row filtering
- Role-based permissions
- Document sharing between users

## Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 14+ (Postgres.app or similar)

### Database Setup

```bash
# Create database and user
psql -c "CREATE USER app_user WITH PASSWORD 'password';"
psql -c "CREATE DATABASE arbak_db OWNER app_user;"
psql -c "GRANT ALL PRIVILEGES ON DATABASE arbak_db TO app_user;"
```

### Environment

Create `.env` file:

```env
DATABASE_URL=postgres:///arbak_db?host=/tmp&user=app_user
JWT_SECRET=your-256-bit-secret-key-here-minimum-32-chars
JWT_EXPIRATION_SECONDS=900
RUST_LOG=info,sqlx=warn
HOST=0.0.0.0
PORT=3000
```

### Run

```bash
cargo run
```

Migrations run automatically on startup.

## API Reference

### Authentication

#### Register
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "john",
  "email": "john@example.com",
  "password": "securepass123"
}
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepass123"
}
```

#### Get Current User
```bash
GET /api/auth/me
Authorization: Bearer <token>
```

#### Refresh Token
```bash
POST /api/auth/refresh
Authorization: Bearer <token>
```

### Documents

All document endpoints require authentication.

#### List Documents
```bash
GET /api/documents
Authorization: Bearer <token>
```

Returns only documents the user can access:
- Documents they own
- Public documents
- Documents shared with them

#### Get Document
```bash
GET /api/documents/:id
Authorization: Bearer <token>
```

#### Create Document
```bash
POST /api/documents
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My Document",
  "content": "Document content here",
  "is_public": false
}
```

#### Update Document
```bash
PUT /api/documents/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content",
  "is_public": true
}
```

#### Delete Document
```bash
DELETE /api/documents/:id
Authorization: Bearer <token>
```

#### Share Document
```bash
POST /api/documents/:id/share
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": "uuid-of-user-to-share-with",
  "can_read": true,
  "can_write": false
}
```

## Row-Level Security

RLS policies automatically filter database rows based on the authenticated user. The application sets `app.current_user_id` session variable on each request.

### Document Visibility Rules

| Condition | Can Read | Can Update | Can Delete |
|-----------|----------|------------|------------|
| Owner | Yes | Yes | Yes |
| Public document | Yes | No | No |
| Shared (can_read) | Yes | No | No |
| Shared (can_write) | Yes | Yes | No |
| Admin (document:manage) | Yes | Yes | Yes |

### How It Works

1. User authenticates and receives JWT
2. Each API request includes JWT in Authorization header
3. Middleware validates JWT and extracts user ID
4. Database connection sets `app.current_user_id` session variable
5. PostgreSQL RLS policies automatically filter rows

```sql
-- Example: documents_select policy
CREATE POLICY documents_select ON documents FOR SELECT USING (
    owner_id = current_user_id()           -- Owner can see
    OR is_public = true                     -- Anyone can see public
    OR has_document_access(id)              -- Shared access
    OR user_has_permission('document', 'manage')  -- Admin override
);
```

## Roles and Permissions

Default roles created by seed data:

| Role | Permissions |
|------|-------------|
| admin | document:manage (full access to all documents) |
| user | document:create, document:read (own docs only) |
| viewer | document:read (own docs only) |

New users are assigned the `user` role by default.

## Architecture

```
src/
├── auth/
│   ├── jwt.rs          # Token encoding/decoding
│   ├── middleware.rs   # Auth middleware, AuthUser extractor
│   └── password.rs     # Argon2 hashing
├── db/
│   └── pool.rs         # AuthenticatedConnection (sets RLS context)
├── handlers/
│   ├── auth_handlers.rs
│   └── document_handlers.rs
├── models/
│   ├── user.rs
│   ├── role.rs
│   └── document.rs
├── repositories/
│   ├── user_repository.rs
│   ├── role_repository.rs
│   └── document_repository.rs
├── services/
│   └── auth_service.rs
├── config.rs
├── error.rs
├── lib.rs
├── main.rs
└── routes.rs
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Example Usage

```bash
# Register a user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"password123"}'

# Save the token
TOKEN="eyJ..."

# Create a private document
curl -X POST http://localhost:3000/api/documents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Private Notes","content":"Secret stuff","is_public":false}'

# Create a public document
curl -X POST http://localhost:3000/api/documents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Public Post","content":"Hello world!","is_public":true}'

# List documents (sees both)
curl http://localhost:3000/api/documents \
  -H "Authorization: Bearer $TOKEN"

# Another user would only see the public document
```

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE) for details.
