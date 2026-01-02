# Project Overview: Arbak

## Purpose
Arbak is a Rust-based web API implementing Role-Based Access Control (RBAC) with Row-Level Security (RLS) for document management.

## Tech Stack
- **Language**: Rust 2021 edition
- **Web Framework**: Axum 0.7
- **Database**: PostgreSQL with SQLx 0.8 (with RLS policies)
- **Authentication**: JWT (jsonwebtoken) + Argon2 password hashing
- **Async Runtime**: Tokio
- **Serialization**: Serde

## Key Features
- User authentication with JWT tokens
- Role-based access control
- Document management with RLS protection
- Permission-based authorization

## Architecture
- `src/auth/` - Authentication (JWT, middleware, password handling)
- `src/db/` - Database pool management
- `src/models/` - Data models (User, Role, Permission, Document)
- `src/repositories/` - Data access layer
- `src/error.rs` - Error handling with AppResult type
- `src/config.rs` - Configuration
