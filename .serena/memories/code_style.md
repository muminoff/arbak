# Code Style and Conventions

## Repository Pattern
- Repositories are struct-based with static methods
- Use `AppResult<T>` as return type
- Use `sqlx::query_as` for typed results
- Use `sqlx::query_scalar` for single-value results
- SQL queries use raw string literals `r#"..."#`

## Documentation
- Use `///` doc comments for public functions
- Short, descriptive comments explaining purpose

## Naming
- Snake_case for functions and variables
- PascalCase for types/structs
- Use descriptive names (find_by_id, create, update, delete)

## Error Handling
- Use `AppError` enum from `src/error.rs`
- `?` operator for propagating errors
- `AppResult<T>` type alias for `Result<T, AppError>`

## SQL Patterns
- RETURNING clause for INSERT/UPDATE operations
- ON CONFLICT for upserts
- Bind parameters with `$1`, `$2`, etc.

## Transactions
- Document repository uses `Transaction<'_, Postgres>` for RLS context
- User/Role repos use `PgPool` directly
