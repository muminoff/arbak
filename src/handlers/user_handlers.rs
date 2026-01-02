use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::{
    auth::{hash_password, AuthUser},
    error::{AppError, AppResult, ErrorResponse},
    models::{PaginationMeta, UpdateUser, User, UserWithRoles},
    repositories::UserRepository,
    AppState,
};

/// Query parameters for user list
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserListParams {
    /// Page number (1-indexed)
    #[param(minimum = 1, default = 1, example = 1)]
    #[serde(default = "default_page")]
    pub page: i64,

    /// Number of items per page
    #[param(minimum = 1, maximum = 100, default = 20, example = 20)]
    #[serde(default = "default_per_page")]
    pub per_page: i64,

    /// Search term to filter users by email (case-insensitive)
    #[param(example = "admin@")]
    pub search: Option<String>,

    /// Filter by active status
    #[param(example = true)]
    pub is_active: Option<bool>,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    20
}

impl UserListParams {
    pub fn offset(&self) -> i64 {
        (self.page.max(1) - 1) * self.per_page
    }

    pub fn limit(&self) -> i64 {
        self.per_page.clamp(1, 100)
    }
}

/// Paginated list of users
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserListResponse {
    /// Array of users for the current page
    pub data: Vec<User>,
    /// Pagination metadata
    pub pagination: PaginationMeta,
}

/// Single user response
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    /// User object with all fields
    pub data: UserWithRoles,
}

/// User deletion/action confirmation
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserActionResponse {
    /// Success message
    #[schema(example = "User deleted")]
    pub message: String,
}

// ============================================================================
// User List and Get
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "users",
    operation_id = "listUsers",
    summary = "List all users",
    description = "Returns a paginated list of all users. Requires admin privileges. \
                   Use 'search' to filter by email, 'is_active' to filter by status.",
    security(("bearer_auth" = [])),
    params(UserListParams),
    responses(
        (status = 200, description = "Users retrieved successfully", body = UserListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Admin privileges required", body = ErrorResponse)
    )
)]
async fn list_users(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(params): Query<UserListParams>,
) -> AppResult<Json<UserListResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    let limit = params.limit();
    let offset = params.offset();
    let search = params.search.as_deref();
    let is_active = params.is_active;

    let users = UserRepository::find_all(&state.pool, limit, offset, search, is_active).await?;
    let total = UserRepository::count(&state.pool, search, is_active).await?;

    let pagination = PaginationMeta::new(params.page, params.per_page, total);

    Ok(Json(UserListResponse {
        data: users,
        pagination,
    }))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "users",
    operation_id = "getUser",
    summary = "Get user by ID",
    description = "Returns a single user by their ID, including their assigned roles. \
                   Users can view their own profile. Admins can view any user.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique user identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "User retrieved successfully", body = UserResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Cannot view other users without admin privileges", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn get_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    // Users can view themselves, admins can view anyone
    if claims.sub != id {
        let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
        if !user_roles.contains(&"admin".to_string()) {
            return Err(AppError::Forbidden);
        }
    }

    let user = UserRepository::get_with_roles(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse { data: user }))
}

// ============================================================================
// User Update
// ============================================================================

#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "users",
    operation_id = "updateUser",
    summary = "Update user",
    description = "Updates a user's profile. Users can update their own email and password. \
                   Admins can update any user and also modify the is_active status.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique user identifier (UUID format)")
    ),
    request_body(
        description = "User update data. All fields are optional.",
        content = UpdateUser
    ),
    responses(
        (status = 200, description = "User updated successfully", body = UserResponse),
        (status = 400, description = "Invalid input (e.g., email already taken, password too short)", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Cannot update other users without admin privileges", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn update_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateUser>,
) -> AppResult<Json<UserResponse>> {
    let is_admin = {
        let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
        user_roles.contains(&"admin".to_string())
    };

    // Users can update themselves, admins can update anyone
    if claims.sub != id && !is_admin {
        return Err(AppError::Forbidden);
    }

    // Non-admins cannot change is_active status
    if input.is_active.is_some() && !is_admin {
        return Err(AppError::Forbidden);
    }

    // Verify user exists
    UserRepository::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Update email if provided
    if let Some(ref email) = input.email {
        if email.trim().is_empty() {
            return Err(AppError::Validation("Email cannot be empty".to_string()));
        }

        // Check if email is already taken by another user
        if let Some(existing) = UserRepository::find_by_email(&state.pool, email).await? {
            if existing.id != id {
                return Err(AppError::Validation(
                    "Email is already registered".to_string(),
                ));
            }
        }

        UserRepository::update_email(&state.pool, id, email).await?;
    }

    // Update password if provided
    if let Some(ref password) = input.password {
        if password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let password_hash = hash_password(password)?;
        UserRepository::update_password(&state.pool, id, &password_hash).await?;
    }

    // Update is_active if provided (admin only, already checked above)
    if let Some(is_active) = input.is_active {
        UserRepository::set_active(&state.pool, id, is_active).await?;
    }

    // Return updated user
    let user = UserRepository::get_with_roles(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse { data: user }))
}

// ============================================================================
// User Activation/Deactivation
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/users/{id}/activate",
    tag = "users",
    operation_id = "activateUser",
    summary = "Activate user",
    description = "Activates a user account, allowing them to log in. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique user identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "User activated successfully", body = UserResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Admin privileges required", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn activate_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Verify user exists
    UserRepository::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    UserRepository::set_active(&state.pool, id, true).await?;

    let user = UserRepository::get_with_roles(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse { data: user }))
}

#[utoipa::path(
    post,
    path = "/api/users/{id}/deactivate",
    tag = "users",
    operation_id = "deactivateUser",
    summary = "Deactivate user",
    description = "Deactivates a user account, preventing them from logging in. \
                   Requires admin privileges. Admins cannot deactivate themselves.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique user identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "User deactivated successfully", body = UserResponse),
        (status = 400, description = "Cannot deactivate yourself", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Admin privileges required", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn deactivate_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Prevent self-deactivation
    if claims.sub == id {
        return Err(AppError::Validation(
            "Cannot deactivate your own account".to_string(),
        ));
    }

    // Verify user exists
    UserRepository::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    UserRepository::set_active(&state.pool, id, false).await?;

    let user = UserRepository::get_with_roles(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse { data: user }))
}

// ============================================================================
// User Delete
// ============================================================================

#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "users",
    operation_id = "deleteUser",
    summary = "Delete user",
    description = "Permanently deletes a user account and all associated data. \
                   Requires admin privileges. Admins cannot delete themselves.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique user identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "User deleted successfully", body = UserActionResponse),
        (status = 400, description = "Cannot delete yourself", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Admin privileges required", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn delete_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<UserActionResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Prevent self-deletion
    if claims.sub == id {
        return Err(AppError::Validation(
            "Cannot delete your own account".to_string(),
        ));
    }

    let deleted = UserRepository::delete(&state.pool, id).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    Ok(Json(UserActionResponse {
        message: "User deleted".to_string(),
    }))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Create user management routes (all protected)
/// Note: /:user_id/roles routes are in role_handlers.rs
pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users))
        .route("/:id", get(get_user).put(update_user).delete(delete_user))
        .route("/:id/activate", axum::routing::post(activate_user))
        .route("/:id/deactivate", axum::routing::post(deactivate_user))
}
