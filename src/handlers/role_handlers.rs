use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    error::{AppError, AppResult, ErrorResponse},
    models::{AssignRole, CreateRole, Permission, Role, UpdateRole, UserRolesResponse},
    repositories::{PermissionRepository, RoleRepository, UserRepository},
    AppState,
};

/// List of all roles in the system
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RoleListResponse {
    /// Array of roles
    pub data: Vec<Role>,
}

/// Single role with full details
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RoleResponse {
    /// Role object with all fields
    pub data: Role,
}

/// Confirmation of successful deletion
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RoleDeleteResponse {
    /// Success message confirming the operation
    #[schema(example = "Role deleted")]
    pub message: String,
}

/// User roles response wrapper
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct UserRolesDataResponse {
    /// User roles data
    pub data: UserRolesResponse,
}

/// Role assignment confirmation
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RoleAssignmentResponse {
    /// Success message
    #[schema(example = "Role assigned successfully")]
    pub message: String,
    /// The role that was assigned
    pub role: Role,
}

// ============================================================================
// Role CRUD Operations
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/roles",
    tag = "roles",
    operation_id = "listRoles",
    summary = "List all roles",
    description = "Returns a list of all roles in the system. Requires authentication.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Roles retrieved successfully", body = RoleListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse)
    )
)]
async fn list_roles(
    State(state): State<AppState>,
    AuthUser(_claims): AuthUser,
) -> AppResult<Json<RoleListResponse>> {
    let roles = RoleRepository::find_all(&state.pool).await?;
    Ok(Json(RoleListResponse { data: roles }))
}

#[utoipa::path(
    get,
    path = "/api/roles/{id}",
    tag = "roles",
    operation_id = "getRole",
    summary = "Get role by ID",
    description = "Returns a single role by its ID. Requires authentication.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique role identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "Role retrieved successfully", body = RoleResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse)
    )
)]
async fn get_role(
    State(state): State<AppState>,
    AuthUser(_claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<RoleResponse>> {
    let role = RoleRepository::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(RoleResponse { data: role }))
}

#[utoipa::path(
    post,
    path = "/api/roles",
    tag = "roles",
    operation_id = "createRole",
    summary = "Create a new role",
    description = "Creates a new role in the system. Role names must be unique. \
                   Requires admin privileges.",
    security(("bearer_auth" = [])),
    request_body(
        description = "Role creation data",
        content = CreateRole
    ),
    responses(
        (status = 201, description = "Role created successfully", body = RoleResponse),
        (status = 400, description = "Invalid input or role name already exists", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse)
    )
)]
async fn create_role(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(input): Json<CreateRole>,
) -> AppResult<Json<RoleResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Validate input
    if input.name.trim().is_empty() {
        return Err(AppError::Validation("Role name cannot be empty".to_string()));
    }

    // Check if role name already exists
    if RoleRepository::find_by_name(&state.pool, &input.name)
        .await?
        .is_some()
    {
        return Err(AppError::Validation(
            "Role with this name already exists".to_string(),
        ));
    }

    let role =
        RoleRepository::create(&state.pool, &input.name, input.description.as_deref()).await?;

    Ok(Json(RoleResponse { data: role }))
}

#[utoipa::path(
    put,
    path = "/api/roles/{id}",
    tag = "roles",
    operation_id = "updateRole",
    summary = "Update a role",
    description = "Updates an existing role. Role names must remain unique. \
                   Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique role identifier (UUID format)")
    ),
    request_body(
        description = "Role update data",
        content = UpdateRole
    ),
    responses(
        (status = 200, description = "Role updated successfully", body = RoleResponse),
        (status = 400, description = "Invalid input or role name already exists", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse)
    )
)]
async fn update_role(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateRole>,
) -> AppResult<Json<RoleResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Validate input
    if input.name.trim().is_empty() {
        return Err(AppError::Validation("Role name cannot be empty".to_string()));
    }

    // Check if another role with the same name exists
    if let Some(existing) = RoleRepository::find_by_name(&state.pool, &input.name).await? {
        if existing.id != id {
            return Err(AppError::Validation(
                "Role with this name already exists".to_string(),
            ));
        }
    }

    let role = RoleRepository::update(&state.pool, id, &input.name, input.description.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(RoleResponse { data: role }))
}

#[utoipa::path(
    delete,
    path = "/api/roles/{id}",
    tag = "roles",
    operation_id = "deleteRole",
    summary = "Delete a role",
    description = "Deletes a role from the system. This will also remove the role from all users \
                   who have it assigned. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique role identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "Role deleted successfully", body = RoleDeleteResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse)
    )
)]
async fn delete_role(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<RoleDeleteResponse>> {
    // Check if user has admin role
    let user_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !user_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    let deleted = RoleRepository::delete(&state.pool, id).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    Ok(Json(RoleDeleteResponse {
        message: "Role deleted".to_string(),
    }))
}

// ============================================================================
// User Role Assignment Operations
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/roles",
    tag = "roles",
    operation_id = "getUserRoles",
    summary = "Get user's roles",
    description = "Returns the list of roles assigned to a specific user. Requires authentication.",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = Uuid, Path, description = "User ID to get roles for")
    ),
    responses(
        (status = 200, description = "User roles retrieved successfully", body = UserRolesDataResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse)
    )
)]
async fn get_user_roles(
    State(state): State<AppState>,
    AuthUser(_claims): AuthUser,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserRolesDataResponse>> {
    // Verify user exists
    UserRepository::find_by_id(&state.pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let roles = UserRepository::get_user_roles(&state.pool, user_id).await?;

    Ok(Json(UserRolesDataResponse {
        data: UserRolesResponse { user_id, roles },
    }))
}

#[utoipa::path(
    post,
    path = "/api/users/{user_id}/roles",
    tag = "roles",
    operation_id = "assignRoleToUser",
    summary = "Assign role to user",
    description = "Assigns a role to a user. If the user already has the role, this operation \
                   is idempotent and succeeds. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = Uuid, Path, description = "User ID to assign role to")
    ),
    request_body(
        description = "Role to assign",
        content = AssignRole
    ),
    responses(
        (status = 200, description = "Role assigned successfully", body = RoleAssignmentResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "User or role not found", body = ErrorResponse)
    )
)]
async fn assign_role_to_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(user_id): Path<Uuid>,
    Json(input): Json<AssignRole>,
) -> AppResult<Json<RoleAssignmentResponse>> {
    // Check if user has admin role
    let admin_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !admin_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Verify target user exists
    UserRepository::find_by_id(&state.pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify role exists
    let role = RoleRepository::find_by_id(&state.pool, input.role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Assign the role
    UserRepository::assign_role(&state.pool, user_id, input.role_id).await?;

    Ok(Json(RoleAssignmentResponse {
        message: "Role assigned successfully".to_string(),
        role,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/roles/{role_id}",
    tag = "roles",
    operation_id = "removeRoleFromUser",
    summary = "Remove role from user",
    description = "Removes a role from a user. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = Uuid, Path, description = "User ID to remove role from"),
        ("role_id" = Uuid, Path, description = "Role ID to remove")
    ),
    responses(
        (status = 200, description = "Role removed successfully", body = RoleDeleteResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "User or role not found", body = ErrorResponse)
    )
)]
async fn remove_role_from_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<RoleDeleteResponse>> {
    // Check if user has admin role
    let admin_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !admin_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Verify target user exists
    UserRepository::find_by_id(&state.pool, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify role exists
    RoleRepository::find_by_id(&state.pool, role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Remove the role
    UserRepository::remove_role(&state.pool, user_id, role_id).await?;

    Ok(Json(RoleDeleteResponse {
        message: "Role removed from user".to_string(),
    }))
}

// ============================================================================
// Permission Operations
// ============================================================================

/// List of all permissions in the system
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct PermissionListResponse {
    /// Array of permissions
    pub data: Vec<Permission>,
}

/// Request body for adding permission to role
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AddPermissionToRole {
    /// The ID of the permission to add
    pub permission_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/api/permissions",
    tag = "permissions",
    operation_id = "listPermissions",
    summary = "List all permissions",
    description = "Returns a list of all permissions in the system. Requires authentication.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Permissions retrieved successfully", body = PermissionListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse)
    )
)]
async fn list_permissions(
    State(state): State<AppState>,
    AuthUser(_claims): AuthUser,
) -> AppResult<Json<PermissionListResponse>> {
    let permissions = PermissionRepository::find_all(&state.pool).await?;
    Ok(Json(PermissionListResponse { data: permissions }))
}

#[utoipa::path(
    get,
    path = "/api/roles/{role_id}/permissions",
    tag = "permissions",
    operation_id = "getRolePermissions",
    summary = "Get role's permissions",
    description = "Returns the list of permissions assigned to a specific role. Requires authentication.",
    security(("bearer_auth" = [])),
    params(
        ("role_id" = Uuid, Path, description = "Role ID to get permissions for")
    ),
    responses(
        (status = 200, description = "Role permissions retrieved successfully", body = PermissionListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse)
    )
)]
async fn get_role_permissions(
    State(state): State<AppState>,
    AuthUser(_claims): AuthUser,
    Path(role_id): Path<Uuid>,
) -> AppResult<Json<PermissionListResponse>> {
    // Verify role exists
    RoleRepository::find_by_id(&state.pool, role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let permissions = PermissionRepository::get_role_permissions(&state.pool, role_id).await?;
    Ok(Json(PermissionListResponse { data: permissions }))
}

#[utoipa::path(
    post,
    path = "/api/roles/{role_id}/permissions",
    tag = "permissions",
    operation_id = "addPermissionToRole",
    summary = "Add permission to role",
    description = "Adds a permission to a role. If the role already has the permission, this operation \
                   is idempotent and succeeds. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("role_id" = Uuid, Path, description = "Role ID to add permission to")
    ),
    request_body(
        description = "Permission to add",
        content = AddPermissionToRole
    ),
    responses(
        (status = 200, description = "Permission added successfully", body = PermissionListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role or permission not found", body = ErrorResponse)
    )
)]
async fn add_permission_to_role(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path(role_id): Path<Uuid>,
    Json(input): Json<AddPermissionToRole>,
) -> AppResult<Json<PermissionListResponse>> {
    // Check if user has admin role
    let admin_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !admin_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Verify role exists
    RoleRepository::find_by_id(&state.pool, role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify permission exists
    PermissionRepository::find_by_id(&state.pool, input.permission_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Add the permission
    PermissionRepository::add_permission_to_role(&state.pool, role_id, input.permission_id).await?;

    // Return updated permissions list
    let permissions = PermissionRepository::get_role_permissions(&state.pool, role_id).await?;
    Ok(Json(PermissionListResponse { data: permissions }))
}

#[utoipa::path(
    delete,
    path = "/api/roles/{role_id}/permissions/{permission_id}",
    tag = "permissions",
    operation_id = "removePermissionFromRole",
    summary = "Remove permission from role",
    description = "Removes a permission from a role. Requires admin privileges.",
    security(("bearer_auth" = [])),
    params(
        ("role_id" = Uuid, Path, description = "Role ID to remove permission from"),
        ("permission_id" = Uuid, Path, description = "Permission ID to remove")
    ),
    responses(
        (status = 200, description = "Permission removed successfully", body = RoleDeleteResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role or permission not found", body = ErrorResponse)
    )
)]
async fn remove_permission_from_role(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<RoleDeleteResponse>> {
    // Check if user has admin role
    let admin_roles = UserRepository::get_user_roles(&state.pool, claims.sub).await?;
    if !admin_roles.contains(&"admin".to_string()) {
        return Err(AppError::Forbidden);
    }

    // Verify role exists
    RoleRepository::find_by_id(&state.pool, role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Verify permission exists
    PermissionRepository::find_by_id(&state.pool, permission_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Remove the permission
    PermissionRepository::remove_permission_from_role(&state.pool, role_id, permission_id).await?;

    Ok(Json(RoleDeleteResponse {
        message: "Permission removed from role".to_string(),
    }))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Create role management routes (all protected)
pub fn role_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_roles).post(create_role))
        .route("/:id", get(get_role).put(update_role).delete(delete_role))
        .route(
            "/:role_id/permissions",
            get(get_role_permissions).post(add_permission_to_role),
        )
        .route(
            "/:role_id/permissions/:permission_id",
            delete(remove_permission_from_role),
        )
}

/// Create user role management routes (all protected)
pub fn user_role_routes() -> Router<AppState> {
    Router::new()
        .route("/:user_id/roles", get(get_user_roles).post(assign_role_to_user))
        .route("/:user_id/roles/:role_id", delete(remove_role_from_user))
}

/// Create permission routes (all protected)
pub fn permission_routes() -> Router<AppState> {
    Router::new().route("/", get(list_permissions))
}
