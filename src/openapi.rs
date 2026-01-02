use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::{
    error::ErrorResponse,
    handlers::{
        auth_handlers::{__path_login, __path_me, __path_refresh, __path_register, UserResponse},
        document_handlers::{
            __path_create_document, __path_delete_document, __path_get_document,
            __path_list_documents, __path_share_document, __path_update_document,
            DeleteResponse, DocumentAccessResponse, DocumentListResponse, DocumentResponse,
        },
        role_handlers::{
            __path_add_permission_to_role, __path_assign_role_to_user, __path_create_role,
            __path_delete_role, __path_get_role, __path_get_role_permissions, __path_get_user_roles,
            __path_list_permissions, __path_list_roles, __path_remove_permission_from_role,
            __path_remove_role_from_user, __path_update_role, AddPermissionToRole,
            PermissionListResponse, RoleAssignmentResponse, RoleDeleteResponse, RoleListResponse,
            RoleResponse, UserRolesDataResponse,
        },
        user_handlers::{
            __path_activate_user, __path_deactivate_user, __path_delete_user, __path_get_user,
            __path_list_users, __path_update_user, UserActionResponse, UserListResponse,
            UserResponse as UserDataResponse,
        },
    },
    models::{
        AssignRole, CreateDocument, CreateRole, CreateUser, Document, DocumentAccess,
        PaginationMeta, Permission, PermissionAction, Role, ShareDocument, UpdateDocument,
        UpdateRole, UpdateUser, User, UserRolesResponse, UserWithRoles,
    },
    services::{AuthResponse, LoginRequest},
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Arbak API",
        description = "A Role-Based Access Control (RBAC) API using PostgreSQL Row-Level Security (RLS) for database-level authorization. \
                       All protected endpoints require a valid JWT token in the Authorization header (Bearer scheme). \
                       Document visibility is automatically enforced by RLS policies - users can only access documents they own, \
                       have been shared with, or are marked as public.",
        version = "0.1.0",
        contact(
            name = "Arbak Team",
            email = "team@arbak.dev"
        ),
        license(name = "Proprietary"),
    ),
    tags(
        (name = "auth", description = "User authentication and session management. Register and login endpoints are public. \
                                        All other endpoints require a valid JWT token in the Authorization header as 'Bearer <token>'. \
                                        Tokens expire after 15 minutes and can be refreshed using the refresh endpoint."),
        (name = "users", description = "User management operations. Users can view and update their own profile. \
                                         Admins can list all users, activate/deactivate accounts, and delete users. \
                                         User roles are managed separately under the roles tag."),
        (name = "documents", description = "Document CRUD operations with Row-Level Security. Access is automatically controlled at the database level - \
                                             users see only documents they own, have explicit access to via sharing, or are marked public. \
                                             Admins with 'document:manage' permission can access all documents."),
        (name = "roles", description = "Role management operations. Roles are used to group permissions and can be assigned to users. \
                                         Most operations require admin privileges. List and get operations are available to all authenticated users."),
        (name = "permissions", description = "Permission management operations. Permissions define what actions can be performed on resources. \
                                               Permissions are assigned to roles, and roles are assigned to users. \
                                               Admin privileges required for modification operations.")
    ),
    paths(
        // Auth
        register,
        login,
        refresh,
        me,
        // Users
        list_users,
        get_user,
        update_user,
        activate_user,
        deactivate_user,
        delete_user,
        // Documents
        list_documents,
        get_document,
        create_document,
        update_document,
        delete_document,
        share_document,
        // Roles
        list_roles,
        get_role,
        create_role,
        update_role,
        delete_role,
        // User roles
        get_user_roles,
        assign_role_to_user,
        remove_role_from_user,
        // Permissions
        list_permissions,
        get_role_permissions,
        add_permission_to_role,
        remove_permission_from_role,
    ),
    components(
        schemas(
            // Auth
            CreateUser,
            LoginRequest,
            AuthResponse,
            UserWithRoles,
            UserResponse,
            // Users
            User,
            UpdateUser,
            UserListResponse,
            UserDataResponse,
            UserActionResponse,
            // Documents
            Document,
            DocumentAccess,
            CreateDocument,
            UpdateDocument,
            ShareDocument,
            DocumentListResponse,
            DocumentResponse,
            DocumentAccessResponse,
            DeleteResponse,
            // Roles
            Role,
            CreateRole,
            UpdateRole,
            AssignRole,
            UserRolesResponse,
            RoleListResponse,
            RoleResponse,
            RoleDeleteResponse,
            RoleAssignmentResponse,
            UserRolesDataResponse,
            // Permissions
            Permission,
            PermissionAction,
            PermissionListResponse,
            AddPermissionToRole,
            // Pagination
            PaginationMeta,
            // Errors
            ErrorResponse,
        )
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}
