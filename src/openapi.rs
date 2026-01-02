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
    },
    models::{
        CreateDocument, CreateUser, Document, DocumentAccess, ShareDocument, UpdateDocument,
        UserWithRoles,
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
        (name = "documents", description = "Document CRUD operations with Row-Level Security. Access is automatically controlled at the database level - \
                                             users see only documents they own, have explicit access to via sharing, or are marked public. \
                                             Admins with 'document:manage' permission can access all documents.")
    ),
    paths(
        register,
        login,
        refresh,
        me,
        list_documents,
        get_document,
        create_document,
        update_document,
        delete_document,
        share_document,
    ),
    components(
        schemas(
            // Auth
            CreateUser,
            LoginRequest,
            AuthResponse,
            UserWithRoles,
            UserResponse,
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
