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
        description = "RBAC with PostgreSQL Row-Level Security",
        version = "0.1.0",
        license(name = "Proprietary"),
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "documents", description = "Document management endpoints")
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
