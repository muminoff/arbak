use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    db::AuthenticatedConnection,
    error::{AppError, AppResult, ErrorResponse},
    models::{
        CreateDocument, Document, DocumentAccess, PaginationMeta, PaginationParams,
        ShareDocument, UpdateDocument,
    },
    repositories::DocumentRepository,
    AppState,
};

/// Paginated list of documents accessible to the current user
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentListResponse {
    /// Array of documents for the current page
    pub data: Vec<Document>,
    /// Pagination metadata
    pub pagination: PaginationMeta,
}

/// Single document with full details
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentResponse {
    /// Document object with all fields
    pub data: Document,
}

/// Document sharing permission details
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentAccessResponse {
    /// Access grant details including permissions
    pub data: DocumentAccess,
}

/// Confirmation of successful deletion
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DeleteResponse {
    /// Success message confirming the operation
    #[schema(example = "Document deleted")]
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/api/documents",
    tag = "documents",
    operation_id = "listDocuments",
    summary = "List accessible documents",
    description = "Returns a paginated list of documents the authenticated user can access. This includes documents \
                   they own, documents shared with them, and public documents. Results are filtered by PostgreSQL RLS policies.",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "Documents retrieved successfully with pagination metadata.", body = DocumentListResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse)
    )
)]
async fn list_documents(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<DocumentListResponse>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;

    let limit = pagination.limit();
    let offset = pagination.offset();

    let docs = DocumentRepository::find_all(conn.executor(), limit, offset).await?;
    let total_items = DocumentRepository::count(conn.executor()).await?;
    conn.commit().await?;

    Ok(Json(DocumentListResponse {
        data: docs,
        pagination: PaginationMeta::new(pagination.page, limit, total_items),
    }))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}",
    tag = "documents",
    operation_id = "getDocumentById",
    summary = "Get document by ID",
    description = "Retrieves a single document by its unique identifier. Returns 404 if the document doesn't exist \
                   or if the user doesn't have permission to view it (RLS will hide inaccessible documents).",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique document identifier (UUID format, e.g., 550e8400-e29b-41d4-a716-446655440000)")
    ),
    responses(
        (status = 200, description = "Document retrieved successfully", body = DocumentResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 404, description = "Document not found or not accessible to current user", body = ErrorResponse)
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/documents",
    tag = "documents",
    operation_id = "createDocument",
    summary = "Create a new document",
    description = "Creates a new document owned by the authenticated user. The document is private by default \
                   unless is_public is set to true. Returns the created document with generated ID and timestamps.",
    security(("bearer_auth" = [])),
    request_body(
        description = "Document content and metadata",
        content = CreateDocument
    ),
    responses(
        (status = 201, description = "Document created successfully with generated ID and timestamps", body = DocumentResponse),
        (status = 400, description = "Validation error: title is required and cannot be empty", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse)
    )
)]
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

#[utoipa::path(
    put,
    path = "/api/documents/{id}",
    tag = "documents",
    operation_id = "updateDocument",
    summary = "Update a document",
    description = "Updates an existing document. Only the document owner or users with write access can update. \
                   All fields are optional - only provided fields will be updated. Returns the updated document.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique document identifier (UUID format)")
    ),
    request_body(
        description = "Fields to update (all optional, only provided fields are modified)",
        content = UpdateDocument
    ),
    responses(
        (status = 200, description = "Document updated successfully", body = DocumentResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "User does not have write permission for this document", body = ErrorResponse),
        (status = 404, description = "Document not found or not accessible to current user", body = ErrorResponse)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/documents/{id}",
    tag = "documents",
    operation_id = "deleteDocument",
    summary = "Delete a document",
    description = "Permanently deletes a document. Only the document owner or admins with 'document:manage' permission \
                   can delete documents. This action cannot be undone. All sharing permissions are also removed.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique document identifier (UUID format)")
    ),
    responses(
        (status = 200, description = "Document deleted successfully", body = DeleteResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "User does not have permission to delete this document", body = ErrorResponse),
        (status = 404, description = "Document not found or not accessible to current user", body = ErrorResponse)
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/documents/{id}/share",
    tag = "documents",
    operation_id = "shareDocument",
    summary = "Share document with user",
    description = "Grants another user access to a document. Only the document owner can share documents. \
                   You can grant read-only or read-write access. Sharing with a user who already has access \
                   will update their permissions.",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Unique document identifier (UUID format)")
    ),
    request_body(
        description = "User to share with and permission levels",
        content = ShareDocument
    ),
    responses(
        (status = 200, description = "Document shared successfully. Returns the access grant details.", body = DocumentAccessResponse),
        (status = 401, description = "Missing or invalid authentication token", body = ErrorResponse),
        (status = 403, description = "Only the document owner can share documents", body = ErrorResponse),
        (status = 404, description = "Document not found or target user does not exist", body = ErrorResponse)
    )
)]
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
