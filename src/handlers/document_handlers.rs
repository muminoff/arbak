use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    db::AuthenticatedConnection,
    error::{AppError, AppResult, ErrorResponse},
    models::{CreateDocument, Document, DocumentAccess, ShareDocument, UpdateDocument},
    repositories::DocumentRepository,
    AppState,
};

/// Response wrapper for document list
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentListResponse {
    pub data: Vec<Document>,
}

/// Response wrapper for single document
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentResponse {
    pub data: Document,
}

/// Response wrapper for document access
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DocumentAccessResponse {
    pub data: DocumentAccess,
}

/// Response for delete operation
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DeleteResponse {
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/api/documents",
    tag = "documents",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of accessible documents", body = DocumentListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse)
    )
)]
async fn list_documents(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let docs = DocumentRepository::find_all(conn.executor()).await?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": docs })))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}",
    tag = "documents",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 200, description = "Document details", body = DocumentResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 404, description = "Document not found", body = ErrorResponse)
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
    security(("bearer_auth" = [])),
    request_body = CreateDocument,
    responses(
        (status = 200, description = "Document created", body = DocumentResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse)
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
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    request_body = UpdateDocument,
    responses(
        (status = 200, description = "Document updated", body = DocumentResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 404, description = "Document not found", body = ErrorResponse)
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
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 200, description = "Document deleted", body = DeleteResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 404, description = "Document not found", body = ErrorResponse)
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
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    request_body = ShareDocument,
    responses(
        (status = 200, description = "Document shared", body = DocumentAccessResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not document owner", body = ErrorResponse),
        (status = 404, description = "Document not found", body = ErrorResponse)
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
