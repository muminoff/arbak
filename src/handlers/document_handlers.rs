use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    db::AuthenticatedConnection,
    error::{AppError, AppResult},
    models::{CreateDocument, ShareDocument, UpdateDocument},
    repositories::DocumentRepository,
    AppState,
};

/// GET /api/documents
async fn list_documents(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let mut conn = AuthenticatedConnection::new(&state.pool, claims.sub).await?;
    let docs = DocumentRepository::find_all(conn.executor()).await?;
    conn.commit().await?;

    Ok(Json(serde_json::json!({ "data": docs })))
}

/// GET /api/documents/:id
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

/// POST /api/documents
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

/// PUT /api/documents/:id
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

/// DELETE /api/documents/:id
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

/// POST /api/documents/:id/share
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
