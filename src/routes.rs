use axum::{middleware, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{auth::auth_middleware, handlers, openapi::ApiDoc, AppState};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let (auth_public, auth_protected) = handlers::auth_routes();

    // Public routes (no auth required)
    let public_routes = Router::new().nest("/auth", auth_public);

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .nest("/auth", auth_protected)
        .nest("/documents", handlers::document_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Combine all routes under /api
    Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .nest("/api", public_routes.merge(protected_routes))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
