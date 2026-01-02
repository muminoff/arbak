pub mod auth_handlers;
pub mod document_handlers;
pub mod role_handlers;

pub use auth_handlers::auth_routes;
pub use document_handlers::document_routes;
pub use role_handlers::{permission_routes, role_routes, user_role_routes};
