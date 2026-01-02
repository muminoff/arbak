use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Query parameters for paginated, filtered, and sorted document list
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PaginationParams {
    /// Page number (1-indexed)
    #[param(minimum = 1, default = 1, example = 1)]
    #[serde(default = "default_page")]
    pub page: i64,

    /// Number of items per page
    #[param(minimum = 1, maximum = 100, default = 20, example = 20)]
    #[serde(default = "default_per_page")]
    pub per_page: i64,

    /// Search term to filter documents by title or content (case-insensitive)
    #[param(example = "quarterly report")]
    pub search: Option<String>,

    /// Filter by public/private visibility
    #[param(example = true)]
    pub is_public: Option<bool>,

    /// Field to sort by
    #[param(default = "created_at", example = "created_at")]
    #[serde(default = "default_sort_by")]
    pub sort_by: String,

    /// Sort order
    #[param(default = "desc", example = "desc")]
    #[serde(default = "default_sort_order")]
    pub sort_order: String,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    20
}

fn default_sort_by() -> String {
    "created_at".to_string()
}

fn default_sort_order() -> String {
    "desc".to_string()
}

impl PaginationParams {
    /// Calculate the SQL OFFSET value
    pub fn offset(&self) -> i64 {
        (self.page.max(1) - 1) * self.per_page
    }

    /// Get the clamped limit value (1-100)
    pub fn limit(&self) -> i64 {
        self.per_page.clamp(1, 100)
    }

    /// Get validated sort column (prevents SQL injection)
    pub fn sort_column(&self) -> &str {
        match self.sort_by.as_str() {
            "created_at" => "created_at",
            "updated_at" => "updated_at",
            "title" => "title",
            _ => "created_at",
        }
    }

    /// Get validated sort direction
    pub fn sort_direction(&self) -> &str {
        match self.sort_order.to_lowercase().as_str() {
            "asc" => "ASC",
            "desc" => "DESC",
            _ => "DESC",
        }
    }
}

/// Pagination metadata for list responses
#[derive(Debug, Serialize, ToSchema)]
pub struct PaginationMeta {
    /// Current page number
    #[schema(example = 1, minimum = 1)]
    pub page: i64,

    /// Items per page
    #[schema(example = 20, minimum = 1, maximum = 100)]
    pub per_page: i64,

    /// Total number of items across all pages
    #[schema(example = 156)]
    pub total_items: i64,

    /// Total number of pages
    #[schema(example = 8)]
    pub total_pages: i64,
}

impl PaginationMeta {
    pub fn new(page: i64, per_page: i64, total_items: i64) -> Self {
        let total_pages = (total_items + per_page - 1) / per_page;
        Self {
            page,
            per_page,
            total_items,
            total_pages,
        }
    }
}
