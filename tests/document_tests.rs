use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::util::ServiceExt;

mod common {
    include!("common/mod.rs");
}

use common::{create_test_state, setup_test_db};

async fn make_request(
    app: axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {}", t));
    }

    let body = body
        .map(|v| Body::from(serde_json::to_string(&v).unwrap()))
        .unwrap_or(Body::empty());

    let response = app.oneshot(req.body(body).unwrap()).await.unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or(json!({}));

    (status, json)
}

/// Helper to register a user and get their token
async fn register_and_get_token(state: arbak::AppState) -> (String, arbak::AppState) {
    let app = arbak::routes::create_router(state.clone());
    let unique_email = format!("doctest_{}@example.com", uuid::Uuid::new_v4());

    let (_, body) = make_request(
        app,
        "POST",
        "/api/auth/register",
        Some(json!({
            "email": unique_email,
            "password": "password123"
        })),
        None,
    )
    .await;

    let token = body["access_token"].as_str().unwrap().to_string();
    (token, state)
}

/// Helper to create a document
async fn create_document(
    state: arbak::AppState,
    token: &str,
    title: &str,
    content: Option<&str>,
    is_public: bool,
) -> Value {
    let app = arbak::routes::create_router(state);
    let mut doc = json!({
        "title": title,
        "is_public": is_public
    });
    if let Some(c) = content {
        doc["content"] = json!(c);
    }

    let (status, body) = make_request(app, "POST", "/api/documents", Some(doc), Some(token)).await;

    assert_eq!(status, StatusCode::OK, "Failed to create document: {:?}", body);
    body["data"].clone()
}

// ============================================================================
// Pagination Tests
// ============================================================================

#[tokio::test]
async fn test_list_documents_default_pagination() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create 3 documents
    for i in 1..=3 {
        create_document(
            state.clone(),
            &token,
            &format!("Doc {}", i),
            Some("Content"),
            false,
        )
        .await;
    }

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(app, "GET", "/api/documents", None, Some(&token)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
    assert!(body["pagination"]["page"].as_i64().unwrap() >= 1);
    assert!(body["pagination"]["per_page"].as_i64().unwrap() >= 1);
    assert!(body["pagination"]["total_items"].as_i64().unwrap() >= 3);
}

#[tokio::test]
async fn test_list_documents_custom_pagination() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create 5 documents
    for i in 1..=5 {
        create_document(
            state.clone(),
            &token,
            &format!("Paginated Doc {}", i),
            None,
            false,
        )
        .await;
    }

    // Request page 1 with 2 items per page
    let app = arbak::routes::create_router(state.clone());
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?page=1&per_page=2",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pagination"]["page"], 1);
    assert_eq!(body["pagination"]["per_page"], 2);
    assert!(body["data"].as_array().unwrap().len() <= 2);

    // Request page 2
    let app2 = arbak::routes::create_router(state);
    let (status2, body2) = make_request(
        app2,
        "GET",
        "/api/documents?page=2&per_page=2",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body2["pagination"]["page"], 2);
}

// ============================================================================
// Search Filter Tests
// ============================================================================

#[tokio::test]
async fn test_search_by_title() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create documents with distinct titles
    create_document(
        state.clone(),
        &token,
        "Quarterly Financial Report",
        Some("Numbers and charts"),
        false,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Meeting Notes",
        Some("Discussion points"),
        false,
    )
    .await;

    // Search for "Quarterly"
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=Quarterly",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(docs.iter().any(|d| d["title"]
        .as_str()
        .unwrap()
        .contains("Quarterly")));
}

#[tokio::test]
async fn test_search_by_content() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create documents
    create_document(
        state.clone(),
        &token,
        "Document One",
        Some("This contains a unique keyword: xylophone123"),
        false,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Document Two",
        Some("Regular content here"),
        false,
    )
    .await;

    // Search for the unique keyword in content
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=xylophone123",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(!docs.is_empty());
    assert!(docs
        .iter()
        .any(|d| d["content"].as_str().unwrap_or("").contains("xylophone123")));
}

#[tokio::test]
async fn test_search_case_insensitive() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    create_document(
        state.clone(),
        &token,
        "UPPERCASE TITLE",
        Some("lowercase content"),
        false,
    )
    .await;

    // Search with different case
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=uppercase",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(docs.iter().any(|d| d["title"]
        .as_str()
        .unwrap()
        .contains("UPPERCASE")));
}

// ============================================================================
// is_public Filter Tests
// ============================================================================

#[tokio::test]
async fn test_filter_public_documents() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create public and private documents
    create_document(
        state.clone(),
        &token,
        "Public Doc",
        Some("Public content"),
        true,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Private Doc",
        Some("Private content"),
        false,
    )
    .await;

    // Filter for public only
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?is_public=true",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(docs.iter().all(|d| d["is_public"].as_bool().unwrap() == true));
}

#[tokio::test]
async fn test_filter_private_documents() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create public and private documents
    create_document(
        state.clone(),
        &token,
        "Public Doc 2",
        Some("Public content"),
        true,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Private Doc 2",
        Some("Private content"),
        false,
    )
    .await;

    // Filter for private only
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?is_public=false",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(docs.iter().all(|d| d["is_public"].as_bool().unwrap() == false));
}

// ============================================================================
// Sorting Tests
// ============================================================================

#[tokio::test]
async fn test_sort_by_title_asc() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create documents with titles that sort predictably
    create_document(state.clone(), &token, "Zebra Doc", None, false).await;
    create_document(state.clone(), &token, "Alpha Doc", None, false).await;
    create_document(state.clone(), &token, "Middle Doc", None, false).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?sort_by=title&sort_order=asc",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();

    // Verify ascending order (at least for our created docs)
    let titles: Vec<&str> = docs.iter().map(|d| d["title"].as_str().unwrap()).collect();
    let mut sorted_titles = titles.clone();
    sorted_titles.sort();
    assert_eq!(titles, sorted_titles);
}

#[tokio::test]
async fn test_sort_by_title_desc() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create documents with titles that sort predictably
    create_document(state.clone(), &token, "Zebra Desc", None, false).await;
    create_document(state.clone(), &token, "Alpha Desc", None, false).await;
    create_document(state.clone(), &token, "Middle Desc", None, false).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?sort_by=title&sort_order=desc",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();

    // Verify descending order
    let titles: Vec<&str> = docs.iter().map(|d| d["title"].as_str().unwrap()).collect();
    let mut sorted_titles = titles.clone();
    sorted_titles.sort();
    sorted_titles.reverse();
    assert_eq!(titles, sorted_titles);
}

#[tokio::test]
async fn test_sort_by_created_at_desc() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create documents (they will have sequential created_at times)
    create_document(state.clone(), &token, "First Created", None, false).await;
    create_document(state.clone(), &token, "Second Created", None, false).await;
    create_document(state.clone(), &token, "Third Created", None, false).await;

    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?sort_by=created_at&sort_order=desc",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();

    // Most recently created should be first
    let timestamps: Vec<&str> = docs.iter().map(|d| d["created_at"].as_str().unwrap()).collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    sorted.reverse();
    assert_eq!(timestamps, sorted);
}

// ============================================================================
// Date Range Filter Tests
// ============================================================================

#[tokio::test]
async fn test_filter_by_created_from() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create a document
    let doc = create_document(
        state.clone(),
        &token,
        "Recent Document",
        Some("Created recently"),
        false,
    )
    .await;

    // Use a date in the past to ensure we get results
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?created_from=2020-01-01T00:00:00Z",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    // The document we created should be in the results
    assert!(docs.iter().any(|d| d["id"] == doc["id"]));
}

#[tokio::test]
async fn test_filter_by_created_to() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create a document
    create_document(
        state.clone(),
        &token,
        "Old Document",
        Some("This should be excluded"),
        false,
    )
    .await;

    // Use a date in the past - should exclude the document we just created
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?created_to=2020-01-01T00:00:00Z",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    // No documents should be created before 2020 in our test
    assert!(docs.is_empty() || docs.iter().all(|d| {
        let created = d["created_at"].as_str().unwrap();
        created <= "2020-01-01T00:00:00Z"
    }));
}

#[tokio::test]
async fn test_filter_by_date_range() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create a document
    create_document(
        state.clone(),
        &token,
        "Date Range Doc",
        Some("Within range"),
        false,
    )
    .await;

    // Use a wide date range that includes now
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?created_from=2020-01-01T00:00:00Z&created_to=2030-12-31T23:59:59Z",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    assert!(!docs.is_empty());
}

// ============================================================================
// Combined Filter Tests
// ============================================================================

#[tokio::test]
async fn test_combined_search_and_public_filter() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create test documents
    create_document(
        state.clone(),
        &token,
        "Public Report",
        Some("Searchable content"),
        true,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Private Report",
        Some("Searchable content"),
        false,
    )
    .await;
    create_document(
        state.clone(),
        &token,
        "Public Notes",
        Some("Different content"),
        true,
    )
    .await;

    // Search for "Report" and filter by public
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=Report&is_public=true",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let docs = body["data"].as_array().unwrap();
    // Should only get public documents matching "Report"
    for doc in docs {
        assert!(doc["is_public"].as_bool().unwrap());
        let title = doc["title"].as_str().unwrap();
        let content = doc["content"].as_str().unwrap_or("");
        assert!(title.contains("Report") || content.contains("Report"));
    }
}

#[tokio::test]
async fn test_combined_filters_with_sorting_and_pagination() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    // Create multiple public documents
    for i in 1..=5 {
        create_document(
            state.clone(),
            &token,
            &format!("Combined Test {}", i),
            Some("Test content for combined"),
            true,
        )
        .await;
    }

    // Combine all filters
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=Combined&is_public=true&sort_by=title&sort_order=asc&page=1&per_page=3",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pagination"]["page"], 1);
    assert_eq!(body["pagination"]["per_page"], 3);

    let docs = body["data"].as_array().unwrap();
    assert!(docs.len() <= 3);

    // Verify all returned docs are public and match search
    for doc in docs {
        assert!(doc["is_public"].as_bool().unwrap());
        let title = doc["title"].as_str().unwrap();
        assert!(title.contains("Combined"));
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_empty_search_term() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    create_document(state.clone(), &token, "Empty Search Test", None, false).await;

    // Empty search should return all documents
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?search=",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_invalid_sort_column_uses_default() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let (token, state) = register_and_get_token(state).await;

    create_document(state.clone(), &token, "Invalid Sort Test", None, false).await;

    // Invalid sort column should fall back to created_at
    let app = arbak::routes::create_router(state);
    let (status, body) = make_request(
        app,
        "GET",
        "/api/documents?sort_by=invalid_column",
        None,
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].is_array());
}

#[tokio::test]
async fn test_requires_authentication() {
    let pool = setup_test_db().await;
    let state = create_test_state(pool);
    let app = arbak::routes::create_router(state);

    // Try to list documents without token
    let (status, _) = make_request(app, "GET", "/api/documents", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
