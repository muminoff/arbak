use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};

use crate::{
    auth::{decode_token, Claims},
    error::{AppError, AppResult},
    AppState,
};

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(request: &Request) -> AppResult<&str> {
    let header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    // RFC 7235: Authorization scheme is case-insensitive
    if header.len() >= 7 && header[..7].eq_ignore_ascii_case("bearer ") {
        Ok(&header[7..])
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Middleware that validates JWT and stores claims in request extensions.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&request)?;
    let claims = decode_token(token, &state.config.jwt_secret)?;

    // Store claims in request extensions for handlers to access
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extractor for getting claims in handlers.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(AuthUser)
            .ok_or(AppError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    fn make_request_with_auth(auth_value: &str) -> Request<Body> {
        Request::builder()
            .header(AUTHORIZATION, auth_value)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_without_auth() -> Request<Body> {
        Request::builder().body(Body::empty()).unwrap()
    }

    #[test]
    fn test_extract_bearer_token_valid() {
        let request = make_request_with_auth("Bearer valid.token.here");
        let result = extract_bearer_token(&request);
        assert_eq!(result.unwrap(), "valid.token.here");
    }

    #[test]
    fn test_extract_bearer_token_case_insensitive() {
        let request = make_request_with_auth("bearer valid.token.here");
        let result = extract_bearer_token(&request);
        assert_eq!(result.unwrap(), "valid.token.here");

        let request = make_request_with_auth("BEARER valid.token.here");
        let result = extract_bearer_token(&request);
        assert_eq!(result.unwrap(), "valid.token.here");
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        let request = make_request_without_auth();
        let result = extract_bearer_token(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_bearer_token_missing_prefix() {
        let request = make_request_with_auth("Basic dXNlcjpwYXNz");
        let result = extract_bearer_token(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_bearer_token_empty_token() {
        let request = make_request_with_auth("Bearer ");
        let result = extract_bearer_token(&request);
        assert_eq!(result.unwrap(), "");
    }
}
