use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid, // user_id
    pub email: String,
    pub roles: Vec<String>, // role names (for client-side UI)
    pub exp: i64,           // expiration timestamp
    pub iat: i64,           // issued at
}

impl Claims {
    pub fn new(user_id: Uuid, email: String, roles: Vec<String>, expiration_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id,
            email,
            roles,
            iat: now.timestamp(),
            exp: (now + Duration::seconds(expiration_seconds)).timestamp(),
        }
    }
}

/// Encode claims into a JWT token.
pub fn encode_token(claims: &Claims, secret: &str) -> AppResult<String> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(AppError::from)
}

/// Decode and validate a JWT token.
pub fn decode_token(token: &str, secret: &str) -> AppResult<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_token() {
        let user_id = Uuid::new_v4();
        let claims = Claims::new(
            user_id,
            "test@example.com".to_string(),
            vec!["user".to_string()],
            3600,
        );
        let secret = "test-secret-key-minimum-32-chars!!";

        let token = encode_token(&claims, secret).unwrap();
        let decoded = decode_token(&token, secret).unwrap();

        assert_eq!(decoded.sub, user_id);
        assert_eq!(decoded.email, "test@example.com");
        assert_eq!(decoded.roles, vec!["user"]);
    }

    #[test]
    fn test_invalid_token_fails() {
        let secret = "test-secret-key-minimum-32-chars!!";
        let result = decode_token("invalid.token.here", secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_fails() {
        let claims = Claims::new(Uuid::new_v4(), "test@example.com".to_string(), vec![], 3600);
        let token = encode_token(&claims, "secret1-minimum-32-characters!!").unwrap();
        let result = decode_token(&token, "secret2-minimum-32-characters!!");
        assert!(result.is_err());
    }
}
