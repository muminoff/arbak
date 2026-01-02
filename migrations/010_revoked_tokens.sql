-- Token blacklist for logout functionality
-- Stores revoked JWT IDs (jti) to invalidate tokens before expiry

CREATE TABLE revoked_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti UUID NOT NULL UNIQUE,              -- JWT ID from the token
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,       -- When the original token expires (for cleanup)
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast JTI lookups during auth
CREATE INDEX idx_revoked_tokens_jti ON revoked_tokens(jti);

-- Index for cleanup of expired entries
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Cleanup function to remove expired revoked tokens (they're no longer needed)
CREATE OR REPLACE FUNCTION cleanup_expired_revoked_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM revoked_tokens WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;
