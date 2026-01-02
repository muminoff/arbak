-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast token lookup
CREATE INDEX idx_reset_tokens_hash ON password_reset_tokens(token_hash);

-- Index for cleanup of expired tokens
CREATE INDEX idx_reset_tokens_expires ON password_reset_tokens(expires_at);
