-- Add email_verified column to users
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Set existing users as verified (they registered before this feature)
UPDATE users SET email_verified = TRUE;

-- Email verification tokens table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast token lookup
CREATE INDEX idx_verification_tokens_hash ON email_verification_tokens(token_hash);

-- Index for cleanup of expired tokens
CREATE INDEX idx_verification_tokens_expires ON email_verification_tokens(expires_at);
