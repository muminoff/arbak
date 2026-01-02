-- Add tokens_revoked_at column for logout-all functionality
-- Any token issued before this timestamp is considered invalid

ALTER TABLE users ADD COLUMN tokens_revoked_at TIMESTAMPTZ;

-- Index for efficient lookups during auth
CREATE INDEX idx_users_tokens_revoked_at ON users(tokens_revoked_at) WHERE tokens_revoked_at IS NOT NULL;
