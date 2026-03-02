-- Schema for go-better-auth example
-- Field names match the snake_case keys used by the betterauth adapter layer.

CREATE TABLE IF NOT EXISTS "user" (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image       TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS session (
    id          TEXT PRIMARY KEY,
    token       TEXT UNIQUE NOT NULL,
    user_id     TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS account (
    id                       TEXT PRIMARY KEY,
    user_id                  TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    account_id               TEXT NOT NULL,
    provider_id              TEXT NOT NULL,
    access_token             TEXT,
    refresh_token            TEXT,
    access_token_expires_at  TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope                    TEXT,
    id_token                 TEXT,
    password                 TEXT,
    created_at               TIMESTAMPTZ NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS verification (
    id         TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Indexes for common lookup patterns
CREATE INDEX IF NOT EXISTS idx_session_user_id     ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_account_user_id     ON account(user_id);
CREATE INDEX IF NOT EXISTS idx_account_provider    ON account(provider_id, account_id);
CREATE INDEX IF NOT EXISTS idx_verification_ident  ON verification(identifier);
