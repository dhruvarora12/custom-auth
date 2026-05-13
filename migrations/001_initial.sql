-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                     VARCHAR(255) UNIQUE NOT NULL,
    password_hash             VARCHAR(255),
    name                      VARCHAR(255),
    avatar_url                VARCHAR(500),
    email_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    email_verification_token  VARCHAR(255),
    password_reset_token      VARCHAR(255),
    password_reset_expires_at TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);

-- +goose Down
DROP TABLE IF EXISTS oauth_accounts;
DROP TABLE IF EXISTS users;
