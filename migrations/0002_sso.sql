-- Central SSO server: registered applications (OAuth2 clients), app keys,
-- authorization codes with PKCE, user consents, refresh tokens and a JWT
-- revocation list.

CREATE TABLE oauth_clients (
    id                 TEXT    PRIMARY KEY,
    client_id          TEXT    NOT NULL UNIQUE,
    client_secret_hash TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    description        TEXT,
    client_type        TEXT    NOT NULL DEFAULT 'confidential'
                               CHECK (client_type IN ('confidential', 'public')),
    -- JSON array of absolute redirect URIs
    redirect_uris      TEXT    NOT NULL DEFAULT '[]',
    -- JSON array of scopes this application may ever request
    allowed_scopes     TEXT    NOT NULL DEFAULT '[]',
    owner_id           TEXT    REFERENCES users (id) ON DELETE SET NULL,
    status             TEXT    NOT NULL DEFAULT 'active'
                               CHECK (status IN ('active', 'disabled')),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    last_used_at       INTEGER,
    secret_rotated_at  INTEGER
);

CREATE INDEX idx_oauth_clients_status ON oauth_clients (status);

-- "App keys": bearer credentials handed to integrations that cannot perform an
-- OAuth dance (cron jobs, internal services, third-party webhooks).
-- Only the SHA-256 of the secret is stored; `key_prefix` is for display only.
CREATE TABLE api_keys (
    id           TEXT    PRIMARY KEY,
    client_id    TEXT    NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    key_prefix   TEXT    NOT NULL,
    key_hash     TEXT    NOT NULL UNIQUE,
    scopes       TEXT    NOT NULL DEFAULT '[]',
    environment  TEXT    NOT NULL DEFAULT 'live' CHECK (environment IN ('live', 'test')),
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    created_by   TEXT,
    created_at   INTEGER NOT NULL
);

CREATE INDEX idx_api_keys_client ON api_keys (client_id);
CREATE INDEX idx_api_keys_prefix ON api_keys (key_prefix);

CREATE TABLE oauth_authorization_codes (
    id                    TEXT    PRIMARY KEY,
    code_hash             TEXT    NOT NULL UNIQUE,
    client_id             TEXT    NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id               TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT    NOT NULL,
    scopes                TEXT    NOT NULL DEFAULT '[]',
    code_challenge        TEXT,
    code_challenge_method TEXT,
    expires_at            INTEGER NOT NULL,
    used_at               INTEGER,
    created_at            INTEGER NOT NULL
);

CREATE INDEX idx_oauth_codes_client ON oauth_authorization_codes (client_id);

CREATE TABLE oauth_consents (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT    NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scopes     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (user_id, client_id)
);

CREATE TABLE oauth_refresh_tokens (
    id           TEXT    PRIMARY KEY,
    token_hash   TEXT    NOT NULL UNIQUE,
    client_id    TEXT    NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scopes       TEXT    NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    replaced_by  TEXT,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE INDEX idx_oauth_refresh_user ON oauth_refresh_tokens (user_id, client_id);

-- Denylist for access tokens that must stop working before they expire.
CREATE TABLE revoked_tokens (
    jti        TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL,
    reason     TEXT
);

CREATE INDEX idx_revoked_tokens_exp ON revoked_tokens (expires_at);
