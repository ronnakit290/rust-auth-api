-- Initial schema for the authentication service.
-- All timestamps are stored as INTEGER (unix seconds, UTC) so that range queries
-- and comparisons are unambiguous and index friendly in SQLite.

CREATE TABLE users (
    id                    TEXT    PRIMARY KEY,
    email                 TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    full_name             TEXT,
    role                  TEXT    NOT NULL DEFAULT 'user'
                                  CHECK (role IN ('user', 'moderator', 'admin', 'superadmin')),
    status                TEXT    NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'suspended', 'deleted')),
    email_verified_at     INTEGER,
    last_login_at         INTEGER,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until          INTEGER,
    password_changed_at   INTEGER,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);

CREATE INDEX idx_users_role       ON users (role);
CREATE INDEX idx_users_status     ON users (status);
CREATE INDEX idx_users_created_at ON users (created_at);

-- A session row == one refresh-token family member. Rotating a refresh token
-- revokes the old row and inserts a new one inside the same family, which lets
-- us detect token replay (reuse of an already-rotated token).
CREATE TABLE sessions (
    id                 TEXT    PRIMARY KEY,
    user_id            TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id          TEXT    NOT NULL,
    refresh_token_hash TEXT    NOT NULL UNIQUE,
    replaced_by        TEXT,
    user_agent         TEXT,
    ip_address         TEXT,
    expires_at         INTEGER NOT NULL,
    revoked_at         INTEGER,
    revoke_reason      TEXT,
    created_at         INTEGER NOT NULL,
    last_used_at       INTEGER
);

CREATE INDEX idx_sessions_user      ON sessions (user_id);
CREATE INDEX idx_sessions_family    ON sessions (family_id);
CREATE INDEX idx_sessions_expires   ON sessions (expires_at);

-- Single-use tokens for e-mail verification and password resets.
-- Only the SHA-256 hash of the token is stored.
CREATE TABLE one_time_tokens (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('email_verification', 'password_reset')),
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_ott_user ON one_time_tokens (user_id, kind);
CREATE INDEX idx_ott_hash ON one_time_tokens (token_hash);

CREATE TABLE two_factor_settings (
    user_id      TEXT    PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret       TEXT    NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 0,
    confirmed_at INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_recovery_user ON recovery_codes (user_id, used_at);

CREATE TABLE audit_logs (
    id          TEXT    PRIMARY KEY,
    actor_id    TEXT,
    actor_email TEXT,
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    metadata    TEXT,
    created_at  INTEGER NOT NULL
);

CREATE INDEX idx_audit_created ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_actor   ON audit_logs (actor_id);
CREATE INDEX idx_audit_action  ON audit_logs (action);
