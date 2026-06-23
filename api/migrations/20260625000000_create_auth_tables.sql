-- Migration: Create Authentication and Session Tracking Tables
-- Created: 2026-06-25

-- 1. Core Authentication Users Table
CREATE TABLE auth_users (
    id UUID PRIMARY KEY, -- Maps to user_id in pot_bonus_registrations
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user', -- 'user' or 'admin'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for email checks during login
CREATE INDEX idx_auth_users_email ON auth_users(email);

-- 2. Registered WebAuthn Passkeys (Touch ID, Windows Hello, etc.)
CREATE TABLE auth_passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    passkey_json JSONB NOT NULL, -- Serialized webauthn_rs::prelude::Passkey
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for fetching registered passkeys for a user
CREATE INDEX idx_auth_passkeys_user ON auth_passkeys(user_id);

-- 3. Transient WebAuthn Challenge State
CREATE TABLE auth_webauthn_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NULL,
    user_id UUID NULL,
    challenge_json JSONB NOT NULL, -- Serialized PasskeyRegistration or PasskeyAuthentication
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for purging expired challenges
CREATE INDEX idx_auth_webauthn_challenges_expiry ON auth_webauthn_challenges(expires_at);

-- 4. Transient Passwordless Magic Link Tokens
CREATE TABLE auth_magic_links (
    token VARCHAR(255) PRIMARY KEY, -- Secure random token string
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index to quickly query active tokens
CREATE INDEX idx_auth_magic_links_active ON auth_magic_links(token) WHERE used = FALSE;

-- 5. Persistent Active Sessions
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) NOT NULL UNIQUE, -- Secure token string
    user_agent VARCHAR(512) NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_active_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_token ON auth_sessions(session_token);
