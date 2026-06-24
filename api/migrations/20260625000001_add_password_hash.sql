-- Migration: Add password_hash column to auth_users for password authentication
-- Created: 2026-06-25

ALTER TABLE auth_users ADD COLUMN password_hash VARCHAR(255) NULL;
