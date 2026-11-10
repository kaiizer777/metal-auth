-- Phase 3: Transition verification_tokens and password_reset_tokens to DELETE-on-consume model.
-- Safely migrates existing tables to BYTEA PRIMARY KEY (32-byte SHA-256 digest) without dropping tables.

-- ============================================================================
-- 1. verification_tokens
-- ============================================================================

CREATE TABLE IF NOT EXISTS verification_tokens (
    token_hash  BYTEA        NOT NULL,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    -- Drop legacy 'used' column after pruning used tokens
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'verification_tokens' AND column_name = 'used'
    ) THEN
        DELETE FROM verification_tokens WHERE used = TRUE;
        ALTER TABLE verification_tokens DROP COLUMN used;
    END IF;
END $$;

DO $$
DECLARE
    pk_name text;
BEGIN
    -- Drop legacy primary key constraint if not already on token_hash alone
    SELECT conname INTO pk_name
    FROM pg_constraint
    WHERE conrelid = 'verification_tokens'::regclass
      AND contype = 'p';

    IF pk_name IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint c
            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
            WHERE c.conrelid = 'verification_tokens'::regclass
              AND c.contype = 'p'
              AND a.attname = 'token_hash'
              AND array_length(c.conkey, 1) = 1
        ) THEN
            EXECUTE 'ALTER TABLE verification_tokens DROP CONSTRAINT ' || quote_ident(pk_name);
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    -- Drop legacy 'id' column if present
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'verification_tokens' AND column_name = 'id'
    ) THEN
        ALTER TABLE verification_tokens DROP COLUMN id;
    END IF;
END $$;

DO $$
DECLARE
    uk_name text;
BEGIN
    -- Drop legacy UNIQUE constraint on token_hash if present
    SELECT conname INTO uk_name
    FROM pg_constraint
    WHERE conrelid = 'verification_tokens'::regclass
      AND contype = 'u';

    IF uk_name IS NOT NULL THEN
        EXECUTE 'ALTER TABLE verification_tokens DROP CONSTRAINT ' || quote_ident(uk_name);
    END IF;
END $$;

DO $$
BEGIN
    -- Convert token_hash to BYTEA if it is text/varchar
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'verification_tokens' 
          AND column_name = 'token_hash' 
          AND data_type IN ('text', 'character varying')
    ) THEN
        ALTER TABLE verification_tokens 
            ALTER COLUMN token_hash TYPE BYTEA 
            USING (
                CASE 
                    WHEN length(token_hash) = 64 THEN decode(token_hash, 'hex')
                    ELSE token_hash::bytea
                END
            );
    END IF;
END $$;

-- Purge expired tokens or tokens with invalid hash length
DELETE FROM verification_tokens WHERE expires_at < NOW() OR octet_length(token_hash) != 32;

DO $$
BEGIN
    -- Set PRIMARY KEY (token_hash) if not already set
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'verification_tokens'::regclass AND contype = 'p'
    ) THEN
        ALTER TABLE verification_tokens ADD PRIMARY KEY (token_hash);
    END IF;
END $$;

DO $$
BEGIN
    -- Add 32-byte length check constraint
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'verification_tokens'::regclass AND conname = 'chk_vt_token_hash_len'
    ) THEN
        ALTER TABLE verification_tokens ADD CONSTRAINT chk_vt_token_hash_len CHECK (octet_length(token_hash) = 32);
    END IF;
END $$;

-- Ensure foreign key constraint to users(id) ON DELETE CASCADE
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'verification_tokens'::regclass AND contype = 'f'
    ) THEN
        ALTER TABLE verification_tokens ADD CONSTRAINT fk_vt_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_vt_user_id ON verification_tokens (user_id);

-- ============================================================================
-- 2. password_reset_tokens
-- ============================================================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash  BYTEA        NOT NULL,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    -- Drop legacy 'used' column after pruning used tokens
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'password_reset_tokens' AND column_name = 'used'
    ) THEN
        DELETE FROM password_reset_tokens WHERE used = TRUE;
        ALTER TABLE password_reset_tokens DROP COLUMN used;
    END IF;
END $$;

DO $$
DECLARE
    pk_name text;
BEGIN
    -- Drop legacy primary key constraint if not already on token_hash alone
    SELECT conname INTO pk_name
    FROM pg_constraint
    WHERE conrelid = 'password_reset_tokens'::regclass
      AND contype = 'p';

    IF pk_name IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint c
            JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
            WHERE c.conrelid = 'password_reset_tokens'::regclass
              AND c.contype = 'p'
              AND a.attname = 'token_hash'
              AND array_length(c.conkey, 1) = 1
        ) THEN
            EXECUTE 'ALTER TABLE password_reset_tokens DROP CONSTRAINT ' || quote_ident(pk_name);
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    -- Drop legacy 'id' column if present
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'password_reset_tokens' AND column_name = 'id'
    ) THEN
        ALTER TABLE password_reset_tokens DROP COLUMN id;
    END IF;
END $$;

DO $$
DECLARE
    uk_name text;
BEGIN
    -- Drop legacy UNIQUE constraint on token_hash if present
    SELECT conname INTO uk_name
    FROM pg_constraint
    WHERE conrelid = 'password_reset_tokens'::regclass
      AND contype = 'u';

    IF uk_name IS NOT NULL THEN
        EXECUTE 'ALTER TABLE password_reset_tokens DROP CONSTRAINT ' || quote_ident(uk_name);
    END IF;
END $$;

DO $$
BEGIN
    -- Convert token_hash to BYTEA if it is text/varchar
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'password_reset_tokens' 
          AND column_name = 'token_hash' 
          AND data_type IN ('text', 'character varying')
    ) THEN
        ALTER TABLE password_reset_tokens 
            ALTER COLUMN token_hash TYPE BYTEA 
            USING (
                CASE 
                    WHEN length(token_hash) = 64 THEN decode(token_hash, 'hex')
                    ELSE token_hash::bytea
                END
            );
    END IF;
END $$;

-- Purge expired tokens or tokens with invalid hash length
DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR octet_length(token_hash) != 32;

DO $$
BEGIN
    -- Set PRIMARY KEY (token_hash) if not already set
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'password_reset_tokens'::regclass AND contype = 'p'
    ) THEN
        ALTER TABLE password_reset_tokens ADD PRIMARY KEY (token_hash);
    END IF;
END $$;

DO $$
BEGIN
    -- Add 32-byte length check constraint
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'password_reset_tokens'::regclass AND conname = 'chk_prt_token_hash_len'
    ) THEN
        ALTER TABLE password_reset_tokens ADD CONSTRAINT chk_prt_token_hash_len CHECK (octet_length(token_hash) = 32);
    END IF;
END $$;

-- Ensure foreign key constraint to users(id) ON DELETE CASCADE
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'password_reset_tokens'::regclass AND contype = 'f'
    ) THEN
        ALTER TABLE password_reset_tokens ADD CONSTRAINT fk_prt_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_prt_user_id ON password_reset_tokens (user_id);
