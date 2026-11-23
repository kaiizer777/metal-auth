-- Migration: 20240101000009_bind_two_factor_tokens_to_credential.sql
-- Up Migration
-- Bind each challenge to the credential that authorized it. Redemption compares the stored
-- snapshot against the live `users.password_hash` under the user row lock, so a password
-- reset revokes challenges that were already in flight when it committed.
--
-- Challenges in flight when this migration runs are invalidated. That is intentional and
-- fail-closed: the affected user re-enters the second factor once, instead of redeeming a
-- challenge whose authorizing credential state is unknown.
--
-- The DELETE is what makes the NOT NULL add legal on a populated table. A backfill from
-- `users.password_hash` is deliberately absent — it would re-authorize exactly the
-- pre-reset challenges this binding exists to revoke.
DELETE FROM two_factor_tokens;

-- No DEFAULT: every mint must supply the snapshot, so an omission fails the NOT NULL
-- constraint instead of silently producing an unbound challenge.
ALTER TABLE two_factor_tokens ADD COLUMN credential_hash TEXT NOT NULL;

-- Down Migration (Documentation / Rollback Reference)
-- ALTER TABLE two_factor_tokens DROP COLUMN IF EXISTS credential_hash;
