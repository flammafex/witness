-- WAL journal mode and synchronous=NORMAL are connection-level pragmas; sqlx
-- wraps each migration in a transaction, and SQLite refuses to change either
-- inside one ("Safety level may not be changed inside a transaction"). Both
-- pragmas are now applied at connection time via SqliteConnectOptions in
-- storage.rs, so this migration is intentionally a no-op kept only to preserve
-- the migration sequence.
SELECT 1;
