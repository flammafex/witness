# crates/witness-auditor/migrations/

## Responsibility

Forward-only SQL migrations for the auditor's SQLite state, compiled into the binary via `sqlx::migrate!("./migrations")` and run by `Storage::migrate()` at startup. Currently one migration: `0001_initial_schema.sql`.

### `0001_initial_schema.sql`

- **Responsibility**: create the two tables that form the auditor's persistent memory.
- **`audited_sths`**: one row per successfully verified STH, `PRIMARY KEY (gateway_url, tree_size)`. Columns: `gateway_url`, `network_id`, `tree_size`, `timestamp`, `root_hash` (BLOB), `signed_attestation_json` (TEXT — retains the full threshold-signed payload so the STH can be rehydrated and re-verified offline), `audited_at`. `INSERT OR IGNORE` semantics mean a tree size accepted once is never overwritten.
- **Index**: `idx_audited_sths_gateway_latest (gateway_url, tree_size DESC)` — backs the "last-known size per gateway" lookup used to pick the consistency-proof anchor on the next tick.
- **`audit_failures`**: append-only anomaly log. `id INTEGER PRIMARY KEY AUTOINCREMENT`, `gateway_url`, `failure_type` (TEXT — enum stored as a string so new failure kinds need no migration), nullable `tree_size`, `detected_at`, `detail`.
- **Index**: `idx_audit_failures_recent (gateway_url, detected_at DESC)` — backs `recent_failures`.
- **Design notes**: all DDL uses `CREATE TABLE/INDEX IF NOT EXISTS` for idempotency; forward-only, no down migrations (consistent with the gateway's migration policy). `failure_type` as free-form TEXT decouples schema versioning from enum evolution.

## Flow

`Storage::migrate()` → `sqlx::migrate!` applies pending migrations in filename order → tables/indexes created → `audit.rs` ticks persist into these tables.

## Integration

- Consumed only by `witness-auditor` (`storage.rs`). Not shared with other crates.
- The migration set is compiled into the binary at build time; the DB is created on first run at the path given by `--database` / `WITNESS_AUDITOR_DB`.
- **Security-sensitive** (per AGENTS.md migration constraints): forward-only; do not renumber or edit `0001` in place — add a `0002` migration instead.
