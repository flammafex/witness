# crates/witness-gateway/migrations/

## Responsibility

Forward-only SQL migrations for the gateway's SQLite database, compiled in via
`sqlx::migrate!("./migrations")` and applied automatically at startup
(`storage::Storage::migrate`). They define the complete persistent schema for
attestations, signatures, batches, cross-anchors, signed tree heads, and anchor
proofs, and evolve it in-place as the gateway moves from single-shot signing
through batching and federated anchoring to durable lease-based jobs.

## Design

- **Forward-only**: migrations are immutable once deployed — there are no down
  migrations. Schema changes are additive `ALTER TABLE` / `CREATE TABLE` /
  `CREATE INDEX` statements or, where SQLite forces it, explicit drop-and-
  recreate with a clean-break justification (see 0005).
- **Compiled at build time**: `sqlx::migrate!` embeds the SQL and tracks applied
  versions in SQLite's `_sqlx_migrations` table; a checksum mismatch on an
  already-applied migration is a startup failure.
- **Key constraints**: the `attestations.hash` primary key is the *global
  canonical* reservation key across all networks, and `(network_id, sequence)`
  is unique per network from 0008 onward — a tuple is never rewritten on retry,
  so signatures stay valid.
- **WAL journal mode is NOT a migration**: SQLite cannot change journal mode or
  `synchronous` inside a transaction, so those pragmas are applied per-
  connection via `SqliteConnectOptions` in `storage.rs`. Migration 0003 is a
  documented no-op placeholder preserved for the migration sequence.
- **One-time data repair lives in Rust**: the runtime `migrate_bls_legacy_rows`
  pass (storage.rs) moves legacy `BLS_AGGREGATED:...` rows into the dedicated
  aggregated tables after 0004-0008 have run.

## Migration list (schema evolution)

### 0001_initial_schema.sql
- **Adds**: the base schema — `attestations` (hash PK, timestamp, network_id,
  sequence, created_at), `signatures` (per-witness Ed25519 rows,
  `UNIQUE(hash, witness_id)`), `batches` + `batch_attestations`
  (merkle_index linking, PK `(batch_id, hash)`), `cross_anchors` +
  `cross_anchor_signatures` (per-witness signature rows), `sequences`
  (per-network atomic counter), `external_anchor_proofs` (provider, proof_json,
  anchored_data), plus the `timestamp DESC` and `batch` indexes.
- **Origin**: Phase 1 single-shot signing + initial batch storage.

### 0002_add_batch_id.sql
- **Adds**: `attestations.batch_id` (nullable FK to `batches.id`) — the
  many-attestations-to-one-batch link used to mark an attestation as batched.

### 0003_wal_mode.sql
- **Adds**: nothing — intentionally a `SELECT 1` no-op.
- **Why it exists**: originally tried to set WAL journal mode; sqlx wraps
  migrations in transactions and SQLite refuses pragma changes there. WAL +
  `synchronous=NORMAL` are now connection-level options in `storage.rs`. The
  file is kept only to preserve the migration sequence. **Do not renumber.**

### 0004_bls_aggregated_tables.sql
- **Adds**: `aggregated_signatures` (hash PK, signature BLOB, scheme) and
  `aggregated_signers` (hash, witness_id, position, PK `(hash, witness_id)`),
  replacing the old packed `BLS_AGGREGATED:<ids>` encoding that lived in the
  `signatures.witness_id` column.

### 0005_cross_anchor_signed_attestation.sql
- **Changes**: drops `cross_anchor_signatures` and the old `cross_anchors`;
  recreates `cross_anchors` with a `witness_attestation_json` column holding a
  complete peer `SignedAttestation` so cross-anchors are independently
  verifiable offline without trusting the originating gateway.
- **Justification for the destructive change**: clean break — no federation data
  existed in production yet.

### 0006_signed_tree_heads.sql
- **Adds**: `signed_tree_heads` — one row per closed batch committing to the
  entire log (`tree_size`, `root_hash`, `signed_attestation_json` holding the
  threshold-signed envelope over the STH digest), PK `(network_id, tree_size)`,
  with `batch_id` and `(network_id, tree_size DESC)` indexes. This is the table
  RFC 9162 auditors walk to confirm no history rewrite.

### 0007_attestation_status_log_state.sql
- **Adds**: `attestations.status` (default `'confirmed'` — legacy rows are
  treated as confirmed), an index on `status`, and `log_state`
  (per-network current root / tree size for O(1) STH computation).

### 0008_attestation_jobs.sql
- **Adds**: the durable job lifecycle columns on `attestations` — `lease_token`,
  `lease_expires_at`, `attempts`, `next_attempt_at`, `last_error`,
  `completed_at`.
- **Data migration**: rewrites existing rows — a legacy `confirmed` row stays
  confirmed only if it carries a real Ed25519 signature row (64 bytes, or the
  legacy 96-byte BLS encoding) or a complete BLS aggregate representation;
  `pending` stays pending (made immediately due with `next_attempt_at = 0`);
  everything else becomes terminal `failed` with a descriptive `last_error`.
- **Guards**: `CREATE UNIQUE INDEX (network_id, sequence)` refuses the migration
  if duplicate tuples exist (rather than renumber and invalidate signatures);
  a `(status, next_attempt_at, lease_expires_at, sequence, hash)` index backs
  `claim_job`; `sequences` counters are repaired (forward-only, never rewound);
  BEFORE INSERT/UPDATE triggers enforce the four legal statuses (SQLite can't
  add a CHECK without a table rebuild).

## Flow

1. **Startup**: `Storage::new` opens the pool with WAL + busy timeout →
   `Storage::migrate` runs 0001→0008 in order (each inside its own
   transaction) and records them in `_sqlx_migrations`.
2. **Runtime reads/writes** are shaped by the final 0008 schema: `reserve_job`
   inserts `pending` rows and consumes `sequences`; `claim_job` picks due
   unexpired jobs via the `idx_attestation_jobs_due` index; `complete_verified_job`
   flips to `confirmed` under a matching `lease_token`; `store_batch` sets
   `batch_id` and fills `batch_attestations`; `store_sth` appends STH rows;
   `store_anchor_proof`/`store_cross_anchor` append per-batch proofs.
3. **Legacy data paths**: rows written before 0008 are classified by the 0008
   UPDATE; the Rust `migrate_bls_legacy_rows` pass then moves surviving
   `BLS_AGGREGATED:` signature rows into the aggregated tables (idempotent via
   `INSERT OR IGNORE`, deletes only rows successfully moved).

## Integration

- **storage.rs** is the only consumer — every table is referenced by
  `sqlx::query` in that module; other gateway modules go through `Storage` and
  never touch SQL directly.
- **witness-core types** map onto these tables: `Attestation` → `attestations`,
  `WitnessSignature`/`AttestationSignatures::Aggregated` → `signatures` +
  `aggregated_signatures`/`aggregated_signers`, `AttestationBatch` →
  `batches` + `batch_attestations`, `CrossAnchor` → `cross_anchors`,
  `SignedTreeHead` → `signed_tree_heads`, `ExternalAnchorProof` →
  `external_anchor_proofs`.
- **Forward-only constraint**: any future schema change must be additive
  (new table / nullable column / index / view). Destructive or renumbering
  changes, including touching the 0003 no-op placeholder, require explicit
  confirmation (see AGENTS.md constraints).
