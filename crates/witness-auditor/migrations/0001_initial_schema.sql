-- Auditor state.  One row per (gateway, tree_size) STH we have observed
-- and verified, plus an append-only failure log so anomalies survive
-- restarts and can be reviewed offline.

CREATE TABLE IF NOT EXISTS audited_sths (
    gateway_url             TEXT    NOT NULL,
    network_id              TEXT    NOT NULL,
    tree_size               INTEGER NOT NULL,
    timestamp               INTEGER NOT NULL,
    root_hash               BLOB    NOT NULL,
    signed_attestation_json TEXT    NOT NULL,
    audited_at              INTEGER NOT NULL,
    PRIMARY KEY (gateway_url, tree_size)
);

CREATE INDEX IF NOT EXISTS idx_audited_sths_gateway_latest
    ON audited_sths(gateway_url, tree_size DESC);

CREATE TABLE IF NOT EXISTS audit_failures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    gateway_url   TEXT    NOT NULL,
    failure_type  TEXT    NOT NULL,
    tree_size     INTEGER,
    detected_at   INTEGER NOT NULL,
    detail        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_failures_recent
    ON audit_failures(gateway_url, detected_at DESC);
