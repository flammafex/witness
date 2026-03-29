CREATE TABLE IF NOT EXISTS attestations (
    hash TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    network_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (hash) REFERENCES attestations(hash),
    UNIQUE(hash, witness_id)
);

CREATE INDEX IF NOT EXISTS idx_attestations_timestamp
ON attestations(timestamp DESC);

CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT NOT NULL,
    merkle_root BLOB NOT NULL,
    period_start INTEGER NOT NULL,
    period_end INTEGER NOT NULL,
    attestation_count INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS batch_attestations (
    batch_id INTEGER NOT NULL,
    hash TEXT NOT NULL,
    merkle_index INTEGER NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES batches(id),
    FOREIGN KEY (hash) REFERENCES attestations(hash),
    PRIMARY KEY (batch_id, hash)
);

CREATE TABLE IF NOT EXISTS cross_anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    witnessing_network TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES batches(id)
);

CREATE TABLE IF NOT EXISTS cross_anchor_signatures (
    cross_anchor_id INTEGER NOT NULL,
    witness_id TEXT NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (cross_anchor_id) REFERENCES cross_anchors(id),
    PRIMARY KEY (cross_anchor_id, witness_id)
);

CREATE TABLE IF NOT EXISTS sequences (
    network_id TEXT PRIMARY KEY,
    next_val INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS external_anchor_proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    proof_json TEXT NOT NULL,
    anchored_data BLOB,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES batches(id)
);

CREATE INDEX IF NOT EXISTS idx_external_anchors_batch
ON external_anchor_proofs(batch_id);
