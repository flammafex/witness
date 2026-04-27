-- Cross-anchors now embed a full SignedAttestation from the peer network
-- rather than a bare list of signatures.  This makes cross-anchors
-- independently verifiable by clients without trusting the originating
-- gateway.  The old per-signature table is dropped (clean break — no
-- federation data is in production yet).
DROP TABLE IF EXISTS cross_anchor_signatures;
DROP TABLE IF EXISTS cross_anchors;

CREATE TABLE cross_anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    witnessing_network TEXT NOT NULL,
    witness_attestation_json TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (batch_id) REFERENCES batches(id)
);

CREATE INDEX IF NOT EXISTS idx_cross_anchors_batch
ON cross_anchors(batch_id);
