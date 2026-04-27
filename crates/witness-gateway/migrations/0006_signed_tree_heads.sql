-- RFC 9162 Signed Tree Heads.
--
-- One STH is produced every time a batch closes: it commits to the entire
-- log up to that point (every attestation in every prior closed batch, in
-- (batch_id, merkle_index) order).  Auditors fetch the latest STH, then walk
-- backwards via consistency proofs to confirm the operator never rewrote
-- history.
--
-- The signed_attestation_json column stores the witness threshold-signed
-- envelope (Ed25519 multi-sig or BLS aggregated) over the STH digest, which
-- lets clients verify each STH offline against NetworkConfig.
CREATE TABLE IF NOT EXISTS signed_tree_heads (
    tree_size               INTEGER NOT NULL,
    network_id              TEXT    NOT NULL,
    timestamp               INTEGER NOT NULL,
    root_hash               BLOB    NOT NULL,
    batch_id                INTEGER NOT NULL,
    signed_attestation_json TEXT    NOT NULL,
    created_at              INTEGER NOT NULL,
    PRIMARY KEY (network_id, tree_size),
    FOREIGN KEY (batch_id) REFERENCES batches(id)
);

CREATE INDEX IF NOT EXISTS idx_sth_batch_id ON signed_tree_heads(batch_id);
CREATE INDEX IF NOT EXISTS idx_sth_network_latest
    ON signed_tree_heads(network_id, tree_size DESC);
