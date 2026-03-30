-- Dedicated tables for BLS aggregated signatures, replacing the "BLS_AGGREGATED:..."
-- encoding that was previously packed into the signatures.witness_id column.

CREATE TABLE IF NOT EXISTS aggregated_signatures (
    hash    TEXT NOT NULL,
    signature BLOB NOT NULL,
    scheme  TEXT NOT NULL DEFAULT 'bls',
    PRIMARY KEY (hash),
    FOREIGN KEY (hash) REFERENCES attestations(hash)
);

CREATE TABLE IF NOT EXISTS aggregated_signers (
    hash        TEXT    NOT NULL,
    witness_id  TEXT    NOT NULL,
    position    INTEGER NOT NULL,
    PRIMARY KEY (hash, witness_id),
    FOREIGN KEY (hash) REFERENCES attestations(hash)
);
